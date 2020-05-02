/*
Copyright (c) 2013, Kenneth MacKay
Copyright (c) 2014, Emergya (Cloud4all, FP7/2007-2013 grant agreement #289016)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "uv/android-ifaddrs.h"
#include "uv-common.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <type_traits>

struct NetlinkList
{
    NetlinkList *m_next;
    nlmsghdr *m_data;
    unsigned int m_size;
};

static int netlink_socket(pid_t *p_pid)
{
    auto l_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(l_socket < 0)
    {
        return -1;
    }

    auto l_addr = sockaddr_nl{};
    memset(&l_addr, 0, sizeof(decltype(l_addr)));
    l_addr.nl_family = AF_NETLINK;
    if(bind(l_socket, reinterpret_cast<sockaddr *>(&l_addr), sizeof(decltype(l_addr))) < 0)
    {
        close(l_socket);
        return -1;
    }

    auto l_len = static_cast<socklen_t>(sizeof(decltype(l_addr)));
    if(getsockname(l_socket, reinterpret_cast<sockaddr *>(&l_addr), &l_len) < 0)
    {
        close(l_socket);
        return -1;
    }
    *p_pid = l_addr.nl_pid;

    return l_socket;
}

static int netlink_send(int p_socket, int p_request)
{
    char l_buffer[NLMSG_ALIGN(sizeof(nlmsghdr)) + NLMSG_ALIGN(sizeof(rtgenmsg))];

    memset(l_buffer, 0, sizeof(l_buffer));

    auto l_hdr = reinterpret_cast<nlmsghdr *>(l_buffer);
    auto l_msg = static_cast<rtgenmsg *>(NLMSG_DATA(l_hdr));

    l_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(decltype(*l_msg)));
    l_hdr->nlmsg_type = p_request;
    l_hdr->nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    l_hdr->nlmsg_pid = 0;
    l_hdr->nlmsg_seq = p_socket;
    l_msg->rtgen_family = AF_UNSPEC;

    auto l_addr = sockaddr_nl{};
    memset(&l_addr, 0, sizeof(decltype(l_addr)));
    l_addr.nl_family = AF_NETLINK;
    return (sendto(p_socket, l_hdr, l_hdr->nlmsg_len, 0, reinterpret_cast<sockaddr *>(&l_addr), sizeof(l_addr)));
}

static int netlink_recv(int p_socket, void *p_buffer, size_t p_len)
{


    for(;;)
    {
        auto l_iov = iovec{};
        l_iov.iov_base = p_buffer;
        l_iov.iov_len = p_len;

        auto l_addr = sockaddr_nl{};
        auto l_msg = msghdr{};

        l_msg.msg_name = static_cast<void *>(&l_addr);
        l_msg.msg_namelen = sizeof(decltype(l_addr));
        l_msg.msg_iov = &l_iov;
        l_msg.msg_iovlen = 1;
        l_msg.msg_control = nullptr;
        l_msg.msg_controllen = 0;
        l_msg.msg_flags = 0;
        
        auto l_result = recvmsg(p_socket, &l_msg, 0);

        if(l_result < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            return -2;
        }

        /* Buffer was too small */
        if(l_msg.msg_flags & MSG_TRUNC)
        {
            return -1;
        }
        return l_result;
    }
}

nlmsghdr *getNetlinkResponse(int p_socket, pid_t p_pid, int *p_size, int *p_done)
{
    void *l_buffer = nullptr;

    for(;;)
    {
        uv__free(l_buffer);
        auto l_size = 4096ull;
        auto l_buffer = uv__malloc(l_size);
        if (l_buffer == nullptr)
        {
            return nullptr;
        }

        auto l_read = netlink_recv(p_socket, l_buffer, l_size);
        *p_size = l_read;
        if(l_read == -2)
        {
            uv__free(l_buffer);
            return nullptr;
        }
        if(l_read >= 0)
        {
            for(auto l_hdr = static_cast<nlmsghdr *>(l_buffer); NLMSG_OK(l_hdr, (unsigned int)l_read); l_hdr = static_cast<nlmsghdr *>(NLMSG_NEXT(l_hdr, l_read)))
            {
                if(static_cast<pid_t>(l_hdr->nlmsg_pid) != p_pid || static_cast<int>(l_hdr->nlmsg_seq) != p_socket)
                {
                    continue;
                }

                if(l_hdr->nlmsg_type == NLMSG_DONE)
                {
                    *p_done = 1;
                    break;
                }

                if(l_hdr->nlmsg_type == NLMSG_ERROR)
                {
                    uv__free(l_buffer);
                    return nullptr;
                }
            }
            return static_cast<nlmsghdr *>(l_buffer);
        }

        l_size *= 2;
    }
}

static NetlinkList *newListItem(nlmsghdr *p_data, unsigned int p_size)
{
    auto l_item = static_cast<NetlinkList *>(uv__malloc(sizeof(NetlinkList)));
    if (l_item == nullptr)
    {
        return nullptr;
    }

    l_item->m_next = nullptr;
    l_item->m_data = p_data;
    l_item->m_size = p_size;
    return l_item;
}

static void freeResultList(NetlinkList *p_list)
{
    while(p_list)
    {
        auto l_cur = p_list;
        p_list = p_list->m_next;
        uv__free(l_cur->m_data);
        uv__free(l_cur);
    }
}

static NetlinkList *getResultList(int p_socket, int p_request, pid_t p_pid)
{
    if(netlink_send(p_socket, p_request) < 0)
    {
        return nullptr;
    }

    NetlinkList *l_list = nullptr;
    NetlinkList *l_end = nullptr;
    auto l_done = 0;
    while(!l_done)
    {
        auto l_size = int{};
        auto l_hdr = getNetlinkResponse(p_socket, p_pid, &l_size, &l_done);
        /* Error */
        if(!l_hdr)
        {
            freeResultList(l_list);
            return nullptr;
        }

        auto l_item = newListItem(l_hdr, l_size);
        if (!l_item)
        {
            freeResultList(l_list);
            return nullptr;
        }
        if(!l_list)
        {
            l_list = l_item;
        }
        else
        {
            l_end->m_next = l_item;
        }
        l_end = l_item;
    }
    return l_list;
}

static size_t maxSize(size_t a, size_t b)
{
    return (a > b ? a : b);
}

static size_t calcAddrLen(sa_family_t p_family, int p_dataSize)
{
    switch(p_family)
    {
        case AF_INET:
            return sizeof(sockaddr_in);
        case AF_INET6:
            return sizeof(sockaddr_in6);
        case AF_PACKET:
            return maxSize(sizeof(sockaddr_ll), offsetof(sockaddr_ll, sll_addr) + p_dataSize);
        default:
            return maxSize(sizeof(sockaddr), offsetof(sockaddr, sa_data) + p_dataSize);
    }
}

static void makeSockaddr(sa_family_t p_family, sockaddr *p_dest, void *p_data, size_t p_size)
{
    switch(p_family)
    {
        case AF_INET:
            memcpy(&reinterpret_cast<sockaddr_in*>(p_dest)->sin_addr, p_data, p_size);
            break;
        case AF_INET6:
            memcpy(&reinterpret_cast<sockaddr_in6*>(p_dest)->sin6_addr, p_data, p_size);
            break;
        case AF_PACKET:
            memcpy(reinterpret_cast<sockaddr_ll*>(p_dest)->sll_addr, p_data, p_size);
            reinterpret_cast<sockaddr_ll*>(p_dest)->sll_halen = p_size;
            break;
        default:
            memcpy(p_dest->sa_data, p_data, p_size);
            break;
    }
    p_dest->sa_family = p_family;
}

static void addToEnd(ifaddrs **p_resultList, ifaddrs *p_entry)
{
    if(!*p_resultList)
    {
        *p_resultList = p_entry;
    }
    else
    {
        auto l_cur = *p_resultList;
        while(l_cur->ifa_next)
        {
            l_cur = l_cur->ifa_next;
        }
        l_cur->ifa_next = p_entry;
    }
}

static int interpretLink(nlmsghdr *p_hdr, ifaddrs **p_resultList)
{

    ifinfomsg *l_info = static_cast<ifinfomsg *>(NLMSG_DATA(p_hdr));

    auto l_nameSize = 0ull;
    auto l_addrSize = 0ull;
    auto l_dataSize = 0ull;

    auto l_rtaSize = NLMSG_PAYLOAD(p_hdr, sizeof(ifinfomsg));
    for(auto l_rta = IFLA_RTA(l_info); RTA_OK(l_rta, l_rtaSize); l_rta = RTA_NEXT(l_rta, l_rtaSize))
    {
        auto l_rtaDataSize = RTA_PAYLOAD(l_rta);
        switch(l_rta->rta_type)
        {
            case IFLA_ADDRESS:
            case IFLA_BROADCAST:
                l_addrSize += NLMSG_ALIGN(calcAddrLen(AF_PACKET, l_rtaDataSize));
                break;
            case IFLA_IFNAME:
                l_nameSize += NLMSG_ALIGN(l_rtaSize + 1);
                break;
            case IFLA_STATS:
                l_dataSize += NLMSG_ALIGN(l_rtaSize);
                break;
            default:
                break;
        }
    }

    auto l_entry = static_cast<ifaddrs *>(uv__malloc(sizeof(ifaddrs) + sizeof(int) + l_nameSize + l_addrSize + l_dataSize));
    if (l_entry == nullptr)
    {
        return -1;
    }
    memset(l_entry, 0, sizeof(ifaddrs));
    l_entry->ifa_name = "";

    auto l_index = reinterpret_cast<char *>(l_entry) + sizeof(ifaddrs);
    auto l_name = l_index + sizeof(int);
    auto l_addr = l_name + l_nameSize;
    auto l_data = l_addr + l_addrSize;

    /* Save the interface index so we can look it up when handling the
     * addresses.
     */
    memcpy(l_index, &l_info->ifi_index, sizeof(int));

    l_entry->ifa_flags = l_info->ifi_flags;

    l_rtaSize = NLMSG_PAYLOAD(p_hdr, sizeof(ifinfomsg));
    for(auto l_rta = IFLA_RTA(l_info); RTA_OK(l_rta, l_rtaSize); l_rta = RTA_NEXT(l_rta, l_rtaSize))
    {
        auto *l_rtaData = RTA_DATA(l_rta);
        auto l_rtaDataSize = RTA_PAYLOAD(l_rta);
        switch(l_rta->rta_type)
        {
            case IFLA_ADDRESS:
            case IFLA_BROADCAST:
            {
                auto l_addrLen = calcAddrLen(AF_PACKET, l_rtaDataSize);
                makeSockaddr(AF_PACKET, (sockaddr *)l_addr, l_rtaData, l_rtaDataSize);
                reinterpret_cast<sockaddr_ll *>(l_addr)->sll_ifindex = l_info->ifi_index;
                reinterpret_cast<sockaddr_ll *>(l_addr)->sll_hatype = l_info->ifi_type;
                if(l_rta->rta_type == IFLA_ADDRESS)
                {
                    l_entry->ifa_addr = reinterpret_cast<sockaddr *>(l_addr);
                }
                else
                {
                    l_entry->ifa_broadaddr = reinterpret_cast<sockaddr *>(l_addr);
                }
                l_addr += NLMSG_ALIGN(l_addrLen);
                break;
            }
            case IFLA_IFNAME:
                strncpy(l_name, static_cast<const char*>(l_rtaData), l_rtaDataSize);
                l_name[l_rtaDataSize] = '\0';
                l_entry->ifa_name = l_name;
                break;
            case IFLA_STATS:
                memcpy(l_data, l_rtaData, l_rtaDataSize);
                l_entry->ifa_data = l_data;
                break;
            default:
                break;
        }
    }

    addToEnd(p_resultList, l_entry);
    return 0;
}

static ifaddrs *findInterface(int p_index, ifaddrs **p_links, int p_numLinks)
{
    auto l_num = 0;
    auto *l_cur = *p_links;
    while(l_cur && l_num < p_numLinks)
    {
        auto l_indexPtr = (reinterpret_cast<char *>(l_cur)) + sizeof(ifaddrs);
        auto l_index = int{};
        memcpy(&l_index, l_indexPtr, sizeof(int));
        if(l_index == p_index)
        {
            return l_cur;
        }

        l_cur = l_cur->ifa_next;
        ++l_num;
    }
    return nullptr;
}

static int interpretAddr(nlmsghdr *p_hdr, ifaddrs **p_resultList, int p_numLinks)
{
    auto l_info = static_cast<ifaddrmsg *>(NLMSG_DATA(p_hdr));
    auto *l_interface = findInterface(l_info->ifa_index, p_resultList, p_numLinks);

    auto l_rtaSize = NLMSG_PAYLOAD(p_hdr, sizeof(ifaddrmsg));

    auto l_nameSize = 0ull;
    auto l_addrSize = 0ull;
    auto l_addedNetmask = 0;
    for(auto l_rta = IFA_RTA(l_info); RTA_OK(l_rta, l_rtaSize); l_rta = RTA_NEXT(l_rta, l_rtaSize))
    {
        auto l_rtaDataSize = RTA_PAYLOAD(l_rta);
        if(l_info->ifa_family == AF_PACKET)
        {
            continue;
        }

        switch(l_rta->rta_type)
        {
            case IFA_ADDRESS:
            case IFA_LOCAL:
                l_addrSize += NLMSG_ALIGN(calcAddrLen(l_info->ifa_family, l_rtaDataSize));
                if((l_info->ifa_family == AF_INET || l_info->ifa_family == AF_INET6) && !l_addedNetmask)
                {
                    /* Make room for netmask */
                    l_addrSize += NLMSG_ALIGN(calcAddrLen(l_info->ifa_family, l_rtaDataSize));
                    l_addedNetmask = 1;
                }
                break;
            case IFA_BROADCAST:
                l_addrSize += NLMSG_ALIGN(calcAddrLen(l_info->ifa_family, l_rtaDataSize));
                break;
            case IFA_LABEL:
                l_nameSize += NLMSG_ALIGN(l_rtaDataSize + 1);
                break;
            default:
                break;
        }
    }

    auto l_entry = static_cast<ifaddrs *>(uv__malloc(sizeof(ifaddrs) + l_nameSize + l_addrSize));
    if (l_entry == nullptr)
    {
        return -1;
    }
    memset(l_entry, 0, sizeof(ifaddrs));
    l_entry->ifa_name = const_cast<char*>(l_interface ? l_interface->ifa_name : "");

    auto l_name = (reinterpret_cast<char *>(l_entry)) + sizeof(ifaddrs);
    auto l_addr = l_name + l_nameSize;

    l_entry->ifa_flags = l_info->ifa_flags;
    if(l_interface)
    {
        l_entry->ifa_flags |= l_interface->ifa_flags;
    }

    l_rtaSize = NLMSG_PAYLOAD(p_hdr, sizeof(ifaddrmsg));
    for(auto l_rta = IFA_RTA(l_info); RTA_OK(l_rta, l_rtaSize); l_rta = RTA_NEXT(l_rta, l_rtaSize))
    {
        auto *l_rtaData = RTA_DATA(l_rta);
        auto l_rtaDataSize = RTA_PAYLOAD(l_rta);
        switch(l_rta->rta_type)
        {
            case IFA_ADDRESS:
            case IFA_BROADCAST:
            case IFA_LOCAL:
            {
                auto l_addrLen = calcAddrLen(l_info->ifa_family, l_rtaDataSize);
                makeSockaddr(l_info->ifa_family, reinterpret_cast<sockaddr *>(l_addr), l_rtaData, l_rtaDataSize);
                if(l_info->ifa_family == AF_INET6)
                {
                    if(IN6_IS_ADDR_LINKLOCAL(static_cast<in6_addr *>(l_rtaData)) || IN6_IS_ADDR_MC_LINKLOCAL(static_cast<in6_addr *>(l_rtaData)))
                    {
                        (reinterpret_cast<sockaddr_in6 *>(l_addr))->sin6_scope_id = l_info->ifa_index;
                    }
                }

                /* Apparently in a point-to-point network IFA_ADDRESS contains
                 * the dest address and IFA_LOCAL contains the local address
                 */
                if(l_rta->rta_type == IFA_ADDRESS)
                {
                    if(l_entry->ifa_addr)
                    {
                        l_entry->ifa_dstaddr = reinterpret_cast<sockaddr *>(l_addr);
                    }
                    else
                    {
                        l_entry->ifa_addr = reinterpret_cast<sockaddr *>(l_addr);
                    }
                }
                else if(l_rta->rta_type == IFA_LOCAL)
                {
                    if(l_entry->ifa_addr)
                    {
                        l_entry->ifa_dstaddr = l_entry->ifa_addr;
                    }
                    l_entry->ifa_addr = reinterpret_cast<sockaddr *>(l_addr);
                }
                else
                {
                    l_entry->ifa_broadaddr = reinterpret_cast<sockaddr *>(l_addr);
                }
                l_addr += NLMSG_ALIGN(l_addrLen);
                break;
            }
            case IFA_LABEL:
                strncpy(l_name, static_cast<const char*>(l_rtaData), l_rtaDataSize);
                l_name[l_rtaDataSize] = '\0';
                l_entry->ifa_name = l_name;
                break;
            default:
                break;
        }
    }

    if(l_entry->ifa_addr && (l_entry->ifa_addr->sa_family == AF_INET || l_entry->ifa_addr->sa_family == AF_INET6))
    {
        auto l_maxPrefix = static_cast<unsigned int>(l_entry->ifa_addr->sa_family == AF_INET ? 32 : 128);
        auto l_prefix = static_cast<unsigned int>(l_info->ifa_prefixlen > l_maxPrefix ? l_maxPrefix : l_info->ifa_prefixlen);
        unsigned char l_mask[16] = {0};
        auto i = unsigned{};
        for(i=0; i<(l_prefix/8); ++i)
        {
            l_mask[i] = 0xff;
        }
        if(l_prefix % 8)
        {
            l_mask[i] = 0xff << (8 - (l_prefix % 8));
        }

        makeSockaddr(l_entry->ifa_addr->sa_family, reinterpret_cast<sockaddr *>(l_addr), l_mask, l_maxPrefix / 8);
        l_entry->ifa_netmask = reinterpret_cast<sockaddr *>(l_addr);
    }

    addToEnd(p_resultList, l_entry);
    return 0;
}

static int interpretLinks(int p_socket, pid_t p_pid, NetlinkList *p_netlinkList, ifaddrs **p_resultList)
{

    auto l_numLinks = 0;
    for(; p_netlinkList; p_netlinkList = p_netlinkList->m_next)
    {
        auto l_nlsize = p_netlinkList->m_size;
        for(auto l_hdr = p_netlinkList->m_data; NLMSG_OK(l_hdr, l_nlsize); l_hdr = NLMSG_NEXT(l_hdr, l_nlsize))
        {
            if(static_cast<pid_t>(l_hdr->nlmsg_pid) != p_pid || static_cast<int>(l_hdr->nlmsg_seq) != p_socket)
            {
                continue;
            }

            if(l_hdr->nlmsg_type == NLMSG_DONE)
            {
                break;
            }

            if(l_hdr->nlmsg_type == RTM_NEWLINK)
            {
                if(interpretLink(l_hdr, p_resultList) == -1)
                {
                    return -1;
                }
                ++l_numLinks;
            }
        }
    }
    return l_numLinks;
}

static int interpretAddrs(int p_socket, pid_t p_pid, NetlinkList *p_netlinkList, ifaddrs **p_resultList, int p_numLinks)
{
    for(; p_netlinkList; p_netlinkList = p_netlinkList->m_next)
    {
        auto l_nlsize = p_netlinkList->m_size;
        for(auto l_hdr = p_netlinkList->m_data; NLMSG_OK(l_hdr, l_nlsize); l_hdr = NLMSG_NEXT(l_hdr, l_nlsize))
        {
            if(static_cast<pid_t>(l_hdr->nlmsg_pid) != p_pid || static_cast<int>(l_hdr->nlmsg_seq) != p_socket)
            {
                continue;
            }

            if(l_hdr->nlmsg_type == NLMSG_DONE)
            {
                break;
            }

            if(l_hdr->nlmsg_type == RTM_NEWADDR)
            {
                if (interpretAddr(l_hdr, p_resultList, p_numLinks) == -1)
                {
                    return -1;
                }
            }
        }
    }
    return 0;
}

int getifaddrs(ifaddrs **ifap)
{

    if(!ifap)
    {
        return -1;
    }
    *ifap = nullptr;

    auto l_pid = pid_t{};
    auto l_socket = netlink_socket(&l_pid);
    if(l_socket < 0)
    {
        return -1;
    }

    auto l_linkResults = getResultList(l_socket, RTM_GETLINK, l_pid);
    if(!l_linkResults)
    {
        close(l_socket);
        return -1;
    }

    auto l_addrResults = getResultList(l_socket, RTM_GETADDR, l_pid);
    if(!l_addrResults)
    {
        close(l_socket);
        freeResultList(l_linkResults);
        return -1;
    }

    auto l_result = 0;
    auto l_numLinks = interpretLinks(l_socket, l_pid, l_linkResults, ifap);
    if(l_numLinks == -1 || interpretAddrs(l_socket, l_pid, l_addrResults, ifap, l_numLinks) == -1)
    {
        l_result = -1;
    }

    freeResultList(l_linkResults);
    freeResultList(l_addrResults);
    close(l_socket);
    return l_result;
}

void freeifaddrs(ifaddrs *ifa)
{
    while(ifa)
    {
        auto l_cur = ifa;
        ifa = ifa->ifa_next;
        uv__free(l_cur);
    }
}
