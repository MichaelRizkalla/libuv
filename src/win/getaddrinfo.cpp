/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>

#include "uv.h"
#include "internal.h"
#include "req-inl.h"
#include "idna.h"

/* EAI_* constants. */
#include <winsock2.h>

/* Needed for ConvertInterfaceIndexToLuid and ConvertInterfaceLuidToNameA */
#include <iphlpapi.h>

int uv__getaddrinfo_translate_error(int sys_err) {
  switch (sys_err) {
    case 0:                       return 0;
    case WSATRY_AGAIN:            return UV_EAI_AGAIN;
    case WSAEINVAL:               return UV_EAI_BADFLAGS;
    case WSANO_RECOVERY:          return UV_EAI_FAIL;
    case WSAEAFNOSUPPORT:         return UV_EAI_FAMILY;
    case WSA_NOT_ENOUGH_MEMORY:   return UV_EAI_MEMORY;
    case WSAHOST_NOT_FOUND:       return UV_EAI_NONAME;
    case WSATYPE_NOT_FOUND:       return UV_EAI_SERVICE;
    case WSAESOCKTNOSUPPORT:      return UV_EAI_SOCKTYPE;
    default:                      return uv_translate_sys_error(sys_err);
  }
}


/*
 * MinGW is missing this
 */
#if !defined(_MSC_VER) && !defined(__MINGW64_VERSION_MAJOR)
  struct addrinfoW {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    WCHAR* ai_canonname;
    sockaddr* ai_addr;
    addrinfoW* ai_next;
  };
  typedef addrinfoW ADDRINFOW;
  typedef addrinfoW *PADDRINFOW;

  DECLSPEC_IMPORT int WSAAPI GetAddrInfoW(const WCHAR* node,
                                          const WCHAR* service,
                                          const ADDRINFOW* hints,
                                          PADDRINFOW* result);

  DECLSPEC_IMPORT void WSAAPI FreeAddrInfoW(PADDRINFOW pAddrInfo);
#endif


/* Adjust size value to be multiple of 4. Use to keep pointer aligned.
 * Do we need different versions of this for different architectures? */
#define ALIGNED_SIZE(X)     ((((X) + 3) >> 2) << 2)

#ifndef NDIS_IF_MAX_STRING_SIZE
#define NDIS_IF_MAX_STRING_SIZE IF_MAX_STRING_SIZE
#endif

static void uv__getaddrinfo_work(uv__work* w) {

  auto *req = container_of(w, uv_getaddrinfo_t, work_req);
  auto *hints = req->addrinfow;
  req->addrinfow = nullptr;
  auto err = GetAddrInfoW(req->node, req->service, hints, &req->addrinfow);
  req->retcode = uv__getaddrinfo_translate_error(err);
}

/*
 * Called from uv_run when complete. Call user specified callback
 * then free returned addrinfo
 * Returned addrinfo strings are converted from UTF-16 to UTF-8.
 *
 * To minimize allocation we calculate total size required,
 * and copy all structs and referenced strings into the one block.
 * Each size calculation is adjusted to avoid unaligned pointers.
 */
static void uv__getaddrinfo_done(uv__work* w, int status) {

  auto req = container_of(w, uv_getaddrinfo_t, work_req);
  /* release input parameter memory */
  uv__free(req->alloc);
  req->alloc = nullptr;

  if (status == UV_ECANCELED) {
    assert(req->retcode == 0);
    req->retcode = UV_EAI_CANCELED;

    uv__req_unregister(req->loop, req);

    /* finally do callback with converted result */
    if (req->getaddrinfo_cb)
      req->getaddrinfo_cb(req, req->retcode, req->addrinfo);
    return;
  }

  if (req->retcode == 0) {

    /* Convert addrinfoW to addrinfo. First calculate required length. */
    auto addrinfow_ptr = req->addrinfow;
    auto addrinfo_len = 0;
    auto addrinfo_struct_len = ALIGNED_SIZE(sizeof(addrinfo));

    while (addrinfow_ptr != nullptr) {
      addrinfo_len += static_cast<int>(addrinfo_struct_len +
          ALIGNED_SIZE(addrinfow_ptr->ai_addrlen));
      if (addrinfow_ptr->ai_canonname != nullptr) {
        auto name_len = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       addrinfow_ptr->ai_canonname,
                                       -1,
                                       nullptr,
                                       0,
                                       nullptr,
                                       nullptr);
        if (name_len == 0) {
          req->retcode = uv_translate_sys_error(GetLastError());
          uv__req_unregister(req->loop, req);

          /* finally do callback with converted result */
          if (req->getaddrinfo_cb)
            req->getaddrinfo_cb(req, req->retcode, req->addrinfo);
          return;
        }
        addrinfo_len += ALIGNED_SIZE(name_len);
      }
      addrinfow_ptr = addrinfow_ptr->ai_next;
    }

    /* allocate memory for addrinfo results */
    auto alloc_ptr = (char*)uv__malloc(addrinfo_len);

    /* do conversions */
    if (alloc_ptr != nullptr) {
      auto cur_ptr = alloc_ptr;
      addrinfow_ptr = req->addrinfow;

      while (addrinfow_ptr != nullptr) {
        /* copy addrinfo struct data */
        assert(cur_ptr + addrinfo_struct_len <= alloc_ptr + addrinfo_len);
        auto addrinfo_ptr = reinterpret_cast<addrinfo*>(cur_ptr);
        addrinfo_ptr->ai_family = addrinfow_ptr->ai_family;
        addrinfo_ptr->ai_socktype = addrinfow_ptr->ai_socktype;
        addrinfo_ptr->ai_protocol = addrinfow_ptr->ai_protocol;
        addrinfo_ptr->ai_flags = addrinfow_ptr->ai_flags;
        addrinfo_ptr->ai_addrlen = addrinfow_ptr->ai_addrlen;
        addrinfo_ptr->ai_canonname = nullptr;
        addrinfo_ptr->ai_addr = nullptr;
        addrinfo_ptr->ai_next = nullptr;

        cur_ptr += addrinfo_struct_len;

        /* copy sockaddr */
        if (addrinfo_ptr->ai_addrlen > 0) {
          assert(cur_ptr + addrinfo_ptr->ai_addrlen <=
                 alloc_ptr + addrinfo_len);
          memcpy(cur_ptr, addrinfow_ptr->ai_addr, addrinfo_ptr->ai_addrlen);
          addrinfo_ptr->ai_addr = reinterpret_cast<sockaddr*>(cur_ptr);
          cur_ptr += ALIGNED_SIZE(addrinfo_ptr->ai_addrlen);
        }

        /* convert canonical name to UTF-8 */
        if (addrinfow_ptr->ai_canonname != nullptr) {
          auto name_len = WideCharToMultiByte(CP_UTF8,
                                         0,
                                         addrinfow_ptr->ai_canonname,
                                         -1,
                                         nullptr,
                                         0,
                                         nullptr,
                                         nullptr);
          assert(name_len > 0);
          assert(cur_ptr + name_len <= alloc_ptr + addrinfo_len);
          name_len = WideCharToMultiByte(CP_UTF8,
                                         0,
                                         addrinfow_ptr->ai_canonname,
                                         -1,
                                         cur_ptr,
                                         name_len,
                                         nullptr,
                                         nullptr);
          assert(name_len > 0);
          addrinfo_ptr->ai_canonname = cur_ptr;
          cur_ptr += ALIGNED_SIZE(name_len);
        }
        assert(cur_ptr <= alloc_ptr + addrinfo_len);

        /* set next ptr */
        addrinfow_ptr = addrinfow_ptr->ai_next;
        if (addrinfow_ptr != nullptr) {
          addrinfo_ptr->ai_next = reinterpret_cast<addrinfo*>(cur_ptr);
        }
      }
      req->addrinfo = reinterpret_cast<addrinfo*>(alloc_ptr);
    } else {
      req->retcode = UV_EAI_MEMORY;
    }
  }

  /* return memory to system */
  if (req->addrinfow != nullptr) {
    FreeAddrInfoW(req->addrinfow);
    req->addrinfow = nullptr;
  }

  uv__req_unregister(req->loop, req);

  /* finally do callback with converted result */
  if (req->getaddrinfo_cb)
    req->getaddrinfo_cb(req, req->retcode, req->addrinfo);
}

void uv_freeaddrinfo(addrinfo* ai) {
  auto *alloc_ptr = reinterpret_cast<char*>(ai);

  /* release copied result memory */
  uv__free(alloc_ptr);
}

/*
 * Entry point for getaddrinfo
 * we convert the UTF-8 strings to UNICODE
 * and save the UNICODE string pointers in the req
 * We also copy hints so that caller does not need to keep memory until the
 * callback.
 * return 0 if a callback will be made
 * return error code if validation fails
 *
 * To minimize allocation we calculate total size required,
 * and copy all structs and referenced strings into the one block.
 * Each size calculation is adjusted to avoid unaligned pointers.
 */
int uv_getaddrinfo(uv_loop_t* loop,
                   uv_getaddrinfo_t* req,
                   uv_getaddrinfo_cb getaddrinfo_cb,
                   const char* node,
                   const char* service,
                   const addrinfo* hints) {

  if (req == nullptr || (node == nullptr && service == nullptr)) {
    return UV_EINVAL;
  }

  UV_REQ_INIT(req, UV_GETADDRINFO);
  req->getaddrinfo_cb = getaddrinfo_cb;
  req->addrinfo = nullptr;
  req->loop = loop;
  req->retcode = 0;

  /* calculate required memory size for all input values */
  auto nodesize = 0;
  char hostname_ascii[256];
  if (node != nullptr) {
    auto rc = uv__idna_toascii(node,
                          node + strlen(node),
                          hostname_ascii,
                          hostname_ascii + sizeof(hostname_ascii));
    if (rc < 0)
      return rc;
    nodesize = ALIGNED_SIZE(MultiByteToWideChar(CP_UTF8, 0, hostname_ascii,
                                                -1, nullptr, 0) * sizeof(WCHAR));
    if (nodesize == 0) {
      auto err = GetLastError();
      
      if (req != nullptr) {
        uv__free(req->alloc);
        req->alloc = nullptr;
      }
      return uv_translate_sys_error(err);
    }
    node = hostname_ascii;
  }

  auto servicesize = 0;
  if (service != nullptr) {
    servicesize = ALIGNED_SIZE(MultiByteToWideChar(CP_UTF8,
                                                   0,
                                                   service,
                                                   -1,
                                                   nullptr,
                                                   0) *
                               sizeof(WCHAR));
    if (servicesize == 0) {
      auto err = GetLastError();
      
      if (req != nullptr) {
        uv__free(req->alloc);
        req->alloc = nullptr;
      }
      return uv_translate_sys_error(err);
    }
  }

  auto hintssize = 0;
  if (hints != nullptr) {
    hintssize = ALIGNED_SIZE(sizeof(addrinfoW));
  }

  /* allocate memory for inputs, and partition it as needed */
  auto *alloc_ptr = (char*)uv__malloc(nodesize + servicesize + hintssize);
  if (!alloc_ptr) {
    auto err = WSAENOBUFS;
      
    if (req != nullptr) {
      uv__free(req->alloc);
      req->alloc = nullptr;
    }
    return uv_translate_sys_error(err);
  }

  /* save alloc_ptr now so we can free if error */
  req->alloc = static_cast<void*>(alloc_ptr);

  /* Convert node string to UTF16 into allocated memory and save pointer in the
   * request. */
  if (node != nullptr) {
    req->node = reinterpret_cast<WCHAR*>(alloc_ptr);
    if (MultiByteToWideChar(CP_UTF8,
                            0,
                            node,
                            -1,
                            reinterpret_cast<WCHAR*>(alloc_ptr),
                            nodesize / sizeof(WCHAR)) == 0) {
      auto err = GetLastError();
      
      if (req != nullptr) {
        uv__free(req->alloc);
        req->alloc = nullptr;
      }
      return uv_translate_sys_error(err);
    }
    alloc_ptr += nodesize;
  } else {
    req->node = nullptr;
  }

  /* Convert service string to UTF16 into allocated memory and save pointer in
   * the req. */
  if (service != nullptr) {
    req->service = reinterpret_cast<WCHAR*>(alloc_ptr);
    if (MultiByteToWideChar(CP_UTF8,
                            0,
                            service,
                            -1,
                            reinterpret_cast<WCHAR*>(alloc_ptr),
                            servicesize / sizeof(WCHAR)) == 0) {
      auto err = GetLastError();

      if (req != nullptr) {
        uv__free(req->alloc);
        req->alloc = nullptr;
      }
      return uv_translate_sys_error(err);
    }
    alloc_ptr += servicesize;
  } else {
    req->service = nullptr;
  }

  /* copy hints to allocated memory and save pointer in req */
  if (hints != nullptr) {
    req->addrinfow = reinterpret_cast<addrinfoW*>(alloc_ptr);
    req->addrinfow->ai_family = hints->ai_family;
    req->addrinfow->ai_socktype = hints->ai_socktype;
    req->addrinfow->ai_protocol = hints->ai_protocol;
    req->addrinfow->ai_flags = hints->ai_flags;
    req->addrinfow->ai_addrlen = 0;
    req->addrinfow->ai_canonname = nullptr;
    req->addrinfow->ai_addr = nullptr;
    req->addrinfow->ai_next = nullptr;
  } else {
    req->addrinfow = nullptr;
  }

  uv__req_register(loop, req);

  if (getaddrinfo_cb) {
    uv__work_submit(loop,
                    &req->work_req,
                    UV__WORK_SLOW_IO,
                    uv__getaddrinfo_work,
                    uv__getaddrinfo_done);
    return 0;
  } else {
    uv__getaddrinfo_work(&req->work_req);
    uv__getaddrinfo_done(&req->work_req, 0);
    return req->retcode;
  }
}

int uv_if_indextoname(unsigned int ifindex, char* buffer, size_t* size) {
  wchar_t wname[NDIS_IF_MAX_STRING_SIZE + 1]; /* Add one for the NUL. */

  if (buffer == nullptr || size == nullptr || *size == 0)
    return UV_EINVAL;

  auto luid = NET_LUID{};
  auto r = ConvertInterfaceIndexToLuid(ifindex, &luid);

  if (r != 0)
    return uv_translate_sys_error(r);

  r = ConvertInterfaceLuidToNameW(&luid, wname, ARRAY_SIZE(wname));

  if (r != 0)
    return uv_translate_sys_error(r);

  /* Check how much space we need */
  auto bufsize = WideCharToMultiByte(CP_UTF8, 0, wname, -1, nullptr, 0, nullptr, nullptr);

  if (bufsize == 0) {
    return uv_translate_sys_error(GetLastError());
  } else if (bufsize > *size) {
    *size = bufsize;
    return UV_ENOBUFS;
  }

  /* Convert to UTF-8 */
  bufsize = WideCharToMultiByte(CP_UTF8,
                                0,
                                wname,
                                -1,
                                buffer,
                                static_cast<int>(*size),
                                nullptr,
                                nullptr);

  if (bufsize == 0)
    return uv_translate_sys_error(GetLastError());

  *size = bufsize - 1;
  return 0;
}

int uv_if_indextoiid(unsigned int ifindex, char* buffer, size_t* size) {

  if (buffer == nullptr || size == nullptr || *size == 0)
    return UV_EINVAL;

  auto r = snprintf(buffer, *size, "%d", ifindex);

  if (r < 0)
    return uv_translate_sys_error(r);

  if (r >= static_cast<int>(*size)) {
    *size = r + 1;
    return UV_ENOBUFS;
  }

  *size = r;
  return 0;
}
