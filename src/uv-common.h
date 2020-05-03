/* 
 * Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

/*
 * This file is private to libuv. It provides common functionality to both
 * Windows and Unix backends.
 */

#pragma once

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <type_traits>

#if defined(_MSC_VER) && _MSC_VER < 1600
# include "uv/stdint-msvc2008.h"
#else
# include <stdint.h>
#endif

#include "uv.h"
#include "uv/tree.h"
#include "queue.h"
#include "strscpy.h"

#if EDOM > 0
# define UV__ERR(x) (-(x))
#else
# define UV__ERR(x) (x)
#endif

#if !defined(snprintf) && defined(_MSC_VER) && _MSC_VER < 1900
extern "C" int snprintf(char*, size_t, const char*, ...);
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define container_of(ptr, type, member) \
  ((type *) ((char *) (ptr) - offsetof(type, member)))

#define STATIC_ASSERT(expr)                                                   \
  void uv__static_assert(int static_assert_failed[1 - 2 * !(expr)])

/* Handle flags. Some flags are specific to Windows or UNIX. */
enum {
  /* Used by all handles. */
  UV_HANDLE_CLOSING                     = 0x00000001,
  UV_HANDLE_CLOSED                      = 0x00000002,
  UV_HANDLE_ACTIVE                      = 0x00000004,
  UV_HANDLE_REF                         = 0x00000008,
  UV_HANDLE_INTERNAL                    = 0x00000010,
  UV_HANDLE_ENDGAME_QUEUED              = 0x00000020,

  /* Used by streams. */
  UV_HANDLE_LISTENING                   = 0x00000040,
  UV_HANDLE_CONNECTION                  = 0x00000080,
  UV_HANDLE_SHUTTING                    = 0x00000100,
  UV_HANDLE_SHUT                        = 0x00000200,
  UV_HANDLE_READ_PARTIAL                = 0x00000400,
  UV_HANDLE_READ_EOF                    = 0x00000800,

  /* Used by streams and UDP handles. */
  UV_HANDLE_READING                     = 0x00001000,
  UV_HANDLE_BOUND                       = 0x00002000,
  UV_HANDLE_READABLE                    = 0x00004000,
  UV_HANDLE_WRITABLE                    = 0x00008000,
  UV_HANDLE_READ_PENDING                = 0x00010000,
  UV_HANDLE_SYNC_BYPASS_IOCP            = 0x00020000,
  UV_HANDLE_ZERO_READ                   = 0x00040000,
  UV_HANDLE_EMULATE_IOCP                = 0x00080000,
  UV_HANDLE_BLOCKING_WRITES             = 0x00100000,
  UV_HANDLE_CANCELLATION_PENDING        = 0x00200000,

  /* Used by uv_tcp_t and uv_udp_t handles */
  UV_HANDLE_IPV6                        = 0x00400000,

  /* Only used by uv_tcp_t handles. */
  UV_HANDLE_TCP_NODELAY                 = 0x01000000,
  UV_HANDLE_TCP_KEEPALIVE               = 0x02000000,
  UV_HANDLE_TCP_SINGLE_ACCEPT           = 0x04000000,
  UV_HANDLE_TCP_ACCEPT_STATE_CHANGING   = 0x08000000,
  UV_HANDLE_TCP_SOCKET_CLOSED           = 0x10000000,
  UV_HANDLE_SHARED_TCP_SOCKET           = 0x20000000,

  /* Only used by uv_udp_t handles. */
  UV_HANDLE_UDP_PROCESSING              = 0x01000000,
  UV_HANDLE_UDP_CONNECTED               = 0x02000000,

  /* Only used by uv_pipe_t handles. */
  UV_HANDLE_NON_OVERLAPPED_PIPE         = 0x01000000,
  UV_HANDLE_PIPESERVER                  = 0x02000000,

  /* Only used by uv_tty_t handles. */
  UV_HANDLE_TTY_READABLE                = 0x01000000,
  UV_HANDLE_TTY_RAW                     = 0x02000000,
  UV_HANDLE_TTY_SAVED_POSITION          = 0x04000000,
  UV_HANDLE_TTY_SAVED_ATTRIBUTES        = 0x08000000,

  /* Only used by uv_signal_t handles. */
  UV_SIGNAL_ONE_SHOT_DISPATCHED         = 0x01000000,
  UV_SIGNAL_ONE_SHOT                    = 0x02000000,

  /* Only used by uv_poll_t handles. */
  UV_HANDLE_POLL_SLOW                   = 0x01000000
};

auto uv__loop_configure(uv_loop_t* loop, uv_loop_option option, va_list ap) -> int;

auto uv__loop_close(uv_loop_t* loop) -> void;

auto uv__tcp_bind(uv_tcp_t* tcp,
                 const sockaddr* addr,
                 unsigned int addrlen,
                 unsigned int flags) -> int;

auto uv__tcp_connect(uv_connect_t* req,
                   uv_tcp_t* handle,
                   const sockaddr* addr,
                   unsigned int addrlen,
                   uv_connect_cb cb) -> int;

auto uv__udp_bind(uv_udp_t* handle,
                 const sockaddr* addr,
                 unsigned int  addrlen,
                 unsigned int flags) -> int;

auto uv__udp_connect(uv_udp_t* handle,
                    const sockaddr* addr,
                    unsigned int addrlen) -> int;

auto uv__udp_disconnect(uv_udp_t* handle) -> int;

auto uv__udp_is_connected(uv_udp_t* handle) -> int;

auto uv__udp_send(uv_udp_send_t* req,
                 uv_udp_t* handle,
                 const uv_buf_t bufs[],
                 unsigned int nbufs,
                 const sockaddr* addr,
                 unsigned int addrlen,
                 uv_udp_send_cb send_cb) -> int;

auto uv__udp_try_send(uv_udp_t* handle,
                     const uv_buf_t bufs[],
                     unsigned int nbufs,
                     const sockaddr* addr,
                     unsigned int addrlen) -> int;

auto uv__udp_recv_start(uv_udp_t* handle, uv_alloc_cb alloccb,
                       uv_udp_recv_cb recv_cb) -> int;

auto uv__udp_recv_stop(uv_udp_t* handle) -> int;

auto uv__fs_poll_close(uv_fs_poll_t* handle) -> void;

auto uv__getaddrinfo_translate_error(int sys_err) -> int;    /* EAI_* error. */

enum uv__work_kind {
  UV__WORK_CPU,
  UV__WORK_FAST_IO,
  UV__WORK_SLOW_IO
};

auto uv__work_submit(uv_loop_t* loop,
                     uv__work *w,
                     uv__work_kind kind,
                     void (*work)(uv__work *w),
                     void (*done)(uv__work *w, int status)) -> void;

auto uv__work_done(uv_async_t* handle) -> void;

auto uv__count_bufs(const uv_buf_t bufs[], unsigned int nbufs) -> size_t;

auto uv__socket_sockopt(uv_handle_t* handle, int optname, int* value) -> int;

auto uv__fs_scandir_cleanup(uv_fs_t* req) -> void;
auto uv__fs_readdir_cleanup(uv_fs_t* req) -> void;
auto uv__fs_get_dirent_type(uv__dirent_t* dent) -> uv_dirent_type_t;

auto uv__next_timeout(const uv_loop_t* loop) -> int;
auto uv__run_timers(uv_loop_t* loop) -> void;
auto uv__timer_close(uv_timer_t* handle) -> void;

template <class _loop>
auto uv__has_active_reqs(_loop loop) noexcept -> bool{
  return ((loop)->active_reqs.count > 0);
}

template <class _loop, class _req>
auto uv__req_register(_loop loop, _req req) noexcept {
  (void) req;
  do {
    (loop)->active_reqs.count++;
  }
  while (0);
}

template <class _loop, class _req>
auto uv__req_unregister(_loop loop, _req req) {
  (void) req;
  do {
    assert(uv__has_active_reqs(loop));
    (loop)->active_reqs.count--;
  }
  while (0);
}

template <class _loop>
auto uv__has_active_handles(_loop loop) noexcept -> bool {
  return (loop)->active_handles > 0;
}

template <class _h>
auto uv__active_handle_add(_h h) noexcept {
  do {
    (h)->loop->active_handles++;
  }
  while (0);
}

template <class _h>
auto uv__active_handle_rm(_h h) noexcept {
  do {
    (h)->loop->active_handles--;
  }
  while (0);
}

template <class _h>
auto uv__is_active(_h h) noexcept -> bool {
  return (((h)->flags & UV_HANDLE_ACTIVE) != 0);
}

template <class _h>
auto uv__is_closing(_h h) noexcept -> bool {
  return (((h)->flags & (UV_HANDLE_CLOSING | UV_HANDLE_CLOSED)) != 0);
}

template <class _h>
auto uv__handle_start(_h h) noexcept {
  do {
    if (((h)->flags & UV_HANDLE_ACTIVE) != 0) break;
    (h)->flags |= UV_HANDLE_ACTIVE;
    if (((h)->flags & UV_HANDLE_REF) != 0) uv__active_handle_add(h);
  }
  while (0);
}

template <class _h>
auto uv__handle_stop(_h h) noexcept {
  do {
    if (((h)->flags & UV_HANDLE_ACTIVE) == 0) break;
    (h)->flags &= ~UV_HANDLE_ACTIVE;
    if (((h)->flags & UV_HANDLE_REF) != 0) uv__active_handle_rm(h);
  }
  while (0);
}

template <class _h>
auto uv__handle_ref(_h h) noexcept {
  do {
    if (((h)->flags & UV_HANDLE_REF) != 0) break;
    (h)->flags |= UV_HANDLE_REF;
    if (((h)->flags & UV_HANDLE_CLOSING) != 0) break;
    if (((h)->flags & UV_HANDLE_ACTIVE) != 0) uv__active_handle_add(h);
  }
  while (0);
}

template <class _h>
auto uv__handle_unref(_h h) noexcept {
  do {
    if (((h)->flags & UV_HANDLE_REF) == 0) break;
    (h)->flags &= ~UV_HANDLE_REF;
    if (((h)->flags & UV_HANDLE_CLOSING) != 0) break;
    if (((h)->flags & UV_HANDLE_ACTIVE) != 0) uv__active_handle_rm(h);
  }
  while (0);
}

template <class _h>
auto uv__has_ref(_h h) noexcept -> bool{
  return ((h)->flags & UV_HANDLE_REF) != 0;
}

#if defined(_WIN32)
template <class _h>
auto uv__handle_platform_init(_h h) noexcept { (h)->u.fd = -1; }
#else
template <class _h>
auto uv__handle_platform_init(_h h) noexcept { (h)->next_closing = nullptr ;}
#endif

template<class _loop, class _h, class _type>
auto uv__handle_init(_loop loop_, _h h, _type type_) noexcept {
  do{
    (h)->loop = (loop_);
    (h)->type = (type_);
    (h)->flags = UV_HANDLE_REF; /* Ref the loop when active. */
    QUEUE_INSERT_TAIL(&(loop_)->handle_queue, &(h)->handle_queue);
    uv__handle_platform_init(h);
  }
  while(0);
}

/* Note: uses an open-coded version of SET_REQ_SUCCESS() because of
 * a circular dependency between src/uv-common.h and src/win/internal.h.
 */
#if defined(_WIN32)
template<class _req, class _typ>
auto UV_REQ_INIT(_req req, _typ typ) noexcept {
  do {
    (req)->type = (typ);
    (req)->u.io.overlapped.Internal = 0; /* SET_REQ_SUCCESS() */
  }
  while (0);
}
#else
template<class _req, class _typ>
auto UV_REQ_INIT(_req req, _typ typ) noexcept {
  do {
    (req)->type = (typ);
  }
  while (0);
}
#endif

template<class _loop, class _req, class _typ>
auto uv__req_init(_loop loop, _req req, _typ typ) noexcept {
  do {
    UV_REQ_INIT(req, typ);
    uv__req_register(loop, req);
  }
  while (0);
}


/* Allocator prototypes */
auto uv__calloc(size_t count, size_t size) -> void *;
auto uv__strdup(const char* s) -> char *;
auto uv__strndup(const char* s, size_t n) -> char *;
auto uv__malloc(size_t size) -> void*;
auto uv__free(void* ptr) -> void;
auto uv__realloc(void* ptr, size_t size) -> void*;
auto uv__reallocf(void* ptr, size_t size) -> void*;
