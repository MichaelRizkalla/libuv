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
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "handle-inl.h"
#include "internal.h"
#include "req-inl.h"
#include "stream-inl.h"
#include "uv-common.h"
#include "uv.h"

#include <aclapi.h>
#include <accctrl.h>
#include "../utils/allocator.cpp"
/* A zero-size buffer for use by uv_pipe_read */
static char uv_zero_[] = "";

/* Null uv_buf_t */
static const uv_buf_t uv_null_buf_ = { 0, nullptr };

/* The timeout that the pipe will wait for the remote end to write data when
 * the local ends wants to shut it down. */
static const int64_t eof_timeout = 50; /* ms */

static const int default_pending_pipe_instances = 4;

/* Pipe prefix */
static char pipe_prefix[] = "\\\\?\\pipe";
static const int pipe_prefix_len = sizeof(pipe_prefix) - 1;

/* IPC incoming xfer queue item. */
struct uv__ipc_xfer_queue_item_t{
  uv__ipc_socket_xfer_type_t xfer_type;
  uv__ipc_socket_xfer_info_t xfer_info;
  QUEUE member;
};

/* IPC frame header flags. */
/* clang-format off */
enum {
  UV__IPC_FRAME_HAS_DATA                = 0x01,
  UV__IPC_FRAME_HAS_SOCKET_XFER         = 0x02,
  UV__IPC_FRAME_XFER_IS_TCP_CONNECTION  = 0x04,
  /* These are combinations of the flags above. */
  UV__IPC_FRAME_XFER_FLAGS              = 0x06,
  UV__IPC_FRAME_VALID_FLAGS             = 0x07
};
/* clang-format on */

/* IPC frame header. */
struct uv__ipc_frame_header_t {
  uint32_t flags;
  uint32_t reserved1;   /* Ignored. */
  uint32_t data_length; /* Must be zero if there is no data. */
  uint32_t reserved2;   /* Must be zero. */
};

/* To implement the IPC protocol correctly, these structures must have exactly
 * the right size. */
STATIC_ASSERT(sizeof(uv__ipc_frame_header_t) == 16);
STATIC_ASSERT(sizeof(uv__ipc_socket_xfer_info_t) == 632);

/* Coalesced write request. */
struct uv__coalesced_write_t{
  uv_write_t req;       /* Internal heap-allocated write request. */
  uv_write_t* user_req; /* Pointer to user-specified uv_write_t. */
};

static void eof_timer_init(uv_pipe_t* pipe);
static void eof_timer_start(uv_pipe_t* pipe);
static void eof_timer_stop(uv_pipe_t* pipe);
static void eof_timer_cb(uv_timer_t* timer);
static void eof_timer_destroy(uv_pipe_t* pipe);
static void eof_timer_close_cb(uv_handle_t* handle);

static void uv_unique_pipe_name(char* ptr, char* name, size_t size) {
  snprintf(name, size, "\\\\?\\pipe\\uv\\%p-%lu", ptr, GetCurrentProcessId());
}

int uv_pipe_init(uv_loop_t* loop, uv_pipe_t* handle, int ipc) {
  uv_stream_init(loop, reinterpret_cast<uv_stream_t*>(handle), UV_NAMED_PIPE);

  handle->reqs_pending = 0;
  handle->handle = INVALID_HANDLE_VALUE;
  handle->name = nullptr;
  handle->pipe.conn.ipc_remote_pid = 0;
  handle->pipe.conn.ipc_data_frame.payload_remaining = 0;
  QUEUE_INIT(&handle->pipe.conn.ipc_xfer_queue);
  handle->pipe.conn.ipc_xfer_queue_length = 0;
  handle->ipc = ipc;
  handle->pipe.conn.non_overlapped_writes_tail = nullptr;

  return 0;
}

static void uv_pipe_connection_init(uv_pipe_t* handle) {
  uv_connection_init(reinterpret_cast<uv_stream_t*>(handle));
  handle->read_req.data = handle;
  handle->pipe.conn.eof_timer = nullptr;
  assert(!(handle->flags & UV_HANDLE_PIPESERVER));
  if (handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE) {
    handle->pipe.conn.readfile_thread_handle = nullptr;
    InitializeCriticalSection(&handle->pipe.conn.readfile_thread_lock);
  }
}

static HANDLE open_named_pipe(const WCHAR* name, DWORD* duplex_flags) {

  /*
   * Assume that we have a duplex pipe first, so attempt to
   * connect with GENERIC_READ | GENERIC_WRITE.
   */
  auto pipeHandle = CreateFileW(name,
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED,
                           nullptr);
  if (pipeHandle != INVALID_HANDLE_VALUE) {
    *duplex_flags = UV_HANDLE_READABLE | UV_HANDLE_WRITABLE;
    return pipeHandle;
  }

  /*
   * If the pipe is not duplex CreateFileW fails with
   * ERROR_ACCESS_DENIED.  In that case try to connect
   * as a read-only or write-only.
   */
  if (GetLastError() == ERROR_ACCESS_DENIED) {
    pipeHandle = CreateFileW(name,
                             GENERIC_READ | FILE_WRITE_ATTRIBUTES,
                             0,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED,
                             nullptr);

    if (pipeHandle != INVALID_HANDLE_VALUE) {
      *duplex_flags = UV_HANDLE_READABLE;
      return pipeHandle;
    }
  }

  if (GetLastError() == ERROR_ACCESS_DENIED) {
    pipeHandle = CreateFileW(name,
                             GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                             0,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED,
                             nullptr);

    if (pipeHandle != INVALID_HANDLE_VALUE) {
      *duplex_flags = UV_HANDLE_WRITABLE;
      return pipeHandle;
    }
  }

  return INVALID_HANDLE_VALUE;
}

static void close_pipe(uv_pipe_t* pipe) {
  assert(pipe->u.fd == -1 || pipe->u.fd > 2);
  if (pipe->u.fd == -1)
    CloseHandle(pipe->handle);
  else
    _close(pipe->u.fd);

  pipe->u.fd = -1;
  pipe->handle = INVALID_HANDLE_VALUE;
}

int uv_stdio_pipe_server(uv_loop_t* loop, uv_pipe_t* handle, DWORD access,
    char* name, size_t nameSize) {

  char* ptr = reinterpret_cast<char*>(handle);
  auto pipeHandle = HANDLE{};
  for (;;) {
    uv_unique_pipe_name(ptr, name, nameSize);

    pipeHandle = CreateNamedPipeA(name,
      access | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0,
      nullptr);

    if (pipeHandle != INVALID_HANDLE_VALUE) {
      /* No name collisions.  We're done. */
      break;
    }

    auto err = GetLastError();
    if (err != ERROR_PIPE_BUSY && err != ERROR_ACCESS_DENIED) {
      if (pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(pipeHandle);
      }
      return err;
    }

    /* Pipe name collision.  Increment the pointer and try again. */
    ptr++;
  }

  if (CreateIoCompletionPort(pipeHandle,
                             loop->iocp,
                             (ULONG_PTR)handle,
                             0) == nullptr) {
    auto err = GetLastError();
    if (pipeHandle != INVALID_HANDLE_VALUE) {
      CloseHandle(pipeHandle);
    }
    return err;
  }

  uv_pipe_connection_init(handle);
  handle->handle = pipeHandle;

  return 0;
}

static int uv_set_pipe_handle(uv_loop_t* loop,
                              uv_pipe_t* handle,
                              HANDLE pipeHandle,
                              int fd,
                              DWORD duplex_flags) {

  if (handle->flags & UV_HANDLE_PIPESERVER)
    return UV_EINVAL;
  if (handle->handle != INVALID_HANDLE_VALUE)
    return UV_EBUSY;

  auto mode = DWORD{PIPE_READMODE_BYTE | PIPE_WAIT};
  if (!SetNamedPipeHandleState(pipeHandle, &mode, nullptr, nullptr)) {
    auto err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
      /*
       * SetNamedPipeHandleState can fail if the handle doesn't have either
       * GENERIC_WRITE  or FILE_WRITE_ATTRIBUTES.
       * But if the handle already has the desired wait and blocking modes
       * we can continue.
       */
      auto current_mode = DWORD{0};
      if (!GetNamedPipeHandleState(pipeHandle, &current_mode, nullptr, nullptr,
                                   nullptr, nullptr, 0)) {
        return -1;
      } else if (current_mode & PIPE_NOWAIT) {
        SetLastError(ERROR_ACCESS_DENIED);
        return -1;
      }
    } else {
      /* If this returns ERROR_INVALID_PARAMETER we probably opened
       * something that is not a pipe. */
      if (err == ERROR_INVALID_PARAMETER) {
        SetLastError(WSAENOTSOCK);
      }
      return -1;
    }
  }

  /* Check if the pipe was created with FILE_FLAG_OVERLAPPED. */
  auto io_status = IO_STATUS_BLOCK{};
  auto mode_info = FILE_MODE_INFORMATION{};
  auto nt_status = pNtQueryInformationFile(pipeHandle,
                                      &io_status,
                                      &mode_info,
                                      sizeof(decltype(mode_info)),
                                      FileModeInformation);
  if (nt_status != STATUS_SUCCESS) {
    return -1;
  }

  if (mode_info.Mode & FILE_SYNCHRONOUS_IO_ALERT ||
      mode_info.Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
    /* Non-overlapped pipe. */
    handle->flags |= UV_HANDLE_NON_OVERLAPPED_PIPE;
  } else {
    /* Overlapped pipe.  Try to associate with IOCP. */
    if (CreateIoCompletionPort(pipeHandle,
                               loop->iocp,
                               reinterpret_cast<ULONG_PTR>(handle),
                               0) == nullptr) {
      handle->flags |= UV_HANDLE_EMULATE_IOCP;
    }
  }

  handle->handle = pipeHandle;
  handle->u.fd = fd;
  handle->flags |= duplex_flags;

  return 0;
}

static int pipe_alloc_accept(uv_loop_t* loop, uv_pipe_t* handle,
                             uv_pipe_accept_t* req, BOOL firstInstance) {
  assert(req->pipeHandle == INVALID_HANDLE_VALUE);

  req->pipeHandle =
      CreateNamedPipeW(handle->name,
                       PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | WRITE_DAC |
                         (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                       PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, nullptr);

  if (req->pipeHandle == INVALID_HANDLE_VALUE) {
    return 0;
  }

  /* Associate it with IOCP so we can get events. */
  if (CreateIoCompletionPort(req->pipeHandle,
                             loop->iocp,
                             reinterpret_cast<ULONG_PTR>(handle),
                             0) == nullptr) {
    uv_fatal_error(GetLastError(), "CreateIoCompletionPort");
  }

  /* Stash a handle in the server object for use from places such as
   * getsockname and chmod. As we transfer ownership of these to client
   * objects, we'll allocate new ones here. */
  handle->handle = req->pipeHandle;

  return 1;
}

static DWORD WINAPI pipe_shutdown_thread_proc(void* parameter) {

  auto *req = static_cast<uv_shutdown_t*>(parameter);
  assert(req);
  auto *handle = reinterpret_cast<uv_pipe_t*>(req->handle);
  assert(handle);
  auto *loop = handle->loop;
  assert(loop);

  FlushFileBuffers(handle->handle);

  /* Post completed */
  POST_COMPLETION_FOR_REQ(loop, req);

  return 0;
}

void uv_pipe_endgame(uv_loop_t* loop, uv_pipe_t* handle) {

  if ((handle->flags & UV_HANDLE_CONNECTION) &&
      handle->stream.conn.shutdown_req != nullptr &&
      handle->stream.conn.write_reqs_pending == 0) {
    auto *req = handle->stream.conn.shutdown_req;

    /* Clear the shutdown_req field so we don't go here again. */
    handle->stream.conn.shutdown_req = nullptr;

    if (handle->flags & UV_HANDLE_CLOSING) {
      UNREGISTER_HANDLE_REQ(loop, handle, req);

      /* Already closing. Cancel the shutdown. */
      if (req->cb) {
        req->cb(req, UV_ECANCELED);
      }

      DECREASE_PENDING_REQ_COUNT(handle);
      return;
    }

    /* Try to avoid flushing the pipe buffer in the thread pool. */
    auto io_status = IO_STATUS_BLOCK{};
    auto pipe_info = FILE_PIPE_LOCAL_INFORMATION{};
    auto nt_status = pNtQueryInformationFile(handle->handle,
                                        &io_status,
                                        &pipe_info,
                                        sizeof pipe_info,
                                        FilePipeLocalInformation);

    if (nt_status != STATUS_SUCCESS) {
      /* Failure */
      UNREGISTER_HANDLE_REQ(loop, handle, req);

      handle->flags |= UV_HANDLE_WRITABLE; /* Questionable */
      if (req->cb) {
        auto err = pRtlNtStatusToDosError(nt_status);
        req->cb(req, uv_translate_sys_error(err));
      }

      DECREASE_PENDING_REQ_COUNT(handle);
      return;
    }

    if (pipe_info.OutboundQuota == pipe_info.WriteQuotaAvailable) {
      /* Short-circuit, no need to call FlushFileBuffers. */
      uv_insert_pending_req(loop, (uv_req_t*) req);
      return;
    }

    /* Run FlushFileBuffers in the thread pool. */
    auto result = QueueUserWorkItem(pipe_shutdown_thread_proc,
                               req,
                               WT_EXECUTELONGFUNCTION);
    if (result) {
      return;

    } else {
      /* Failure. */
      UNREGISTER_HANDLE_REQ(loop, handle, req);

      handle->flags |= UV_HANDLE_WRITABLE; /* Questionable */
      if (req->cb) {
        auto err = GetLastError();
        req->cb(req, uv_translate_sys_error(err));
      }

      DECREASE_PENDING_REQ_COUNT(handle);
      return;
    }
  }

  if (handle->flags & UV_HANDLE_CLOSING &&
      handle->reqs_pending == 0) {
    assert(!(handle->flags & UV_HANDLE_CLOSED));

    if (handle->flags & UV_HANDLE_CONNECTION) {
      /* Free pending sockets */
      while (!QUEUE_EMPTY(&handle->pipe.conn.ipc_xfer_queue)) {

        auto q = QUEUE_HEAD(&handle->pipe.conn.ipc_xfer_queue);
        QUEUE_REMOVE(q);
        auto *xfer_queue_item = QUEUE_DATA(q, uv__ipc_xfer_queue_item_t, member);

        /* Materialize socket and close it */
        auto socket = WSASocketW(FROM_PROTOCOL_INFO,
                            FROM_PROTOCOL_INFO,
                            FROM_PROTOCOL_INFO,
                            &xfer_queue_item->xfer_info.socket_info,
                            0,
                            WSA_FLAG_OVERLAPPED);
        uv__free(xfer_queue_item);

        if (socket != INVALID_SOCKET)
          closesocket(socket);
      }
      handle->pipe.conn.ipc_xfer_queue_length = 0;

      if (handle->flags & UV_HANDLE_EMULATE_IOCP) {
        if (handle->read_req.wait_handle != INVALID_HANDLE_VALUE) {
          UnregisterWait(handle->read_req.wait_handle);
          handle->read_req.wait_handle = INVALID_HANDLE_VALUE;
        }
        if (handle->read_req.event_handle != nullptr) {
          CloseHandle(handle->read_req.event_handle);
          handle->read_req.event_handle = nullptr;
        }
      }

      if (handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE)
        DeleteCriticalSection(&handle->pipe.conn.readfile_thread_lock);
    }

    if (handle->flags & UV_HANDLE_PIPESERVER) {
      assert(handle->pipe.serv.accept_reqs);
      uv__free(handle->pipe.serv.accept_reqs);
      handle->pipe.serv.accept_reqs = nullptr;
    }

    uv__handle_close(handle);
  }
}

void uv_pipe_pending_instances(uv_pipe_t* handle, int count) {
  if (handle->flags & UV_HANDLE_BOUND)
    return;
  handle->pipe.serv.pending_instances = count;
  handle->flags |= UV_HANDLE_PIPESERVER;
}

/* Creates a pipe server. */
int uv_pipe_bind(uv_pipe_t* handle, const char* name) {

  auto *loop = handle->loop;

  if (handle->flags & UV_HANDLE_BOUND) {
    return UV_EINVAL;
  }

  if (!name) {
    return UV_EINVAL;
  }

  if (!(handle->flags & UV_HANDLE_PIPESERVER)) {
    handle->pipe.serv.pending_instances = default_pending_pipe_instances;
  }

  handle->pipe.serv.accept_reqs = (uv_pipe_accept_t*)
    uv__malloc(sizeof(uv_pipe_accept_t) * handle->pipe.serv.pending_instances);
  if (!handle->pipe.serv.accept_reqs) {
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
  }

  for (auto i = 0; i < handle->pipe.serv.pending_instances; i++) {
    auto *req = &handle->pipe.serv.accept_reqs[i];
    UV_REQ_INIT(req, UV_ACCEPT);
    req->data = handle;
    req->pipeHandle = INVALID_HANDLE_VALUE;
    req->next_pending = nullptr;
  }

  /* Convert name to UTF16. */
  auto nameSize = MultiByteToWideChar(CP_UTF8, 0, name, -1, nullptr, 0) * sizeof(WCHAR);
  handle->name = (WCHAR*)uv__malloc(nameSize);
  if (!handle->name) {
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
  }

  if (!MultiByteToWideChar(CP_UTF8,
                           0,
                           name,
                           -1,
                           handle->name,
                           static_cast<int>(nameSize / sizeof(WCHAR)))) {
    auto err = GetLastError();
    if (handle->name) {
      uv__free(handle->name);
      handle->name = nullptr;
    } 
    return uv_translate_sys_error(err);
  }

  /*
   * Attempt to create the first pipe with FILE_FLAG_FIRST_PIPE_INSTANCE.
   * If this fails then there's already a pipe server for the given pipe name.
   */
  if (!pipe_alloc_accept(loop,
                         handle,
                         &handle->pipe.serv.accept_reqs[0],
                         1)) {
    auto err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
      err = WSAEADDRINUSE;  /* Translates to UV_EADDRINUSE. */
    } else if (err == ERROR_PATH_NOT_FOUND || err == ERROR_INVALID_NAME) {
      err = WSAEACCES;  /* Translates to UV_EACCES. */
    }
    if (handle->name) {
      uv__free(handle->name);
      handle->name = nullptr;
    }
    return uv_translate_sys_error(err);
  }

  handle->pipe.serv.pending_accepts = nullptr;
  handle->flags |= UV_HANDLE_PIPESERVER;
  handle->flags |= UV_HANDLE_BOUND;

  return 0;
}

static DWORD WINAPI pipe_connect_thread_proc(void* parameter) {

  auto *req = static_cast<uv_connect_t*>(parameter);
  assert(req);
  auto *handle = reinterpret_cast<uv_pipe_t*>(req->handle);
  assert(handle);
  auto *loop = handle->loop;
  assert(loop);

  /* We're here because CreateFile on a pipe returned ERROR_PIPE_BUSY. We wait
   * for the pipe to become available with WaitNamedPipe. */
  auto duplex_flags = DWORD{};
  auto pipeHandle = INVALID_HANDLE_VALUE;
  while (WaitNamedPipeW(handle->name, 30000)) {
    /* The pipe is now available, try to connect. */
    pipeHandle = open_named_pipe(handle->name, &duplex_flags);
    if (pipeHandle != INVALID_HANDLE_VALUE) {
      break;
    }

    SwitchToThread();
  }

  if (pipeHandle != INVALID_HANDLE_VALUE &&
      !uv_set_pipe_handle(loop, handle, pipeHandle, -1, duplex_flags)) {
    SET_REQ_SUCCESS(req);
  } else {
    SET_REQ_ERROR(req, GetLastError());
  }

  /* Post completed */
  POST_COMPLETION_FOR_REQ(loop, req);

  return 0;
}

void uv_pipe_connect_error(uv_loop_t *loop, uv_pipe_t* handle, HANDLE pipeHandle,
    uv_connect_t* req, int err){
  if (handle->name) {
    uv__free(handle->name);
    handle->name = nullptr;
  }

  if (pipeHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(pipeHandle);
  }

  /* Make this req pending reporting an error. */
  SET_REQ_ERROR(req, err);
  uv_insert_pending_req(loop, (uv_req_t*) req);
  handle->reqs_pending++;
  REGISTER_HANDLE_REQ(loop, handle, req);
  return;
}

void uv_pipe_connect(uv_connect_t* req, uv_pipe_t* handle,
    const char* name, uv_connect_cb cb) {

  auto *loop = handle->loop;
  UV_REQ_INIT(req, UV_CONNECT);
  req->handle = reinterpret_cast<uv_stream_t*>(handle);
  req->cb = cb;

  /* Convert name to UTF16. */
  auto nameSize = MultiByteToWideChar(CP_UTF8, 0, name, -1, nullptr, 0) * sizeof(WCHAR);
  handle->name = (WCHAR*)uv__malloc(nameSize);
  if (!handle->name) {
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
  }

  if (!MultiByteToWideChar(CP_UTF8,
                           0,
                           name,
                           -1,
                           handle->name,
                           static_cast<int>(nameSize / sizeof(WCHAR)))) {
    auto err = GetLastError();
    return uv_pipe_connect_error(loop, handle, INVALID_HANDLE_VALUE, req, err);
  }

  auto duplex_flags = DWORD{};
  auto pipeHandle = open_named_pipe(handle->name, &duplex_flags);
  if (pipeHandle == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_PIPE_BUSY) {
      /* Wait for the server to make a pipe instance available. */
      if (!QueueUserWorkItem(&pipe_connect_thread_proc,
                             req,
                             WT_EXECUTELONGFUNCTION)) {
        auto err = GetLastError();
        return uv_pipe_connect_error(loop, handle, pipeHandle, req, err);
      }

      REGISTER_HANDLE_REQ(loop, handle, req);
      handle->reqs_pending++;

      return;
    }

    auto err = GetLastError();
    return uv_pipe_connect_error(loop, handle, pipeHandle, req, err);
  }

  assert(pipeHandle != INVALID_HANDLE_VALUE);

  if (uv_set_pipe_handle(loop,
                         reinterpret_cast<uv_pipe_t*>(req->handle),
                         pipeHandle,
                         -1,
                         duplex_flags)) {
    auto err = GetLastError();
    return uv_pipe_connect_error(loop, handle, pipeHandle, req, err);
  }

  SET_REQ_SUCCESS(req);
  uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
  handle->reqs_pending++;
  REGISTER_HANDLE_REQ(loop, handle, req);
  return;
}

void uv__pipe_interrupt_read(uv_pipe_t* handle) {

  if (!(handle->flags & UV_HANDLE_READ_PENDING))
    return; /* No pending reads. */
  if (handle->flags & UV_HANDLE_CANCELLATION_PENDING)
    return; /* Already cancelled. */
  if (handle->handle == INVALID_HANDLE_VALUE)
    return; /* Pipe handle closed. */

  if (!(handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE)) {
    /* Cancel asynchronous read. */
    auto r = CancelIoEx(handle->handle, &handle->read_req.u.io.overlapped);
    assert(r || GetLastError() == ERROR_NOT_FOUND);

  } else {
    /* Cancel synchronous read (which is happening in the thread pool). */
    auto* thread_ptr = &handle->pipe.conn.readfile_thread_handle;

    EnterCriticalSection(&handle->pipe.conn.readfile_thread_lock);

    auto thread = *thread_ptr;
    if (thread == nullptr) {
      /* The thread pool thread has not yet reached the point of blocking, we
       * can pre-empt it by setting thread_handle to INVALID_HANDLE_VALUE. */
      *thread_ptr = INVALID_HANDLE_VALUE;

    } else {
      /* Spin until the thread has acknowledged (by setting the thread to
       * INVALID_HANDLE_VALUE) that it is past the point of blocking. */
      while (thread != INVALID_HANDLE_VALUE) {
        auto r = CancelSynchronousIo(thread);
        assert(r || GetLastError() == ERROR_NOT_FOUND);
        SwitchToThread(); /* Yield thread. */
        thread = *thread_ptr;
      }
    }

    LeaveCriticalSection(&handle->pipe.conn.readfile_thread_lock);
  }

  /* Set flag to indicate that read has been cancelled. */
  handle->flags |= UV_HANDLE_CANCELLATION_PENDING;
}

void uv__pipe_read_stop(uv_pipe_t* handle) {
  handle->flags &= ~UV_HANDLE_READING;
  DECREASE_ACTIVE_COUNT(handle->loop, handle);

  uv__pipe_interrupt_read(handle);
}

/* Cleans up uv_pipe_t (server or connection) and all resources associated with
 * it. */
void uv_pipe_cleanup(uv_loop_t* loop, uv_pipe_t* handle) {
  (void)loop;
  uv__pipe_interrupt_read(handle);

  if (handle->name) {
    uv__free(handle->name);
    handle->name = nullptr;
  }

  if (handle->flags & UV_HANDLE_PIPESERVER) {
    for (auto i = 0; i < handle->pipe.serv.pending_instances; i++) {
      auto pipeHandle = handle->pipe.serv.accept_reqs[i].pipeHandle;
      if (pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(pipeHandle);
        handle->pipe.serv.accept_reqs[i].pipeHandle = INVALID_HANDLE_VALUE;
      }
    }
    handle->handle = INVALID_HANDLE_VALUE;
  }

  if (handle->flags & UV_HANDLE_CONNECTION) {
    handle->flags &= ~UV_HANDLE_WRITABLE;
    eof_timer_destroy(handle);
  }

  if ((handle->flags & UV_HANDLE_CONNECTION)
      && handle->handle != INVALID_HANDLE_VALUE)
    close_pipe(handle);
}

void uv_pipe_close(uv_loop_t* loop, uv_pipe_t* handle) {
  if (handle->flags & UV_HANDLE_READING) {
    handle->flags &= ~UV_HANDLE_READING;
    DECREASE_ACTIVE_COUNT(loop, handle);
  }

  if (handle->flags & UV_HANDLE_LISTENING) {
    handle->flags &= ~UV_HANDLE_LISTENING;
    DECREASE_ACTIVE_COUNT(loop, handle);
  }

  uv_pipe_cleanup(loop, handle);

  if (handle->reqs_pending == 0) {
    uv_want_endgame(loop, reinterpret_cast<uv_handle_t*>(handle));
  }

  handle->flags &= ~(UV_HANDLE_READABLE | UV_HANDLE_WRITABLE);
  uv__handle_closing(handle);
}

static void uv_pipe_queue_accept(uv_loop_t* loop, uv_pipe_t* handle,
    uv_pipe_accept_t* req, BOOL firstInstance) {
  assert(handle->flags & UV_HANDLE_LISTENING);

  if (!firstInstance && !pipe_alloc_accept(loop, handle, req, FALSE)) {
    SET_REQ_ERROR(req, GetLastError());
    uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
    handle->reqs_pending++;
    return;
  }

  assert(req->pipeHandle != INVALID_HANDLE_VALUE);

  /* Prepare the overlapped structure. */
  memset(&(req->u.io.overlapped), 0, sizeof(decltype(req->u.io.overlapped)));

  if (!ConnectNamedPipe(req->pipeHandle, &req->u.io.overlapped) &&
      GetLastError() != ERROR_IO_PENDING) {
    if (GetLastError() == ERROR_PIPE_CONNECTED) {
      SET_REQ_SUCCESS(req);
    } else {
      CloseHandle(req->pipeHandle);
      req->pipeHandle = INVALID_HANDLE_VALUE;
      /* Make this req pending reporting an error. */
      SET_REQ_ERROR(req, GetLastError());
    }
    uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
    handle->reqs_pending++;
    return;
  }

  /* Wait for completion via IOCP */
  handle->reqs_pending++;
}

int uv_pipe_accept(uv_pipe_t* server, uv_stream_t* client) {

  if (server->ipc) {
    if (QUEUE_EMPTY(&server->pipe.conn.ipc_xfer_queue)) {
      /* No valid pending sockets. */
      return WSAEWOULDBLOCK;
    }

    auto q = QUEUE_HEAD(&server->pipe.conn.ipc_xfer_queue);
    QUEUE_REMOVE(q);
    server->pipe.conn.ipc_xfer_queue_length--;
    auto item = QUEUE_DATA(q, uv__ipc_xfer_queue_item_t, member);

    auto err = uv__tcp_xfer_import(
        reinterpret_cast<uv_tcp_t*>(client), item->xfer_type, &item->xfer_info);
    if (err != 0)
      return err;

    uv__free(item);

  } else {
    auto pipe_client = reinterpret_cast<uv_pipe_t*>(client);

    /* Find a connection instance that has been connected, but not yet
     * accepted. */
    auto req = server->pipe.serv.pending_accepts;

    if (!req) {
      /* No valid connections found, so we error out. */
      return WSAEWOULDBLOCK;
    }

    /* Initialize the client handle and copy the pipeHandle to the client */
    uv_pipe_connection_init(pipe_client);
    pipe_client->handle = req->pipeHandle;
    pipe_client->flags |= UV_HANDLE_READABLE | UV_HANDLE_WRITABLE;

    /* Prepare the req to pick up a new connection */
    server->pipe.serv.pending_accepts = req->next_pending;
    req->next_pending = nullptr;
    req->pipeHandle = INVALID_HANDLE_VALUE;

    server->handle = INVALID_HANDLE_VALUE;
    if (!(server->flags & UV_HANDLE_CLOSING)) {
      auto *loop = server->loop;
      uv_pipe_queue_accept(loop, server, req, 0);
    }
  }

  return 0;
}

/* Starts listening for connections for the given pipe. */
int uv_pipe_listen(uv_pipe_t* handle, int backlog, uv_connection_cb cb) {
  (void)backlog;
  if (handle->flags & UV_HANDLE_LISTENING) {
    handle->stream.serv.connection_cb = cb;
  }

  if (!(handle->flags & UV_HANDLE_BOUND)) {
    return WSAEINVAL;
  }

  if (handle->flags & UV_HANDLE_READING) {
    return WSAEISCONN;
  }

  if (!(handle->flags & UV_HANDLE_PIPESERVER)) {
    return ERROR_NOT_SUPPORTED;
  }

  if (handle->ipc) {
    return WSAEINVAL;
  }

  handle->flags |= UV_HANDLE_LISTENING;
  auto *loop = handle->loop;
  INCREASE_ACTIVE_COUNT(loop, handle);
  handle->stream.serv.connection_cb = cb;

  /* First pipe handle should have already been created in uv_pipe_bind */
  assert(handle->pipe.serv.accept_reqs[0].pipeHandle != INVALID_HANDLE_VALUE);

  for (auto i = 0; i < handle->pipe.serv.pending_instances; i++) {
    uv_pipe_queue_accept(loop, handle, &handle->pipe.serv.accept_reqs[i], i == 0);
  }

  return 0;
}

static DWORD WINAPI uv_pipe_zero_readfile_thread_proc(void* arg) {

  auto *req = static_cast<uv_read_t*>(arg);
  auto *handle = static_cast<uv_pipe_t*>(req->data);
  assert(req->type == UV_READ);
  assert(handle->type == UV_NAMED_PIPE);


  /* Create a handle to the current thread. */
  auto thread = HANDLE{};
  if (!DuplicateHandle(GetCurrentProcess(),
                       GetCurrentThread(),
                       GetCurrentProcess(),
                       &thread,
                       0,
                       FALSE,
                       DUPLICATE_SAME_ACCESS)) {
    auto err = GetLastError();
    if (err)
      SET_REQ_ERROR(req, err);
    else
      SET_REQ_SUCCESS(req);

    auto *loop = handle->loop;
    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
  }

  /* The lock needs to be held when thread handle is modified. */
  auto err = 0;
  auto *lock = &handle->pipe.conn.readfile_thread_lock;
  auto *thread_ptr = &handle->pipe.conn.readfile_thread_handle;
  EnterCriticalSection(lock);
  if (*thread_ptr == INVALID_HANDLE_VALUE) {
    /* uv__pipe_interrupt_read() cancelled reading before we got here. */
    err = ERROR_OPERATION_ABORTED;
  } else {
    /* Let main thread know which worker thread is doing the blocking read. */
    assert(*thread_ptr == nullptr);
    *thread_ptr = thread;
  }
  LeaveCriticalSection(lock);

  if (err){
    CloseHandle(thread);
    if (err)
      SET_REQ_ERROR(req, err);
    else
      SET_REQ_SUCCESS(req);

    auto *loop = handle->loop;
    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
  }

  /* Block the thread until data is available on the pipe, or the read is
   * cancelled. */
  auto bytes = DWORD{};
  if (!ReadFile(handle->handle, &uv_zero_, 0, &bytes, nullptr))
    err = GetLastError();

  /* Let the main thread know the worker is past the point of blocking. */
  assert(thread == *thread_ptr);
  *thread_ptr = INVALID_HANDLE_VALUE;

  /* Briefly acquire the mutex. Since the main thread holds the lock while it
   * is spinning trying to cancel this thread's I/O, we will block here until
   * it stops doing that. */
  EnterCriticalSection(lock);
  LeaveCriticalSection(lock);

  /* Close the handle to the current thread. */
  CloseHandle(thread);

  /* Set request status and post a completion record to the IOCP. */
  if (err)
    SET_REQ_ERROR(req, err);
  else
    SET_REQ_SUCCESS(req);

  auto *loop = handle->loop;
  POST_COMPLETION_FOR_REQ(loop, req);

  return 0;
}

static DWORD WINAPI uv_pipe_writefile_thread_proc(void* parameter) {
  auto *req = static_cast<uv_write_t*>(parameter);
  auto *handle = reinterpret_cast<uv_pipe_t*>(req->handle);

  assert(req != nullptr);
  assert(req->type == UV_WRITE);
  assert(handle->type == UV_NAMED_PIPE);
  assert(req->write_buffer.base);

  auto bytes = DWORD{};
  auto result = WriteFile(handle->handle,
                     req->write_buffer.base,
                     req->write_buffer.len,
                     &bytes,
                     nullptr);

  if (!result) {
    SET_REQ_ERROR(req, GetLastError());
  }

  auto *loop = handle->loop;
  POST_COMPLETION_FOR_REQ(loop, req);
  return 0;
}

static void CALLBACK post_completion_read_wait(void* context, BOOLEAN timed_out) {

  auto *req = static_cast<uv_read_t*>(context);
  assert(req != nullptr);
  auto *handle = static_cast<uv_tcp_t*>(req->data);
  assert(handle != nullptr);
  assert(!timed_out);

  if (!PostQueuedCompletionStatus(handle->loop->iocp,
                                  static_cast<DWORD>(req->u.io.overlapped.InternalHigh),
                                  0,
                                  &req->u.io.overlapped)) {
    uv_fatal_error(GetLastError(), "PostQueuedCompletionStatus");
  }
}

static void CALLBACK post_completion_write_wait(void* context, BOOLEAN timed_out) {

  auto *req = static_cast<uv_write_t*>(context);
  assert(req != nullptr);
  auto *handle = reinterpret_cast<uv_tcp_t*>(req->handle);
  assert(handle != nullptr);
  assert(!timed_out);

  if (!PostQueuedCompletionStatus(handle->loop->iocp,
                                  static_cast<DWORD>(req->u.io.overlapped.InternalHigh),
                                  0,
                                  &req->u.io.overlapped)) {
    uv_fatal_error(GetLastError(), "PostQueuedCompletionStatus");
  }
}

static void uv_pipe_queue_read(uv_loop_t* loop, uv_pipe_t* handle) {

  assert(handle->flags & UV_HANDLE_READING);
  assert(!(handle->flags & UV_HANDLE_READ_PENDING));

  assert(handle->handle != INVALID_HANDLE_VALUE);

  auto *req = &handle->read_req;

  if (handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE) {
    handle->pipe.conn.readfile_thread_handle = nullptr; /* Reset cancellation. */
    if (!QueueUserWorkItem(&uv_pipe_zero_readfile_thread_proc,
                           req,
                           WT_EXECUTELONGFUNCTION)) {
      /* Make this req pending reporting an error. */
      SET_REQ_ERROR(req, GetLastError());
      uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
      handle->flags |= UV_HANDLE_READ_PENDING;
      handle->reqs_pending++;
      return;
    }
  } else {
    memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));
    if (handle->flags & UV_HANDLE_EMULATE_IOCP) {
      assert(req->event_handle != nullptr);
      req->u.io.overlapped.hEvent = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(req->event_handle) | 1);
    }

    /* Do 0-read */
    auto result = ReadFile(handle->handle,
                      &uv_zero_,
                      0,
                      nullptr,
                      &req->u.io.overlapped);

    if (!result && GetLastError() != ERROR_IO_PENDING) {
      /* Make this req pending reporting an error. */
      SET_REQ_ERROR(req, GetLastError());
      uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
      handle->flags |= UV_HANDLE_READ_PENDING;
      handle->reqs_pending++;
      return;
    }

    if (handle->flags & UV_HANDLE_EMULATE_IOCP) {
      if (req->wait_handle == INVALID_HANDLE_VALUE) {
        if (!RegisterWaitForSingleObject(&req->wait_handle,
            req->event_handle, post_completion_read_wait, static_cast<void*>(req),
            INFINITE, WT_EXECUTEINWAITTHREAD)) {
          SET_REQ_ERROR(req, GetLastError());
            uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
            handle->flags |= UV_HANDLE_READ_PENDING;
            handle->reqs_pending++;
            return;
        }
      }
    }
  }

  /* Start the eof timer if there is one */
  eof_timer_start(handle);
  handle->flags |= UV_HANDLE_READ_PENDING;
  handle->reqs_pending++;
  return;
}

int uv_pipe_read_start(uv_pipe_t* handle,
                       uv_alloc_cb alloc_cb,
                       uv_read_cb read_cb) {

  auto *loop = handle->loop;
  handle->flags |= UV_HANDLE_READING;
  INCREASE_ACTIVE_COUNT(loop, handle);
  handle->read_cb = read_cb;
  handle->alloc_cb = alloc_cb;

  /* If reading was stopped and then started again, there could still be a read
   * request pending. */
  if (!(handle->flags & UV_HANDLE_READ_PENDING)) {
    if (handle->flags & UV_HANDLE_EMULATE_IOCP &&
        handle->read_req.event_handle == nullptr) {
      handle->read_req.event_handle = CreateEvent(nullptr, 0, 0, nullptr);
      if (handle->read_req.event_handle == nullptr) {
        uv_fatal_error(GetLastError(), "CreateEvent");
      }
    }
    uv_pipe_queue_read(loop, handle);
  }

  return 0;
}

static void uv_insert_non_overlapped_write_req(uv_pipe_t* handle,
    uv_write_t* req) {
  req->next_req = nullptr;
  if (handle->pipe.conn.non_overlapped_writes_tail) {
    req->next_req =
      handle->pipe.conn.non_overlapped_writes_tail->next_req;
    handle->pipe.conn.non_overlapped_writes_tail->next_req = reinterpret_cast<uv_req_t*>(req);
    handle->pipe.conn.non_overlapped_writes_tail = req;
  } else {
    req->next_req = reinterpret_cast<uv_req_t*>(req);
    handle->pipe.conn.non_overlapped_writes_tail = req;
  }
}

static uv_write_t* uv_remove_non_overlapped_write_req(uv_pipe_t* handle) {

  if (handle->pipe.conn.non_overlapped_writes_tail) {
    auto *req = reinterpret_cast<uv_write_t*>(handle->pipe.conn.non_overlapped_writes_tail->next_req);

    if (req == handle->pipe.conn.non_overlapped_writes_tail) {
      handle->pipe.conn.non_overlapped_writes_tail = nullptr;
    } else {
      handle->pipe.conn.non_overlapped_writes_tail->next_req =
        req->next_req;
    }

    return req;
  } else {
    /* queue empty */
    return nullptr;
  }
}

static void uv_queue_non_overlapped_write(uv_pipe_t* handle) {
  auto *req = uv_remove_non_overlapped_write_req(handle);
  if (req) {
    if (!QueueUserWorkItem(&uv_pipe_writefile_thread_proc,
                           req,
                           WT_EXECUTELONGFUNCTION)) {
      uv_fatal_error(GetLastError(), "QueueUserWorkItem");
    }
  }
}

static int uv__build_coalesced_write_req(uv_write_t* user_req,
                                         const uv_buf_t bufs[],
                                         size_t nbufs,
                                         uv_write_t** req_out,
                                         uv_buf_t* write_buf_out) {
  /* Pack into a single heap-allocated buffer:
   *   (a) a uv_write_t structure where libuv stores the actual state.
   *   (b) a pointer to the original uv_write_t.
   *   (c) data from all `bufs` entries.
   */

  /* Compute combined size of all combined buffers from `bufs`. */
  auto data_length = 0ull;
  for (auto i = 0u; i < nbufs; i++)
    data_length += bufs[i].len;

  /* The total combined size of data buffers should not exceed UINT32_MAX,
   * because WriteFile() won't accept buffers larger than that. */
  if (data_length > UINT32_MAX)
    return WSAENOBUFS; /* Maps to UV_ENOBUFS. */

  /* Compute heap buffer size. */
  uv__coalesced_write_t* coalesced_write_req; /* (a) + (b) */
  auto heap_buffer_length = sizeof(decltype(*coalesced_write_req)) + /* (a) + (b) */
                       data_length;                  /* (c) */

  /* Allocate buffer. */
  auto heap_buffer = create_ptrstruct<char>(heap_buffer_length);
  if (heap_buffer == nullptr)
    return ERROR_NOT_ENOUGH_MEMORY; /* Maps to UV_ENOMEM. */

  /* Copy uv_write_t information to the buffer. */
  coalesced_write_req = (uv__coalesced_write_t*) heap_buffer;
  coalesced_write_req->req = *user_req; /* copy (a) */
  coalesced_write_req->req.coalesced = 1;
  coalesced_write_req->user_req = user_req;         /* copy (b) */
  auto heap_buffer_offset = sizeof(decltype(*coalesced_write_req)); /* offset (a) + (b) */

  /* Copy data buffers to the heap buffer. */
  auto *data_start = &heap_buffer[heap_buffer_offset];
  for (auto i = 0u; i < nbufs; i++) {
    memcpy(&heap_buffer[heap_buffer_offset],
           bufs[i].base,
           bufs[i].len);               /* copy (c) */
    heap_buffer_offset += bufs[i].len; /* offset (c) */
  }
  assert(heap_buffer_offset == heap_buffer_length);

  /* Set out arguments and return. */
  *req_out = &coalesced_write_req->req;
  *write_buf_out = uv_buf_init(data_start, static_cast<unsigned int>(data_length));
  return 0;
}

static int uv__pipe_write_data(uv_loop_t* loop,
                               uv_write_t* req,
                               uv_pipe_t* handle,
                               const uv_buf_t bufs[],
                               size_t nbufs,
                               uv_write_cb cb,
                               int copy_always) {

  assert(handle->handle != INVALID_HANDLE_VALUE);

  UV_REQ_INIT(req, UV_WRITE);
  req->handle = reinterpret_cast<uv_stream_t*>(handle);
  req->send_handle = nullptr;
  req->cb = cb;
  /* Private fields. */
  req->coalesced = 0;
  req->event_handle = nullptr;
  req->wait_handle = INVALID_HANDLE_VALUE;

  /* Prepare the overlapped structure. */
  memset(&req->u.io.overlapped, 0, sizeof(decltype(req->u.io.overlapped)));
  if (handle->flags & (UV_HANDLE_EMULATE_IOCP | UV_HANDLE_BLOCKING_WRITES)) {
    req->event_handle = CreateEvent(nullptr, 0, 0, nullptr);
    if (req->event_handle == nullptr) {
      uv_fatal_error(GetLastError(), "CreateEvent");
    }
    req->u.io.overlapped.hEvent = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(req->event_handle) | 1);
  }
  req->write_buffer = uv_null_buf_;

  auto write_buf = uv_buf_t{};
  if (nbufs == 0) {
    /* Write empty buffer. */
    write_buf = uv_null_buf_;
  } else if (nbufs == 1 && !copy_always) {
    /* Write directly from bufs[0]. */
    write_buf = bufs[0];
  } else {
    /* Coalesce all `bufs` into one big buffer. This also creates a new
     * write-request structure that replaces the old one. */
    auto err = uv__build_coalesced_write_req(req, bufs, nbufs, &req, &write_buf);
    if (err != 0)
      return err;
  }

  if ((handle->flags &
      (UV_HANDLE_BLOCKING_WRITES | UV_HANDLE_NON_OVERLAPPED_PIPE)) ==
      (UV_HANDLE_BLOCKING_WRITES | UV_HANDLE_NON_OVERLAPPED_PIPE)) {
    auto bytes = DWORD{};
    auto result =
        WriteFile(handle->handle, write_buf.base, write_buf.len, &bytes, nullptr);

    if (!result) {
      auto err = GetLastError();
      return err;
    } else {
      /* Request completed immediately. */
      req->u.io.queued_bytes = 0;
    }

    REGISTER_HANDLE_REQ(loop, handle, req);
    handle->reqs_pending++;
    handle->stream.conn.write_reqs_pending++;
    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
  } else if (handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE) {
    req->write_buffer = write_buf;
    uv_insert_non_overlapped_write_req(handle, req);
    if (handle->stream.conn.write_reqs_pending == 0) {
      uv_queue_non_overlapped_write(handle);
    }

    /* Request queued by the kernel. */
    req->u.io.queued_bytes = write_buf.len;
    handle->write_queue_size += req->u.io.queued_bytes;
  } else if (handle->flags & UV_HANDLE_BLOCKING_WRITES) {
    /* Using overlapped IO, but wait for completion before returning */
    auto result = WriteFile(handle->handle,
                       write_buf.base,
                       write_buf.len,
                       nullptr,
                       &req->u.io.overlapped);

    if (!result && GetLastError() != ERROR_IO_PENDING) {
      auto err = GetLastError();
      CloseHandle(req->event_handle);
      req->event_handle = nullptr;
      return err;
    }

    if (result) {
      /* Request completed immediately. */
      req->u.io.queued_bytes = 0;
    } else {
      /* Request queued by the kernel. */
      req->u.io.queued_bytes = write_buf.len;
      handle->write_queue_size += req->u.io.queued_bytes;
      if (WaitForSingleObject(req->event_handle, INFINITE) !=
          WAIT_OBJECT_0) {
        auto err = GetLastError();
        CloseHandle(req->event_handle);
        req->event_handle = nullptr;
        return err;
      }
    }
    CloseHandle(req->event_handle);
    req->event_handle = nullptr;

    REGISTER_HANDLE_REQ(loop, handle, req);
    handle->reqs_pending++;
    handle->stream.conn.write_reqs_pending++;
    return 0;
  } else {
    auto result = WriteFile(handle->handle,
                       write_buf.base,
                       write_buf.len,
                       nullptr,
                       &req->u.io.overlapped);

    if (!result && GetLastError() != ERROR_IO_PENDING) {
      return GetLastError();
    }

    if (result) {
      /* Request completed immediately. */
      req->u.io.queued_bytes = 0;
    } else {
      /* Request queued by the kernel. */
      req->u.io.queued_bytes = write_buf.len;
      handle->write_queue_size += req->u.io.queued_bytes;
    }

    if (handle->flags & UV_HANDLE_EMULATE_IOCP) {
      if (!RegisterWaitForSingleObject(&req->wait_handle,
          req->event_handle, post_completion_write_wait, static_cast<void*>(req),
          INFINITE, WT_EXECUTEINWAITTHREAD)) {
        return GetLastError();
      }
    }
  }

  REGISTER_HANDLE_REQ(loop, handle, req);
  handle->reqs_pending++;
  handle->stream.conn.write_reqs_pending++;

  return 0;
}

static auto uv__pipe_get_ipc_remote_pid(uv_pipe_t* handle) {
  auto *pid = &handle->pipe.conn.ipc_remote_pid;

  /* If the both ends of the IPC pipe are owned by the same process,
   * the remote end pid may not yet be set. If so, do it here.
   * TODO: this is weird; it'd probably better to use a handshake. */
  if (*pid == 0)
    *pid = GetCurrentProcessId();

  return *pid;
}

int uv__pipe_write_ipc(uv_loop_t* loop,
                       uv_write_t* req,
                       uv_pipe_t* handle,
                       const uv_buf_t data_bufs[],
                       size_t data_buf_count,
                       uv_stream_t* send_handle,
                       uv_write_cb cb) {

  /* Compute the combined size of data buffers. */
  auto data_length = 0ull;
  for (auto i = 0ull; i < data_buf_count; i++)
    data_length += data_bufs[i].len;
  if (data_length > UINT32_MAX)
    return WSAENOBUFS; /* Maps to UV_ENOBUFS. */

  /* Prepare the frame's socket xfer payload. */
  auto xfer_type = UV__IPC_SOCKET_XFER_NONE;
  auto xfer_info = uv__ipc_socket_xfer_info_t{};

  if (send_handle != nullptr) {
    uv_tcp_t* send_tcp_handle = (uv_tcp_t*) send_handle;

    /* Verify that `send_handle` it is indeed a tcp handle. */
    if (send_tcp_handle->type != UV_TCP)
      return ERROR_NOT_SUPPORTED;

    /* Export the tcp handle. */
    auto err = uv__tcp_xfer_export(send_tcp_handle,
                              uv__pipe_get_ipc_remote_pid(handle),
                              &xfer_type,
                              &xfer_info);
    if (err != 0)
      return err;
  }

  /* Compute the number of uv_buf_t's required. */
  auto buf_count = 1ull + data_buf_count; /* Frame header and data buffers. */
  if (send_handle != nullptr)
    buf_count += 1; /* One extra for the socket xfer information. */

  /* Use the on-stack buffer array if it is big enough; otherwise allocate
   * space for it on the heap. */
  uv_buf_t* bufs;
  uv_buf_t stack_bufs[6];
  if (buf_count < ARRAY_SIZE(stack_bufs)) {
    /* Use on-stack buffer array. */
    bufs = stack_bufs;
  } else {
    /* Use heap-allocated buffer array. */
    bufs = create_ptrstruct<uv_buf_t>(buf_count, sizeof(uv_buf_t));
    if (bufs == nullptr)
      return ERROR_NOT_ENOUGH_MEMORY; /* Maps to UV_ENOMEM. */
  }
  auto buf_index = 0ull;

  /* Initialize frame header and add it to the buffers list. */
  auto frame_header = uv__ipc_frame_header_t{};
  memset(&frame_header, 0, sizeof(decltype(frame_header)));
  bufs[buf_index++] = uv_buf_init((char*) &frame_header, sizeof(decltype(frame_header)));

  if (send_handle != nullptr) {
    /* Add frame header flags. */
    switch (xfer_type) {
      case UV__IPC_SOCKET_XFER_TCP_CONNECTION:
        frame_header.flags |= UV__IPC_FRAME_HAS_SOCKET_XFER |
                              UV__IPC_FRAME_XFER_IS_TCP_CONNECTION;
        break;
      case UV__IPC_SOCKET_XFER_TCP_SERVER:
        frame_header.flags |= UV__IPC_FRAME_HAS_SOCKET_XFER;
        break;
      default:
        assert(0);  /* Unreachable. */
    }
    /* Add xfer info buffer. */
    bufs[buf_index++] = uv_buf_init((char*) &xfer_info, sizeof xfer_info);
  }

  if (data_length > 0) {
    /* Update frame header. */
    frame_header.flags |= UV__IPC_FRAME_HAS_DATA;
    frame_header.data_length = (uint32_t) data_length;
    /* Add data buffers to buffers list. */
    for (auto i = 0ull; i < data_buf_count; i++)
      bufs[buf_index++] = data_bufs[i];
  }

  /* Write buffers. We set the `always_copy` flag, so it is not a problem that
   * some of the written data lives on the stack. */
  auto err = uv__pipe_write_data(loop, req, handle, bufs, buf_count, cb, 1);

  /* If we had to heap-allocate the bufs array, free it now. */
  if (bufs != stack_bufs) {
    uv__free(bufs);
  }

  return err;
}

int uv__pipe_write(uv_loop_t* loop,
                   uv_write_t* req,
                   uv_pipe_t* handle,
                   const uv_buf_t bufs[],
                   size_t nbufs,
                   uv_stream_t* send_handle,
                   uv_write_cb cb) {
  if (handle->ipc) {
    /* IPC pipe write: use framing protocol. */
    return uv__pipe_write_ipc(loop, req, handle, bufs, nbufs, send_handle, cb);
  } else {
    /* Non-IPC pipe write: put data on the wire directly. */
    assert(send_handle == nullptr);
    return uv__pipe_write_data(loop, req, handle, bufs, nbufs, cb, 0);
  }
}

static void uv_pipe_read_eof(uv_loop_t* loop, uv_pipe_t* handle,
    uv_buf_t buf) {
  (void)loop;
  /* If there is an eof timer running, we don't need it any more, so discard
   * it. */
  eof_timer_destroy(handle);

  handle->flags &= ~UV_HANDLE_READABLE;
  uv_read_stop(reinterpret_cast<uv_stream_t*>(handle));

  handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), UV_EOF, &buf);
}

static void uv_pipe_read_error(uv_loop_t* loop, uv_pipe_t* handle, int error,
    uv_buf_t buf) {
  (void)loop;
  /* If there is an eof timer running, we don't need it any more, so discard
   * it. */
  eof_timer_destroy(handle);

  uv_read_stop(reinterpret_cast<uv_stream_t*>(handle));

  handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), uv_translate_sys_error(error), &buf);
}

static void uv_pipe_read_error_or_eof(uv_loop_t* loop, uv_pipe_t* handle,
    int error, uv_buf_t buf) {
  if (error == ERROR_BROKEN_PIPE) {
    uv_pipe_read_eof(loop, handle, buf);
  } else {
    uv_pipe_read_error(loop, handle, error, buf);
  }
}

static void uv__pipe_queue_ipc_xfer_info(
    uv_pipe_t* handle,
    uv__ipc_socket_xfer_type_t xfer_type,
    uv__ipc_socket_xfer_info_t* xfer_info) {

  auto *item = create_ptrstruct<uv__ipc_xfer_queue_item_t>(sizeof(uv__ipc_xfer_queue_item_t));
  if (item == nullptr)
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");

  item->xfer_type = xfer_type;
  item->xfer_info = *xfer_info;

  QUEUE_INSERT_TAIL(&handle->pipe.conn.ipc_xfer_queue, &item->member);
  handle->pipe.conn.ipc_xfer_queue_length++;
}

/* Read an exact number of bytes from a pipe. If an error or end-of-file is
 * encountered before the requested number of bytes are read, an error is
 * returned. */
static int uv__pipe_read_exactly(HANDLE h, void* buffer, DWORD count) {

  auto bytes_read = DWORD{0};
  auto bytes_read_now = DWORD{};
  while (bytes_read < count) {
    if (!ReadFile(h,
                  static_cast<char*>(buffer) + bytes_read,
                  count - bytes_read,
                  &bytes_read_now,
                  nullptr)) {
      return GetLastError();
    }

    bytes_read += bytes_read_now;
  }

  assert(bytes_read == count);
  return 0;
}

static DWORD uv__pipe_read_data(uv_loop_t* loop,
                                uv_pipe_t* handle,
                                DWORD suggested_bytes,
                                DWORD max_bytes) {

  /* Ask the user for a buffer to read data into. */
  auto buf = uv_buf_init(nullptr, 0);
  handle->alloc_cb(reinterpret_cast<uv_handle_t*>(handle), suggested_bytes, &buf);
  if (buf.base == nullptr || buf.len == 0) {
    handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), UV_ENOBUFS, &buf);
    return 0; /* Break out of read loop. */
  }

  /* Ensure we read at most the smaller of:
   *   (a) the length of the user-allocated buffer.
   *   (b) the maximum data length as specified by the `max_bytes` argument.
   */
  if (max_bytes > buf.len)
    max_bytes = buf.len;

  /* Read into the user buffer. */
  auto bytes_read = DWORD{};
  if (!ReadFile(handle->handle, buf.base, max_bytes, &bytes_read, nullptr)) {
    uv_pipe_read_error_or_eof(loop, handle, GetLastError(), buf);
    return 0; /* Break out of read loop. */
  }

  /* Call the read callback. */
  handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), bytes_read, &buf);

  return bytes_read;
}

static DWORD uv__pipe_read_ipc(uv_loop_t* loop, uv_pipe_t* handle) {
  auto *data_remaining = &handle->pipe.conn.ipc_data_frame.payload_remaining;

  if (*data_remaining > 0) {
    /* Read frame data payload. */
    auto bytes_read =
        uv__pipe_read_data(loop, handle, *data_remaining, *data_remaining);
    *data_remaining -= bytes_read;
    return bytes_read;

  } else {
    /* Start of a new IPC frame. */

    /* Read the IPC frame header. */
    auto frame_header = uv__ipc_frame_header_t{};
    auto err = uv__pipe_read_exactly(
        handle->handle, &frame_header, sizeof frame_header);
    if (err){
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }

    /* Validate that flags are valid. */
    if ((frame_header.flags & ~UV__IPC_FRAME_VALID_FLAGS) != 0){
      /* Invalid frame. */
      err = WSAECONNABORTED; /* Maps to UV_ECONNABORTED. */
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }
    /* Validate that reserved2 is zero. */
    if (frame_header.reserved2 != 0){
      /* Invalid frame. */
      err = WSAECONNABORTED; /* Maps to UV_ECONNABORTED. */
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }

    /* Parse xfer flags. */
    auto xfer_flags = frame_header.flags & UV__IPC_FRAME_XFER_FLAGS;
    auto xfer_type = uv__ipc_socket_xfer_type_t{};
    auto xfer_info = uv__ipc_socket_xfer_info_t{};
    if (xfer_flags & UV__IPC_FRAME_HAS_SOCKET_XFER) {
      /* Socket coming -- determine the type. */
      xfer_type = xfer_flags & UV__IPC_FRAME_XFER_IS_TCP_CONNECTION
                      ? UV__IPC_SOCKET_XFER_TCP_CONNECTION
                      : UV__IPC_SOCKET_XFER_TCP_SERVER;
    } else if (xfer_flags == 0) {
      /* No socket. */
      xfer_type = UV__IPC_SOCKET_XFER_NONE;
    } else {
      /* Invalid flags. */
      /* Invalid frame. */
      err = WSAECONNABORTED; /* Maps to UV_ECONNABORTED. */
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }

    /* Parse data frame information. */
    if (frame_header.flags & UV__IPC_FRAME_HAS_DATA) {
      *data_remaining = frame_header.data_length;
    } else if (frame_header.data_length != 0) {
      /* Data length greater than zero but data flag not set -- invalid. */
      /* Invalid frame. */
      err = WSAECONNABORTED; /* Maps to UV_ECONNABORTED. */
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }

    /* If no socket xfer info follows, return here. Data will be read in a
     * subsequent invocation of uv__pipe_read_ipc(). */
    if (xfer_type == UV__IPC_SOCKET_XFER_NONE)
      return sizeof(decltype(frame_header)); /* Number of bytes read. */

    /* Read transferred socket information. */
    err = uv__pipe_read_exactly(handle->handle, &xfer_info, sizeof(decltype(xfer_info)));
    if (err){
      /* Invalid frame. */
      err = WSAECONNABORTED; /* Maps to UV_ECONNABORTED. */
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);
      return 0; /* Break out of read loop. */
    }

    /* Store the pending socket info. */
    uv__pipe_queue_ipc_xfer_info(handle, xfer_type, &xfer_info);

    /* Return number of bytes read. */
    return sizeof(decltype(frame_header)) + sizeof(decltype(xfer_info));
  }
}

void uv_process_pipe_read_req(uv_loop_t* loop,
                              uv_pipe_t* handle,
                              uv_req_t* req) {
  assert(handle->type == UV_NAMED_PIPE);

  handle->flags &= ~(UV_HANDLE_READ_PENDING | UV_HANDLE_CANCELLATION_PENDING);
  DECREASE_PENDING_REQ_COUNT(handle);
  eof_timer_stop(handle);

  /* At this point, we're done with bookkeeping. If the user has stopped
   * reading the pipe in the meantime, there is nothing left to do, since there
   * is no callback that we can call. */
  if (!(handle->flags & UV_HANDLE_READING))
    return;

  if (!REQ_SUCCESS(req)) {
    /* An error occurred doing the zero-read. */
    auto err = GET_REQ_ERROR(req);

    /* If the read was cancelled by uv__pipe_interrupt_read(), the request may
     * indicate an ERROR_OPERATION_ABORTED error. This error isn't relevant to
     * the user; we'll start a new zero-read at the end of this function. */
    if (err != ERROR_OPERATION_ABORTED)
      uv_pipe_read_error_or_eof(loop, handle, err, uv_null_buf_);

  } else {
    /* The zero-read completed without error, indicating there is data
     * available in the kernel buffer. */

    /* Get the number of bytes available. */
    auto avail = DWORD{0};
    if (!PeekNamedPipe(handle->handle, nullptr, 0, nullptr, &avail, nullptr))
      uv_pipe_read_error_or_eof(loop, handle, GetLastError(), uv_null_buf_);

    /* Read until we've either read all the bytes available, or the 'reading'
     * flag is cleared. */
    while (avail > 0 && handle->flags & UV_HANDLE_READING) {
      /* Depending on the type of pipe, read either IPC frames or raw data. */
      auto bytes_read =
          handle->ipc ? uv__pipe_read_ipc(loop, handle)
                      : uv__pipe_read_data(loop, handle, avail, (DWORD) -1);

      /* If no bytes were read, treat this as an indication that an error
       * occurred, and break out of the read loop. */
      if (bytes_read == 0)
        break;

      /* It is possible that more bytes were read than we thought were
       * available. To prevent `avail` from underflowing, break out of the loop
       * if this is the case. */
      if (bytes_read > avail)
        break;

      /* Recompute the number of bytes available. */
      avail -= bytes_read;
    }
  }

  /* Start another zero-read request if necessary. */
  if ((handle->flags & UV_HANDLE_READING) &&
      !(handle->flags & UV_HANDLE_READ_PENDING)) {
    uv_pipe_queue_read(loop, handle);
  }
}

void uv_process_pipe_write_req(uv_loop_t* loop, uv_pipe_t* handle,
    uv_write_t* req) {

  assert(handle->type == UV_NAMED_PIPE);

  assert(handle->write_queue_size >= req->u.io.queued_bytes);
  handle->write_queue_size -= req->u.io.queued_bytes;

  UNREGISTER_HANDLE_REQ(loop, handle, req);

  if (handle->flags & UV_HANDLE_EMULATE_IOCP) {
    if (req->wait_handle != INVALID_HANDLE_VALUE) {
      UnregisterWait(req->wait_handle);
      req->wait_handle = INVALID_HANDLE_VALUE;
    }
    if (req->event_handle) {
      CloseHandle(req->event_handle);
      req->event_handle = nullptr;
    }
  }

  auto err = GET_REQ_ERROR(req);

  /* If this was a coalesced write, extract pointer to the user_provided
   * uv_write_t structure so we can pass the expected pointer to the callback,
   * then free the heap-allocated write req. */
  if (req->coalesced) {
    auto *coalesced_write =
        container_of(req, uv__coalesced_write_t, req);
    req = coalesced_write->user_req;
    uv__free(coalesced_write);
  }
  if (req->cb) {
    req->cb(req, uv_translate_sys_error(err));
  }

  handle->stream.conn.write_reqs_pending--;

  if (handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE &&
      handle->pipe.conn.non_overlapped_writes_tail) {
    assert(handle->stream.conn.write_reqs_pending > 0);
    uv_queue_non_overlapped_write(handle);
  }

  if (handle->stream.conn.shutdown_req != nullptr &&
      handle->stream.conn.write_reqs_pending == 0) {
    uv_want_endgame(loop, reinterpret_cast<uv_handle_t*>(handle));
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_process_pipe_accept_req(uv_loop_t* loop, uv_pipe_t* handle,
    uv_req_t* raw_req) {
  auto *req = reinterpret_cast<uv_pipe_accept_t*>(raw_req);

  assert(handle->type == UV_NAMED_PIPE);

  if (handle->flags & UV_HANDLE_CLOSING) {
    /* The req->pipeHandle should be freed already in uv_pipe_cleanup(). */
    assert(req->pipeHandle == INVALID_HANDLE_VALUE);
    DECREASE_PENDING_REQ_COUNT(handle);
    return;
  }

  if (REQ_SUCCESS(req)) {
    assert(req->pipeHandle != INVALID_HANDLE_VALUE);
    req->next_pending = handle->pipe.serv.pending_accepts;
    handle->pipe.serv.pending_accepts = req;

    if (handle->stream.serv.connection_cb) {
      handle->stream.serv.connection_cb((uv_stream_t*)handle, 0);
    }
  } else {
    if (req->pipeHandle != INVALID_HANDLE_VALUE) {
      CloseHandle(req->pipeHandle);
      req->pipeHandle = INVALID_HANDLE_VALUE;
    }
    if (!(handle->flags & UV_HANDLE_CLOSING)) {
      uv_pipe_queue_accept(loop, handle, req, FALSE);
    }
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_process_pipe_connect_req(uv_loop_t* loop, uv_pipe_t* handle,
    uv_connect_t* req) {

  assert(handle->type == UV_NAMED_PIPE);

  UNREGISTER_HANDLE_REQ(loop, handle, req);

  if (req->cb) {
    auto err = 0;
    if (REQ_SUCCESS(req)) {
      uv_pipe_connection_init(handle);
    } else {
      err = GET_REQ_ERROR(req);
    }
    req->cb(req, uv_translate_sys_error(err));
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_process_pipe_shutdown_req(uv_loop_t* loop, uv_pipe_t* handle,
    uv_shutdown_t* req) {
  assert(handle->type == UV_NAMED_PIPE);

  UNREGISTER_HANDLE_REQ(loop, handle, req);

  if (handle->flags & UV_HANDLE_READABLE) {
    /* Initialize and optionally start the eof timer. Only do this if the pipe
     * is readable and we haven't seen EOF come in ourselves. */
    eof_timer_init(handle);

    /* If reading start the timer right now. Otherwise uv_pipe_queue_read will
     * start it. */
    if (handle->flags & UV_HANDLE_READ_PENDING) {
      eof_timer_start(handle);
    }

  } else {
    /* This pipe is not readable. We can just close it to let the other end
     * know that we're done writing. */
    close_pipe(handle);
  }

  if (req->cb) {
    req->cb(req, 0);
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

static void eof_timer_init(uv_pipe_t* pipe) {

  assert(pipe->pipe.conn.eof_timer == nullptr);
  assert(pipe->flags & UV_HANDLE_CONNECTION);

  pipe->pipe.conn.eof_timer = create_ptrstruct<uv_timer_t>(sizeof(decltype(*pipe->pipe.conn.eof_timer)));

  auto r = uv_timer_init(pipe->loop, pipe->pipe.conn.eof_timer);
  assert(r == 0); /* timers can't fail */
  pipe->pipe.conn.eof_timer->data = pipe;
  uv_unref(reinterpret_cast<uv_handle_t*>(pipe->pipe.conn.eof_timer));
}

static void eof_timer_start(uv_pipe_t* pipe) {
  assert(pipe->flags & UV_HANDLE_CONNECTION);

  if (pipe->pipe.conn.eof_timer != nullptr) {
    uv_timer_start(pipe->pipe.conn.eof_timer, eof_timer_cb, eof_timeout, 0);
  }
}

static void eof_timer_stop(uv_pipe_t* pipe) {
  assert(pipe->flags & UV_HANDLE_CONNECTION);

  if (pipe->pipe.conn.eof_timer != nullptr) {
    uv_timer_stop(pipe->pipe.conn.eof_timer);
  }
}

static void eof_timer_cb(uv_timer_t* timer) {
  auto *pipe = static_cast<uv_pipe_t*>(timer->data);

  assert(pipe->type == UV_NAMED_PIPE);

  /* This should always be true, since we start the timer only in
   * uv_pipe_queue_read after successfully calling ReadFile, or in
   * uv_process_pipe_shutdown_req if a read is pending, and we always
   * immediately stop the timer in uv_process_pipe_read_req. */
  assert(pipe->flags & UV_HANDLE_READ_PENDING);

  /* If there are many packets coming off the iocp then the timer callback may
   * be called before the read request is coming off the queue. Therefore we
   * check here if the read request has completed but will be processed later.
   */
  if ((pipe->flags & UV_HANDLE_READ_PENDING) &&
      HasOverlappedIoCompleted(&pipe->read_req.u.io.overlapped)) {
    return;
  }

  /* Force both ends off the pipe. */
  close_pipe(pipe);

  /* Stop reading, so the pending read that is going to fail will not be
   * reported to the user. */
  uv_read_stop(reinterpret_cast<uv_stream_t*>(pipe));

  /* Report the eof and update flags. This will get reported even if the user
   * stopped reading in the meantime. TODO: is that okay? */
  auto *loop = timer->loop;
  uv_pipe_read_eof(loop, pipe, uv_null_buf_);
}

static void eof_timer_destroy(uv_pipe_t* pipe) {
  assert(pipe->flags & UV_HANDLE_CONNECTION);

  if (pipe->pipe.conn.eof_timer) {
    uv_close(reinterpret_cast<uv_handle_t*>(pipe->pipe.conn.eof_timer), eof_timer_close_cb);
    pipe->pipe.conn.eof_timer = nullptr;
  }
}

static void eof_timer_close_cb(uv_handle_t* handle) {
  assert(handle->type == UV_TIMER);
  uv__free(handle);
}

int uv_pipe_open(uv_pipe_t* pipe, uv_file file) {

  auto os_handle = uv__get_osfhandle(file);
  if (os_handle == INVALID_HANDLE_VALUE)
    return UV_EBADF;

  uv__once_init();
  /* In order to avoid closing a stdio file descriptor 0-2, duplicate the
   * underlying OS handle and forget about the original fd.
   * We could also opt to use the original OS handle and just never close it,
   * but then there would be no reliable way to cancel pending read operations
   * upon close.
   */
  if (file <= 2) {
    if (!DuplicateHandle(INVALID_HANDLE_VALUE,
                         os_handle,
                         INVALID_HANDLE_VALUE,
                         &os_handle,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS))
      return uv_translate_sys_error(GetLastError());
    file = -1;
  }

  /* Determine what kind of permissions we have on this handle.
   * Cygwin opens the pipe in message mode, but we can support it,
   * just query the access flags and set the stream flags accordingly.
   */
  auto io_status = IO_STATUS_BLOCK{};
  auto access = FILE_ACCESS_INFORMATION{};
  auto nt_status = pNtQueryInformationFile(os_handle,
                                      &io_status,
                                      &access,
                                      sizeof(decltype(access)),
                                      FileAccessInformation);
  if (nt_status != STATUS_SUCCESS)
    return UV_EINVAL;

  if (pipe->ipc) {
    if (!(access.AccessFlags & FILE_WRITE_DATA) ||
        !(access.AccessFlags & FILE_READ_DATA)) {
      return UV_EINVAL;
    }
  }

  auto duplex_flags = DWORD{0};
  if (access.AccessFlags & FILE_WRITE_DATA)
    duplex_flags |= UV_HANDLE_WRITABLE;
  if (access.AccessFlags & FILE_READ_DATA)
    duplex_flags |= UV_HANDLE_READABLE;

  if (os_handle == INVALID_HANDLE_VALUE ||
      uv_set_pipe_handle(pipe->loop,
                         pipe,
                         os_handle,
                         file,
                         duplex_flags) == -1) {
    return UV_EINVAL;
  }

  uv_pipe_connection_init(pipe);

  if (pipe->ipc) {
    assert(!(pipe->flags & UV_HANDLE_NON_OVERLAPPED_PIPE));
    pipe->pipe.conn.ipc_remote_pid = uv_os_getppid();
    assert(pipe->pipe.conn.ipc_remote_pid != (DWORD) -1);
  }
  return 0;
}

static int uv__pipe_getname(const uv_pipe_t* handle, char* buffer, size_t* size) {

  uv__once_init();

  if (handle->handle == INVALID_HANDLE_VALUE) {
    *size = 0;
    return UV_EINVAL;
  }

  /* NtQueryInformationFile will block if another thread is performing a
   * blocking operation on the queried handle. If the pipe handle is
   * synchronous, there may be a worker thread currently calling ReadFile() on
   * the pipe handle, which could cause a deadlock. To avoid this, interrupt
   * the read. */
  if (handle->flags & UV_HANDLE_CONNECTION &&
      handle->flags & UV_HANDLE_NON_OVERLAPPED_PIPE) {
    uv__pipe_interrupt_read((uv_pipe_t*) handle); /* cast away const warning */
  }

  auto io_status = IO_STATUS_BLOCK{};
  auto tmp_name_info = FILE_NAME_INFORMATION{};
  auto nt_status = pNtQueryInformationFile(handle->handle,
                                      &io_status,
                                      &tmp_name_info,
                                      sizeof tmp_name_info,
                                      FileNameInformation);
  
  FILE_NAME_INFORMATION* name_info = nullptr;
  if (nt_status == STATUS_BUFFER_OVERFLOW) {
    auto name_size = sizeof(decltype(*name_info)) + tmp_name_info.FileNameLength;
    name_info = create_ptrstruct<FILE_NAME_INFORMATION>(name_size);
    if (!name_info) {
      *size = 0;
      auto err = UV_ENOMEM;
      return static_cast<int>(err);
    }

    nt_status = pNtQueryInformationFile(handle->handle,
                                        &io_status,
                                        name_info,
                                        static_cast<ULONG>(name_size),
                                        FileNameInformation);
  }

  if (nt_status != STATUS_SUCCESS) {
    *size = 0;
    auto err = uv_translate_sys_error(pRtlNtStatusToDosError(nt_status));
    uv__free(name_info);
    return err;
  }

  auto name_len = unsigned int{};
  WCHAR* name_buf;
  if (!name_info) {
    /* the struct on stack was used */
    name_buf = tmp_name_info.FileName;
    name_len = tmp_name_info.FileNameLength;
  } else {
    name_buf = name_info->FileName;
    name_len = name_info->FileNameLength;
  }

  if (name_len == 0) {
    *size = 0;
    auto err = 0;
    uv__free(name_info);
    return err;
  }

  name_len /= sizeof(WCHAR);

  /* check how much space we need */
  auto addrlen = static_cast<unsigned int>(
                    WideCharToMultiByte(CP_UTF8,
                                0,
                                name_buf,
                                name_len,
                                nullptr,
                                0,
                                nullptr,
                                nullptr));
  if (!addrlen) {
    *size = 0;
    auto err = uv_translate_sys_error(GetLastError());
    uv__free(name_info);
    return err;
  } else if (pipe_prefix_len + addrlen >= *size) {
    /* "\\\\.\\pipe" + name */
    *size = pipe_prefix_len + addrlen + 1;
    auto err = UV_ENOBUFS;
    uv__free(name_info);
    return static_cast<int>(err);
  }

  memcpy(buffer, pipe_prefix, pipe_prefix_len);
  addrlen = WideCharToMultiByte(CP_UTF8,
                                0,
                                name_buf,
                                name_len,
                                buffer+pipe_prefix_len,
                                static_cast<int>(*size-pipe_prefix_len),
                                nullptr,
                                nullptr);
  if (!addrlen) {
    *size = 0;
    auto err = uv_translate_sys_error(GetLastError());
    uv__free(name_info);
    return err;
  }

  addrlen += pipe_prefix_len;
  *size = addrlen;
  buffer[addrlen] = '\0';

  uv__free(name_info);
  return 0;
}

int uv_pipe_pending_count(uv_pipe_t* handle) {
  if (!handle->ipc)
    return 0;
  return handle->pipe.conn.ipc_xfer_queue_length;
}

int uv_pipe_getsockname(const uv_pipe_t* handle, char* buffer, size_t* size) {
  if (handle->flags & UV_HANDLE_BOUND)
    return uv__pipe_getname(handle, buffer, size);

  if (handle->flags & UV_HANDLE_CONNECTION ||
      handle->handle != INVALID_HANDLE_VALUE) {
    *size = 0;
    return 0;
  }

  return UV_EBADF;
}

int uv_pipe_getpeername(const uv_pipe_t* handle, char* buffer, size_t* size) {
  /* emulate unix behaviour */
  if (handle->flags & UV_HANDLE_BOUND)
    return UV_ENOTCONN;

  if (handle->handle != INVALID_HANDLE_VALUE)
    return uv__pipe_getname(handle, buffer, size);

  return UV_EBADF;
}

uv_handle_type uv_pipe_pending_type(uv_pipe_t* handle) {
  if (!handle->ipc)
    return UV_UNKNOWN_HANDLE;
  if (handle->pipe.conn.ipc_xfer_queue_length == 0)
    return UV_UNKNOWN_HANDLE;
  else
    return UV_TCP;
}

int uv_pipe_chmod(uv_pipe_t* handle, int mode) {
  auto sid_world = SID_IDENTIFIER_AUTHORITY{ SECURITY_WORLD_SID_AUTHORITY };

  if (handle == nullptr || handle->handle == INVALID_HANDLE_VALUE)
    return UV_EBADF;

  if (mode != UV_READABLE &&
      mode != UV_WRITABLE &&
      mode != (UV_WRITABLE | UV_READABLE))
    return UV_EINVAL;

  auto everyone = PSID{};
  if (!AllocateAndInitializeSid(&sid_world,
                                1,
                                SECURITY_WORLD_RID,
                                0, 0, 0, 0, 0, 0, 0,
                                &everyone)) {
    auto error = GetLastError();
    return uv_translate_sys_error(error);
  }

  auto sd = PSECURITY_DESCRIPTOR{};
  auto old_dacl = PACL{};
  if (GetSecurityInfo(handle->handle,
                      SE_KERNEL_OBJECT,
                      DACL_SECURITY_INFORMATION,
                      nullptr,
                      nullptr,
                      &old_dacl,
                      nullptr,
                      &sd)) {
    auto error = GetLastError();
    FreeSid(everyone);
    return uv_translate_sys_error(error);
  }

  auto ea = EXPLICIT_ACCESS{};
  memset(&ea, 0, sizeof(decltype(ea)));
  if (mode & UV_READABLE)
    ea.grfAccessPermissions |= GENERIC_READ | FILE_WRITE_ATTRIBUTES;
  if (mode & UV_WRITABLE)
    ea.grfAccessPermissions |= GENERIC_WRITE | FILE_READ_ATTRIBUTES;
  ea.grfAccessPermissions |= SYNCHRONIZE;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName = static_cast<LPTSTR>(everyone);

  auto new_dacl = PACL{};
  if (SetEntriesInAcl(1, &ea, old_dacl, &new_dacl)) {
    auto error = GetLastError();
    LocalFree(static_cast<HLOCAL>(sd));
    FreeSid(everyone);
    return uv_translate_sys_error(error);
  }

  if (SetSecurityInfo(handle->handle,
                      SE_KERNEL_OBJECT,
                      DACL_SECURITY_INFORMATION,
                      nullptr,
                      nullptr,
                      new_dacl,
                      nullptr)) {
    auto error = GetLastError();
    LocalFree(static_cast<HLOCAL>(new_dacl));
    LocalFree(static_cast<HLOCAL>(sd));
    FreeSid(everyone);
    return uv_translate_sys_error(error);
  }

  LocalFree(static_cast<HLOCAL>(new_dacl));
  LocalFree(static_cast<HLOCAL>(sd));
  FreeSid(everyone);
  return uv_translate_sys_error(0);
}
