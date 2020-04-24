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
#include <string.h>
#include <stdlib.h>
#include <limits>

#if defined(_MSC_VER) && _MSC_VER < 1600
# include "uv/stdint-msvc2008.h"
#else
# include <stdint.h>
#endif

#ifndef COMMON_LVB_REVERSE_VIDEO
# define COMMON_LVB_REVERSE_VIDEO 0x4000
#endif

#include "uv.h"
#include "internal.h"
#include "handle-inl.h"
#include "stream-inl.h"
#include "req-inl.h"

#ifndef InterlockedOr
# define InterlockedOr _InterlockedOr
#endif

#define UNICODE_REPLACEMENT_CHARACTER (0xfffd)

#define ANSI_NORMAL           0x0000
#define ANSI_ESCAPE_SEEN      0x0002
#define ANSI_CSI              0x0004
#define ANSI_ST_CONTROL       0x0008
#define ANSI_IGNORE           0x0010
#define ANSI_IN_ARG           0x0020
#define ANSI_IN_STRING        0x0040
#define ANSI_BACKSLASH_SEEN   0x0080
#define ANSI_EXTENSION        0x0100
#define ANSI_DECSCUSR         0x0200

#define MAX_INPUT_BUFFER_LENGTH 8192
#define MAX_CONSOLE_CHAR 8192

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#define CURSOR_SIZE_SMALL     25
#define CURSOR_SIZE_LARGE     100

static void uv_tty_capture_initial_style(
    CONSOLE_SCREEN_BUFFER_INFO* screen_buffer_info,
    CONSOLE_CURSOR_INFO* cursor_info);
static void uv_tty_update_virtual_window(CONSOLE_SCREEN_BUFFER_INFO* info);
static int uv__cancel_read_console(uv_tty_t* handle);


/* Null uv_buf_t */
static const uv_buf_t uv_null_buf_ = { 0, nullptr };

enum uv__read_console_status_e {
  NOT_STARTED,
  IN_PROGRESS,
  TRAP_REQUESTED,
  COMPLETED
};

static volatile LONG uv__read_console_status = NOT_STARTED;
static volatile LONG uv__restore_screen_state;
static CONSOLE_SCREEN_BUFFER_INFO uv__saved_screen_state;


/*
 * The console virtual window.
 *
 * Normally cursor movement in windows is relative to the console screen buffer,
 * e.g. the application is allowed to overwrite the 'history'. This is very
 * inconvenient, it makes absolute cursor movement pretty useless. There is
 * also the concept of 'client rect' which is defined by the actual size of
 * the console window and the scroll position of the screen buffer, but it's
 * very volatile because it changes when the user scrolls.
 *
 * To make cursor movement behave sensibly we define a virtual window to which
 * cursor movement is confined. The virtual window is always as wide as the
 * console screen buffer, but it's height is defined by the size of the
 * console window. The top of the virtual window aligns with the position
 * of the caret when the first stdout/err handle is created, unless that would
 * mean that it would extend beyond the bottom of the screen buffer -  in that
 * that case it's located as far down as possible.
 *
 * When the user writes a long text or many newlines, such that the output
 * reaches beyond the bottom of the virtual window, the virtual window is
 * shifted downwards, but not resized.
 *
 * Since all tty i/o happens on the same console, this window is shared
 * between all stdout/stderr handles.
 */

static int uv_tty_virtual_offset = -1;
static int uv_tty_virtual_height = -1;
static int uv_tty_virtual_width = -1;

/* The console window size
 * We keep this separate from uv_tty_virtual_*. We use those values to only
 * handle signalling SIGWINCH
 */

static HANDLE uv__tty_console_handle = INVALID_HANDLE_VALUE;
static int uv__tty_console_height = -1;
static int uv__tty_console_width = -1;
static HANDLE uv__tty_console_resized = INVALID_HANDLE_VALUE;
static uv_mutex_t uv__tty_console_resize_mutex;

static DWORD WINAPI uv__tty_console_resize_message_loop_thread(void* param);
static void CALLBACK uv__tty_console_resize_event(HWINEVENTHOOK hWinEventHook,
                                                  DWORD event,
                                                  HWND hwnd,
                                                  LONG idObject,
                                                  LONG idChild,
                                                  DWORD dwEventThread,
                                                  DWORD dwmsEventTime);
static DWORD WINAPI uv__tty_console_resize_watcher_thread(void* param);
static void uv__tty_console_signal_resize();

/* We use a semaphore rather than a mutex or critical section because in some
   cases (uv__cancel_read_console) we need take the lock in the main thread and
   release it in another thread. Using a semaphore ensures that in such
   scenario the main thread will still block when trying to acquire the lock. */
static uv_sem_t uv_tty_output_lock;

static WORD uv_tty_default_text_attributes =
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static char uv_tty_default_fg_color = 7;
static char uv_tty_default_bg_color = 0;
static char uv_tty_default_fg_bright = 0;
static char uv_tty_default_bg_bright = 0;
static char uv_tty_default_inverse = 0;

static CONSOLE_CURSOR_INFO uv_tty_default_cursor_info;

/* Determine whether or not ANSI support is enabled. */
static BOOL uv__need_check_vterm_state = true;
static uv_tty_vtermstate_t uv__vterm_state = UV_TTY_UNSUPPORTED;
static void uv__determine_vterm_state(HANDLE handle);

void uv_console_init() {
  if (uv_sem_init(&uv_tty_output_lock, 1))
    abort();
  uv__tty_console_handle = CreateFileW(L"CONOUT$",
                                       GENERIC_READ | GENERIC_WRITE,
                                       FILE_SHARE_WRITE,
                                       0,
                                       OPEN_EXISTING,
                                       0,
                                       0);
  if (uv__tty_console_handle != INVALID_HANDLE_VALUE) {
    CONSOLE_SCREEN_BUFFER_INFO sb_info;
    QueueUserWorkItem(uv__tty_console_resize_message_loop_thread,
                      nullptr,
                      WT_EXECUTELONGFUNCTION);
    uv_mutex_init(&uv__tty_console_resize_mutex);
    if (GetConsoleScreenBufferInfo(uv__tty_console_handle, &sb_info)) {
      uv__tty_console_width = sb_info.dwSize.X;
      uv__tty_console_height = sb_info.srWindow.Bottom - sb_info.srWindow.Top + 1;
    }
  }
}

int uv_tty_init(uv_loop_t* loop, uv_tty_t* tty, uv_file fd) {

  uv__once_init();
  auto handle = uv__get_osfhandle(fd);
  if (handle == INVALID_HANDLE_VALUE)
    return UV_EBADF;

  if (fd <= 2) {
    /* In order to avoid closing a stdio file descriptor 0-2, duplicate the
     * underlying OS handle and forget about the original fd.
     * We could also opt to use the original OS handle and just never close it,
     * but then there would be no reliable way to cancel pending read operations
     * upon close.
     */
    if (!DuplicateHandle(INVALID_HANDLE_VALUE,
                         handle,
                         INVALID_HANDLE_VALUE,
                         &handle,
                         0,
                         false,
                         DUPLICATE_SAME_ACCESS))
      return uv_translate_sys_error(GetLastError());
    fd = -1;
  }

  DWORD NumberOfEvents;
  auto readable = GetNumberOfConsoleInputEvents(handle, &NumberOfEvents);
  if (!readable) {
    /* Obtain the screen buffer info with the output handle. */
    CONSOLE_SCREEN_BUFFER_INFO screen_buffer_info;
    if (!GetConsoleScreenBufferInfo(handle, &screen_buffer_info)) {
      return uv_translate_sys_error(GetLastError());
    }

    /* Obtain the cursor info with the output handle. */
    CONSOLE_CURSOR_INFO cursor_info;
    if (!GetConsoleCursorInfo(handle, &cursor_info)) {
      return uv_translate_sys_error(GetLastError());
    }

    /* Obtain the tty_output_lock because the virtual window state is shared
     * between all uv_tty_t handles. */
    uv_sem_wait(&uv_tty_output_lock);

    if (uv__need_check_vterm_state)
      uv__determine_vterm_state(handle);

    /* Remember the original console text attributes and cursor info. */
    uv_tty_capture_initial_style(&screen_buffer_info, &cursor_info);

    uv_tty_update_virtual_window(&screen_buffer_info);

    uv_sem_post(&uv_tty_output_lock);
  }

  uv_stream_init(loop, reinterpret_cast<uv_stream_t*>(tty), UV_TTY);
  uv_connection_init(reinterpret_cast<uv_stream_t*>(tty));

  tty->handle = handle;
  tty->u.fd = fd;
  tty->reqs_pending = 0;
  tty->flags |= UV_HANDLE_BOUND;

  if (readable) {
    /* Initialize TTY input specific fields. */
    tty->flags |= UV_HANDLE_TTY_READABLE | UV_HANDLE_READABLE;
    /* TODO: remove me in v2.x. */
    tty->tty.rd.unused_ = nullptr;
    tty->tty.rd.read_line_buffer = uv_null_buf_;
    tty->tty.rd.read_raw_wait = nullptr;

    /* Init keycode-to-vt100 mapper state. */
    tty->tty.rd.last_key_len = 0;
    tty->tty.rd.last_key_offset = 0;
    tty->tty.rd.last_utf16_high_surrogate = 0;
    memset(&tty->tty.rd.last_input_record, 0, sizeof tty->tty.rd.last_input_record);
  } else {
    /* TTY output specific fields. */
    tty->flags |= UV_HANDLE_WRITABLE;

    /* Init utf8-to-utf16 conversion state. */
    tty->tty.wr.utf8_bytes_left = 0;
    tty->tty.wr.utf8_codepoint = 0;

    /* Initialize eol conversion state */
    tty->tty.wr.previous_eol = 0;

    /* Init ANSI parser state. */
    tty->tty.wr.ansi_parser_state = ANSI_NORMAL;
  }

  return 0;
}

/* Set the default console text attributes based on how the console was
 * configured when libuv started.
 */
static void uv_tty_capture_initial_style(
    CONSOLE_SCREEN_BUFFER_INFO* screen_buffer_info,
    CONSOLE_CURSOR_INFO* cursor_info) {
  static int style_captured = 0;

  /* Only do this once.
     Assumption: Caller has acquired uv_tty_output_lock. */
  if (style_captured)
    return;

  /* Save raw win32 attributes. */
  uv_tty_default_text_attributes = screen_buffer_info->wAttributes;

  /* Convert black text on black background to use white text. */
  if (uv_tty_default_text_attributes == 0)
    uv_tty_default_text_attributes = 7;

  /* Convert Win32 attributes to ANSI colors. */
  uv_tty_default_fg_color = 0;
  uv_tty_default_bg_color = 0;
  uv_tty_default_fg_bright = 0;
  uv_tty_default_bg_bright = 0;
  uv_tty_default_inverse = 0;

  if (uv_tty_default_text_attributes & FOREGROUND_RED)
    uv_tty_default_fg_color |= 1;

  if (uv_tty_default_text_attributes & FOREGROUND_GREEN)
    uv_tty_default_fg_color |= 2;

  if (uv_tty_default_text_attributes & FOREGROUND_BLUE)
    uv_tty_default_fg_color |= 4;

  if (uv_tty_default_text_attributes & BACKGROUND_RED)
    uv_tty_default_bg_color |= 1;

  if (uv_tty_default_text_attributes & BACKGROUND_GREEN)
    uv_tty_default_bg_color |= 2;

  if (uv_tty_default_text_attributes & BACKGROUND_BLUE)
    uv_tty_default_bg_color |= 4;

  if (uv_tty_default_text_attributes & FOREGROUND_INTENSITY)
    uv_tty_default_fg_bright = 1;

  if (uv_tty_default_text_attributes & BACKGROUND_INTENSITY)
    uv_tty_default_bg_bright = 1;

  if (uv_tty_default_text_attributes & COMMON_LVB_REVERSE_VIDEO)
    uv_tty_default_inverse = 1;

  /* Save the cursor size and the cursor state. */
  uv_tty_default_cursor_info = *cursor_info;

  style_captured = 1;
}


int uv_tty_set_mode(uv_tty_t* tty, uv_tty_mode_t mode) {

  if (!(tty->flags & UV_HANDLE_TTY_READABLE)) {
    return UV_EINVAL;
  }

  if (!!mode == !!(tty->flags & UV_HANDLE_TTY_RAW)) {
    return 0;
  }


  DWORD flags;
  switch (mode) {
    case UV_TTY_MODE_NORMAL:
      flags = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
      break;
    case UV_TTY_MODE_RAW:
      flags = ENABLE_WINDOW_INPUT;
      break;
    case UV_TTY_MODE_IO:
      return UV_ENOTSUP;
    default:
      return UV_EINVAL;
  }

  uv_alloc_cb alloc_cb;
  uv_read_cb read_cb;
  unsigned char was_reading;
  /* If currently reading, stop, and restart reading. */
  if (tty->flags & UV_HANDLE_READING) {
    was_reading = 1;
    alloc_cb = tty->alloc_cb;
    read_cb = tty->read_cb;
    auto err = uv_tty_read_stop(tty);
    if (err) {
      return uv_translate_sys_error(err);
    }
  } else {
    was_reading = 0;
    alloc_cb = nullptr;
    read_cb = nullptr;
  }

  uv_sem_wait(&uv_tty_output_lock);
  if (!SetConsoleMode(tty->handle, flags)) {
    auto err = uv_translate_sys_error(GetLastError());
    uv_sem_post(&uv_tty_output_lock);
    return err;
  }
  uv_sem_post(&uv_tty_output_lock);

  /* Update flag. */
  tty->flags &= ~UV_HANDLE_TTY_RAW;
  tty->flags |= mode ? UV_HANDLE_TTY_RAW : 0;

  /* If we just stopped reading, restart. */
  if (was_reading) {
    auto err = uv_tty_read_start(tty, alloc_cb, read_cb);
    if (err) {
      return uv_translate_sys_error(err);
    }
  }

  return 0;
}

int uv_tty_get_winsize(uv_tty_t* tty, int* width, int* height) {
  CONSOLE_SCREEN_BUFFER_INFO info;
  if (!GetConsoleScreenBufferInfo(tty->handle, &info)) {
    return uv_translate_sys_error(GetLastError());
  }

  uv_sem_wait(&uv_tty_output_lock);
  uv_tty_update_virtual_window(&info);
  uv_sem_post(&uv_tty_output_lock);

  *width = uv_tty_virtual_width;
  *height = uv_tty_virtual_height;

  return 0;
}

static void CALLBACK uv_tty_post_raw_read(void* data, BOOLEAN didTimeout) {

  assert(data);
  assert(!didTimeout);

  auto *req = static_cast<uv_req_t*>(data);
  auto *handle = static_cast<uv_tty_t*>(req->data);
  auto *loop = handle->loop;

  UnregisterWait(handle->tty.rd.read_raw_wait);
  handle->tty.rd.read_raw_wait = nullptr;

  SET_REQ_SUCCESS(req);
  POST_COMPLETION_FOR_REQ(loop, req);
}


static void uv_tty_queue_read_raw(uv_loop_t* loop, uv_tty_t* handle) {

  assert(handle->flags & UV_HANDLE_READING);
  assert(!(handle->flags & UV_HANDLE_READ_PENDING));

  assert(handle->handle && handle->handle != INVALID_HANDLE_VALUE);

  handle->tty.rd.read_line_buffer = uv_null_buf_;

  auto *req = &handle->read_req;
  memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));

  BOOL r = RegisterWaitForSingleObject(&handle->tty.rd.read_raw_wait,
                                        handle->handle,
                                        uv_tty_post_raw_read,
                                        static_cast<void*>(req),
                                        INFINITE,
                                        WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE);
  if (!r) {
    handle->tty.rd.read_raw_wait = nullptr;
    SET_REQ_ERROR(req, GetLastError());
    uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
  }

  handle->flags |= UV_HANDLE_READ_PENDING;
  handle->reqs_pending++;
}


static DWORD CALLBACK uv_tty_line_read_thread(void* data) {

  assert(data);

  auto *req = static_cast<uv_req_t*>(data);
  auto *handle = static_cast<uv_tty_t*>(req->data);
  auto *loop = handle->loop;

  assert(handle->tty.rd.read_line_buffer.base != nullptr);
  assert(handle->tty.rd.read_line_buffer.len > 0);

  /* ReadConsole can't handle big buffers. */
  DWORD bytes;
  if (handle->tty.rd.read_line_buffer.len < MAX_INPUT_BUFFER_LENGTH) {
    bytes = handle->tty.rd.read_line_buffer.len;
  } else {
    bytes = MAX_INPUT_BUFFER_LENGTH;
  }

  /* At last, unicode! One utf-16 codeunit never takes more than 3 utf-8
   * codeunits to encode. */
  auto chars = bytes / 3;

  auto status = InterlockedExchange(&uv__read_console_status, IN_PROGRESS);
  if (status == TRAP_REQUESTED) {
    SET_REQ_SUCCESS(req);
    req->u.io.overlapped.InternalHigh = 0;
    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
  }

  DWORD read_chars;
  WCHAR utf16[MAX_INPUT_BUFFER_LENGTH / 3];
  auto read_console_success = ReadConsoleW(handle->handle,
                                      static_cast<void*>(utf16),
                                      chars,
                                      &read_chars,
                                      nullptr);

  if (read_console_success) {
    auto read_bytes = static_cast<DWORD>(
                            WideCharToMultiByte(CP_UTF8,
                                     0,
                                     utf16,
                                     read_chars,
                                     handle->tty.rd.read_line_buffer.base,
                                     bytes,
                                     nullptr,
                                     nullptr));
    SET_REQ_SUCCESS(req);
    req->u.io.overlapped.InternalHigh = read_bytes;
  } else {
    SET_REQ_ERROR(req, GetLastError());
  }

  status = InterlockedExchange(&uv__read_console_status, COMPLETED);

  if (status ==  TRAP_REQUESTED) {
    /* If we canceled the read by sending a VK_RETURN event, restore the
       screen state to undo the visual effect of the VK_RETURN */
    if (read_console_success && InterlockedOr(&uv__restore_screen_state, 0)) {
      HANDLE active_screen_buffer;
      active_screen_buffer = CreateFileA("conout$",
                                         GENERIC_READ | GENERIC_WRITE,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         nullptr,
                                         OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL,
                                         nullptr);
      if (active_screen_buffer != INVALID_HANDLE_VALUE) {
        auto pos = uv__saved_screen_state.dwCursorPosition;

        /* If the cursor was at the bottom line of the screen buffer, the
           VK_RETURN would have caused the buffer contents to scroll up by one
           line. The right position to reset the cursor to is therefore one line
           higher */
        if (pos.Y == uv__saved_screen_state.dwSize.Y - 1)
          pos.Y--;

        SetConsoleCursorPosition(active_screen_buffer, pos);
        CloseHandle(active_screen_buffer);
      }
    }
    uv_sem_post(&uv_tty_output_lock);
  }
  POST_COMPLETION_FOR_REQ(loop, req);
  return 0;
}


static void uv_tty_queue_read_line(uv_loop_t* loop, uv_tty_t* handle) {

  assert(handle->flags & UV_HANDLE_READING);
  assert(!(handle->flags & UV_HANDLE_READ_PENDING));
  assert(handle->handle && handle->handle != INVALID_HANDLE_VALUE);

  auto *req = &handle->read_req;
  memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));

  handle->tty.rd.read_line_buffer = uv_buf_init(nullptr, 0);
  handle->alloc_cb(reinterpret_cast<uv_handle_t*>(handle), 8192, &handle->tty.rd.read_line_buffer);
  if (handle->tty.rd.read_line_buffer.base == nullptr ||
      handle->tty.rd.read_line_buffer.len == 0) {
    handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                    UV_ENOBUFS,
                    &handle->tty.rd.read_line_buffer);
    return;
  }
  assert(handle->tty.rd.read_line_buffer.base != nullptr);

  /* Reset flags  No locking is required since there cannot be a line read
     in progress. We are also relying on the memory barrier provided by
     QueueUserWorkItem*/
  uv__restore_screen_state = false;
  uv__read_console_status = NOT_STARTED;
  auto r = QueueUserWorkItem(uv_tty_line_read_thread,
                        static_cast<void*>(req),
                        WT_EXECUTELONGFUNCTION);
  if (!r) {
    SET_REQ_ERROR(req, GetLastError());
    uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));
  }

  handle->flags |= UV_HANDLE_READ_PENDING;
  handle->reqs_pending++;
}

static void uv_tty_queue_read(uv_loop_t* loop, uv_tty_t* handle) {
  if (handle->flags & UV_HANDLE_TTY_RAW) {
    uv_tty_queue_read_raw(loop, handle);
  } else {
    uv_tty_queue_read_line(loop, handle);
  }
}

static const char* get_vt100_fn_key(DWORD code, char shift, char ctrl,
    size_t* len) {
#define VK_CASE(vk, normal_str, shift_str, ctrl_str, shift_ctrl_str)          \
    case (vk):                                                                \
      if (shift && ctrl) {                                                    \
        *len = sizeof shift_ctrl_str;                                         \
        return "\033" shift_ctrl_str;                                         \
      } else if (shift) {                                                     \
        *len = sizeof shift_str ;                                             \
        return "\033" shift_str;                                              \
      } else if (ctrl) {                                                      \
        *len = sizeof ctrl_str;                                               \
        return "\033" ctrl_str;                                               \
      } else {                                                                \
        *len = sizeof normal_str;                                             \
        return "\033" normal_str;                                             \
      }

  switch (code) {
    /* These mappings are the same as Cygwin's. Unmodified and alt-modified
     * keypad keys comply with linux console, modifiers comply with xterm
     * modifier usage. F1. f12 and shift-f1. f10 comply with linux console, f6.
     * f12 with and without modifiers comply with rxvt. */
    VK_CASE(VK_INSERT,  "[2~",  "[2;2~", "[2;5~", "[2;6~")
    VK_CASE(VK_END,     "[4~",  "[4;2~", "[4;5~", "[4;6~")
    VK_CASE(VK_DOWN,    "[B",   "[1;2B", "[1;5B", "[1;6B")
    VK_CASE(VK_NEXT,    "[6~",  "[6;2~", "[6;5~", "[6;6~")
    VK_CASE(VK_LEFT,    "[D",   "[1;2D", "[1;5D", "[1;6D")
    VK_CASE(VK_CLEAR,   "[G",   "[1;2G", "[1;5G", "[1;6G")
    VK_CASE(VK_RIGHT,   "[C",   "[1;2C", "[1;5C", "[1;6C")
    VK_CASE(VK_UP,      "[A",   "[1;2A", "[1;5A", "[1;6A")
    VK_CASE(VK_HOME,    "[1~",  "[1;2~", "[1;5~", "[1;6~")
    VK_CASE(VK_PRIOR,   "[5~",  "[5;2~", "[5;5~", "[5;6~")
    VK_CASE(VK_DELETE,  "[3~",  "[3;2~", "[3;5~", "[3;6~")
    VK_CASE(VK_NUMPAD0, "[2~",  "[2;2~", "[2;5~", "[2;6~")
    VK_CASE(VK_NUMPAD1, "[4~",  "[4;2~", "[4;5~", "[4;6~")
    VK_CASE(VK_NUMPAD2, "[B",   "[1;2B", "[1;5B", "[1;6B")
    VK_CASE(VK_NUMPAD3, "[6~",  "[6;2~", "[6;5~", "[6;6~")
    VK_CASE(VK_NUMPAD4, "[D",   "[1;2D", "[1;5D", "[1;6D")
    VK_CASE(VK_NUMPAD5, "[G",   "[1;2G", "[1;5G", "[1;6G")
    VK_CASE(VK_NUMPAD6, "[C",   "[1;2C", "[1;5C", "[1;6C")
    VK_CASE(VK_NUMPAD7, "[A",   "[1;2A", "[1;5A", "[1;6A")
    VK_CASE(VK_NUMPAD8, "[1~",  "[1;2~", "[1;5~", "[1;6~")
    VK_CASE(VK_NUMPAD9, "[5~",  "[5;2~", "[5;5~", "[5;6~")
    VK_CASE(VK_DECIMAL, "[3~",  "[3;2~", "[3;5~", "[3;6~")
    VK_CASE(VK_F1,      "[[A",  "[23~",  "[11^",  "[23^" )
    VK_CASE(VK_F2,      "[[B",  "[24~",  "[12^",  "[24^" )
    VK_CASE(VK_F3,      "[[C",  "[25~",  "[13^",  "[25^" )
    VK_CASE(VK_F4,      "[[D",  "[26~",  "[14^",  "[26^" )
    VK_CASE(VK_F5,      "[[E",  "[28~",  "[15^",  "[28^" )
    VK_CASE(VK_F6,      "[17~", "[29~",  "[17^",  "[29^" )
    VK_CASE(VK_F7,      "[18~", "[31~",  "[18^",  "[31^" )
    VK_CASE(VK_F8,      "[19~", "[32~",  "[19^",  "[32^" )
    VK_CASE(VK_F9,      "[20~", "[33~",  "[20^",  "[33^" )
    VK_CASE(VK_F10,     "[21~", "[34~",  "[21^",  "[34^" )
    VK_CASE(VK_F11,     "[23~", "[23$",  "[23^",  "[23@" )
    VK_CASE(VK_F12,     "[24~", "[24$",  "[24^",  "[24@" )

    default:
      *len = 0;
      return nullptr;
  }
#undef VK_CASE
}

void uv_processs_tty_read_raw_req_out(uv_loop_t* loop, uv_tty_t* handle){
  /* Wait for more input events. */
  if ((handle->flags & UV_HANDLE_READING) &&
      !(handle->flags & UV_HANDLE_READ_PENDING)) {
    uv_tty_queue_read(loop, handle);
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_process_tty_read_raw_req(uv_loop_t* loop, uv_tty_t* handle,
    uv_req_t* req) {
  /* Shortcut for handle->tty.rd.last_input_record.Event.KeyEvent. */
#define KEV handle->tty.rd.last_input_record.Event.KeyEvent

  DWORD records_left, records_read;

  assert(handle->type == UV_TTY);
  assert(handle->flags & UV_HANDLE_TTY_READABLE);
  handle->flags &= ~UV_HANDLE_READ_PENDING;

  if (!(handle->flags & UV_HANDLE_READING) ||
      !(handle->flags & UV_HANDLE_TTY_RAW)) {
    return uv_processs_tty_read_raw_req_out(loop, handle);
  }

  if (!REQ_SUCCESS(req)) {
    /* An error occurred while waiting for the event. */
    if ((handle->flags & UV_HANDLE_READING)) {
      handle->flags &= ~UV_HANDLE_READING;
      handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                      uv_translate_sys_error(GET_REQ_ERROR(req)),
                      &uv_null_buf_);
    }
    return uv_processs_tty_read_raw_req_out(loop, handle);
  }

  /* Fetch the number of events  */
  if (!GetNumberOfConsoleInputEvents(handle->handle, &records_left)) {
    handle->flags &= ~UV_HANDLE_READING;
    DECREASE_ACTIVE_COUNT(loop, handle);
    handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                    uv_translate_sys_error(GetLastError()),
                    &uv_null_buf_);
    return uv_processs_tty_read_raw_req_out(loop, handle);
  }

  /* Windows sends a lot of events that we're not interested in, so buf will be
   * allocated on demand, when there's actually something to emit. */
  auto buf = uv_null_buf_;
  auto buf_used = off_t{0};

  while ((records_left > 0 || handle->tty.rd.last_key_len > 0) &&
         (handle->flags & UV_HANDLE_READING)) {
    if (handle->tty.rd.last_key_len == 0) {
      /* Read the next input record */
      if (!ReadConsoleInputW(handle->handle,
                             &handle->tty.rd.last_input_record,
                             1,
                             &records_read)) {
        handle->flags &= ~UV_HANDLE_READING;
        DECREASE_ACTIVE_COUNT(loop, handle);
        handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                        uv_translate_sys_error(GetLastError()),
                        &buf);
        return uv_processs_tty_read_raw_req_out(loop, handle);
      }
      records_left--;

      /* We might be not subscribed to EVENT_CONSOLE_LAYOUT or we might be
       * running under some TTY emulator that does not send those events. */
      if (handle->tty.rd.last_input_record.EventType == WINDOW_BUFFER_SIZE_EVENT) {
        uv__tty_console_signal_resize();
      }

      /* Ignore other events that are not key events. */
      if (handle->tty.rd.last_input_record.EventType != KEY_EVENT) {
        continue;
      }

      /* Ignore keyup events, unless the left alt key was held and a valid
       * unicode character was emitted. */
      if (!KEV.bKeyDown &&
          (KEV.wVirtualKeyCode != VK_MENU ||
           KEV.uChar.UnicodeChar == 0)) {
        continue;
      }

      /* Ignore keypresses to numpad number keys if the left alt is held
       * because the user is composing a character, or windows simulating this.
       */
      if ((KEV.dwControlKeyState & LEFT_ALT_PRESSED) &&
          !(KEV.dwControlKeyState & ENHANCED_KEY) &&
          (KEV.wVirtualKeyCode == VK_INSERT ||
          KEV.wVirtualKeyCode == VK_END ||
          KEV.wVirtualKeyCode == VK_DOWN ||
          KEV.wVirtualKeyCode == VK_NEXT ||
          KEV.wVirtualKeyCode == VK_LEFT ||
          KEV.wVirtualKeyCode == VK_CLEAR ||
          KEV.wVirtualKeyCode == VK_RIGHT ||
          KEV.wVirtualKeyCode == VK_HOME ||
          KEV.wVirtualKeyCode == VK_UP ||
          KEV.wVirtualKeyCode == VK_PRIOR ||
          KEV.wVirtualKeyCode == VK_NUMPAD0 ||
          KEV.wVirtualKeyCode == VK_NUMPAD1 ||
          KEV.wVirtualKeyCode == VK_NUMPAD2 ||
          KEV.wVirtualKeyCode == VK_NUMPAD3 ||
          KEV.wVirtualKeyCode == VK_NUMPAD4 ||
          KEV.wVirtualKeyCode == VK_NUMPAD5 ||
          KEV.wVirtualKeyCode == VK_NUMPAD6 ||
          KEV.wVirtualKeyCode == VK_NUMPAD7 ||
          KEV.wVirtualKeyCode == VK_NUMPAD8 ||
          KEV.wVirtualKeyCode == VK_NUMPAD9)) {
        continue;
      }

      if (KEV.uChar.UnicodeChar != 0) {
        int prefix_len, char_len;

        /* Character key pressed */
        if (KEV.uChar.UnicodeChar >= 0xD800 &&
            KEV.uChar.UnicodeChar < 0xDC00) {
          /* UTF-16 high surrogate */
          handle->tty.rd.last_utf16_high_surrogate = KEV.uChar.UnicodeChar;
          continue;
        }

        /* Prefix with \u033 if alt was held, but alt was not used as part a
         * compose sequence. */
        if ((KEV.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
            && !(KEV.dwControlKeyState & (LEFT_CTRL_PRESSED |
            RIGHT_CTRL_PRESSED)) && KEV.bKeyDown) {
          handle->tty.rd.last_key[0] = '\033';
          prefix_len = 1;
        } else {
          prefix_len = 0;
        }

        if (KEV.uChar.UnicodeChar >= 0xDC00 &&
            KEV.uChar.UnicodeChar < 0xE000) {
          /* UTF-16 surrogate pair */
          WCHAR utf16_buffer[2];
          utf16_buffer[0] = handle->tty.rd.last_utf16_high_surrogate;
          utf16_buffer[1] = KEV.uChar.UnicodeChar;
          char_len = WideCharToMultiByte(CP_UTF8,
                                         0,
                                         utf16_buffer,
                                         2,
                                         &handle->tty.rd.last_key[prefix_len],
                                         sizeof handle->tty.rd.last_key,
                                         nullptr,
                                         nullptr);
        } else {
          /* Single UTF-16 character */
          char_len = WideCharToMultiByte(CP_UTF8,
                                         0,
                                         &KEV.uChar.UnicodeChar,
                                         1,
                                         &handle->tty.rd.last_key[prefix_len],
                                         sizeof handle->tty.rd.last_key,
                                         nullptr,
                                         nullptr);
        }

        /* Whatever happened, the last character wasn't a high surrogate. */
        handle->tty.rd.last_utf16_high_surrogate = 0;

        /* If the utf16 character(s) couldn't be converted something must be
         * wrong. */
        if (!char_len) {
          handle->flags &= ~UV_HANDLE_READING;
          DECREASE_ACTIVE_COUNT(loop, handle);
          handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                          uv_translate_sys_error(GetLastError()),
                          &buf);
          return uv_processs_tty_read_raw_req_out(loop, handle);
        }

        handle->tty.rd.last_key_len = static_cast<unsigned char>(prefix_len + char_len);
        handle->tty.rd.last_key_offset = 0;
        continue;

      } else {
        /* Function key pressed */
        size_t prefix_len, vt100_len;

        auto vt100 = get_vt100_fn_key(KEV.wVirtualKeyCode,
                                  !!(KEV.dwControlKeyState & SHIFT_PRESSED),
                                  !!(KEV.dwControlKeyState & (
                                    LEFT_CTRL_PRESSED |
                                    RIGHT_CTRL_PRESSED)),
                                  &vt100_len);

        /* If we were unable to map to a vt100 sequence, just ignore. */
        if (!vt100) {
          continue;
        }

        /* Prefix with \x033 when the alt key was held. */
        if (KEV.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) {
          handle->tty.rd.last_key[0] = '\033';
          prefix_len = 1;
        } else {
          prefix_len = 0;
        }

        /* Copy the vt100 sequence to the handle buffer. */
        assert(prefix_len + vt100_len < sizeof handle->tty.rd.last_key);
        memcpy(&handle->tty.rd.last_key[prefix_len], vt100, vt100_len);

        handle->tty.rd.last_key_len = (unsigned char) (prefix_len + vt100_len);
        handle->tty.rd.last_key_offset = 0;
        continue;
      }
    } else {
      /* Copy any bytes left from the last keypress to the user buffer. */
      if (handle->tty.rd.last_key_offset < handle->tty.rd.last_key_len) {
        /* Allocate a buffer if needed */
        if (buf_used == 0) {
          buf = uv_buf_init(nullptr, 0);
          handle->alloc_cb(reinterpret_cast<uv_handle_t*>(handle), 1024, &buf);
          if (buf.base == nullptr || buf.len == 0) {
            handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), UV_ENOBUFS, &buf);
            return uv_processs_tty_read_raw_req_out(loop, handle);
          }
          assert(buf.base != nullptr);
        }

        buf.base[buf_used++] = handle->tty.rd.last_key[handle->tty.rd.last_key_offset++];

        /* If the buffer is full, emit it */
        if (static_cast<size_t>(buf_used) == buf.len) {
          handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), buf_used, &buf);
          buf = uv_null_buf_;
          buf_used = 0;
        }

        continue;
      }

      /* Apply dwRepeat from the last input record. */
      if (--KEV.wRepeatCount > 0) {
        handle->tty.rd.last_key_offset = 0;
        continue;
      }

      handle->tty.rd.last_key_len = 0;
      continue;
    }
  }

  /* Send the buffer back to the user */
  if (buf_used > 0) {
    handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), buf_used, &buf);
  }

  uv_processs_tty_read_raw_req_out(loop, handle);

#undef KEV
}

void uv_process_tty_read_line_req(uv_loop_t* loop, uv_tty_t* handle,
    uv_req_t* req) {

  assert(handle->type == UV_TTY);
  assert(handle->flags & UV_HANDLE_TTY_READABLE);

  auto buf = handle->tty.rd.read_line_buffer;

  handle->flags &= ~UV_HANDLE_READ_PENDING;
  handle->tty.rd.read_line_buffer = uv_null_buf_;

  if (!REQ_SUCCESS(req)) {
    /* Read was not successful */
    if (handle->flags & UV_HANDLE_READING) {
      /* Real error */
      handle->flags &= ~UV_HANDLE_READING;
      DECREASE_ACTIVE_COUNT(loop, handle);
      handle->read_cb(reinterpret_cast<uv_stream_t*>(handle),
                      uv_translate_sys_error(GET_REQ_ERROR(req)),
                      &buf);
    }
  } else {
    if (!(handle->flags & UV_HANDLE_CANCELLATION_PENDING) &&
        req->u.io.overlapped.InternalHigh != 0) {
      /* Read successful. TODO: read unicode, convert to utf-8 */
      auto bytes = req->u.io.overlapped.InternalHigh;
      handle->read_cb(reinterpret_cast<uv_stream_t*>(handle), bytes, &buf);
    }
    handle->flags &= ~UV_HANDLE_CANCELLATION_PENDING;
  }

  /* Wait for more input events. */
  if ((handle->flags & UV_HANDLE_READING) &&
      !(handle->flags & UV_HANDLE_READ_PENDING)) {
    uv_tty_queue_read(loop, handle);
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_process_tty_read_req(uv_loop_t* loop, uv_tty_t* handle,
    uv_req_t* req) {
  assert(handle->type == UV_TTY);
  assert(handle->flags & UV_HANDLE_TTY_READABLE);

  /* If the read_line_buffer member is zero, it must have been an raw read.
   * Otherwise it was a line-buffered read. FIXME: This is quite obscure. Use a
   * flag or something. */
  if (handle->tty.rd.read_line_buffer.len == 0) {
    uv_process_tty_read_raw_req(loop, handle, req);
  } else {
    uv_process_tty_read_line_req(loop, handle, req);
  }
}

int uv_tty_read_start(uv_tty_t* handle, uv_alloc_cb alloc_cb,
    uv_read_cb read_cb) {
  auto *loop = handle->loop;

  if (!(handle->flags & UV_HANDLE_TTY_READABLE)) {
    return ERROR_INVALID_PARAMETER;
  }

  handle->flags |= UV_HANDLE_READING;
  INCREASE_ACTIVE_COUNT(loop, handle);
  handle->read_cb = read_cb;
  handle->alloc_cb = alloc_cb;

  /* If reading was stopped and then started again, there could still be a read
   * request pending. */
  if (handle->flags & UV_HANDLE_READ_PENDING) {
    return 0;
  }

  /* Maybe the user stopped reading half-way while processing key events.
   * Short-circuit if this could be the case. */
  if (handle->tty.rd.last_key_len > 0) {
    SET_REQ_SUCCESS(&handle->read_req);
    uv_insert_pending_req(handle->loop, reinterpret_cast<uv_req_t*>(&handle->read_req));
    /* Make sure no attempt is made to insert it again until it's handled. */
    handle->flags |= UV_HANDLE_READ_PENDING;
    handle->reqs_pending++;
    return 0;
  }

  uv_tty_queue_read(loop, handle);

  return 0;
}

int uv_tty_read_stop(uv_tty_t* handle) {

  handle->flags &= ~UV_HANDLE_READING;
  DECREASE_ACTIVE_COUNT(handle->loop, handle);

  if (!(handle->flags & UV_HANDLE_READ_PENDING))
    return 0;

  if (handle->flags & UV_HANDLE_TTY_RAW) {
    /* Cancel raw read. Write some bullshit event to force the console wait to
     * return. */
    auto record = INPUT_RECORD{};
    memset(&record, 0, sizeof(decltype(record)));
    record.EventType = FOCUS_EVENT;
    
    auto written = DWORD{};
    if (!WriteConsoleInputW(handle->handle, &record, 1, &written)) {
      return GetLastError();
    }
  } else if (!(handle->flags & UV_HANDLE_CANCELLATION_PENDING)) {
    /* Cancel line-buffered read if not already pending */
    auto err = uv__cancel_read_console(handle);
    if (err)
      return err;

    handle->flags |= UV_HANDLE_CANCELLATION_PENDING;
  }

  return 0;
}

static int uv__cancel_read_console(uv_tty_t* handle) {

  assert(!(handle->flags & UV_HANDLE_CANCELLATION_PENDING));

  /* Hold the output lock during the cancellation, to ensure that further
     writes don't interfere with the screen state. It will be the ReadConsole
     thread's responsibility to release the lock. */
  uv_sem_wait(&uv_tty_output_lock);
  auto status = InterlockedExchange(&uv__read_console_status, TRAP_REQUESTED);
  if (status != IN_PROGRESS) {
    /* Either we have managed to set a trap for the other thread before
       ReadConsole is called, or ReadConsole has returned because the user
       has pressed ENTER. In either case, there is nothing else to do. */
    uv_sem_post(&uv_tty_output_lock);
    return 0;
  }

  /* Save screen state before sending the VK_RETURN event */
  auto active_screen_buffer = CreateFileA("conout$",
                                     GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr,
                                     OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL,
                                     nullptr);

  if (active_screen_buffer != INVALID_HANDLE_VALUE &&
      GetConsoleScreenBufferInfo(active_screen_buffer,
                                 &uv__saved_screen_state)) {
    InterlockedOr(&uv__restore_screen_state, 1);
  }

  /* Write enter key event to force the console wait to return. */
  auto record = INPUT_RECORD{};
  record.EventType = KEY_EVENT;
  record.Event.KeyEvent.bKeyDown = true;
  record.Event.KeyEvent.wRepeatCount = 1;
  record.Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
  record.Event.KeyEvent.wVirtualScanCode =
    static_cast<WORD>(MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC));
  record.Event.KeyEvent.uChar.UnicodeChar = L'\r';
  record.Event.KeyEvent.dwControlKeyState = 0;

  auto err = 0;
  DWORD written;
  if (!WriteConsoleInputW(handle->handle, &record, 1, &written))
    err = GetLastError();

  if (active_screen_buffer != INVALID_HANDLE_VALUE)
    CloseHandle(active_screen_buffer);

  return err;
}

static void uv_tty_update_virtual_window(CONSOLE_SCREEN_BUFFER_INFO* info) {
  uv_tty_virtual_width = info->dwSize.X;
  uv_tty_virtual_height = info->srWindow.Bottom - info->srWindow.Top + 1;

  /* Recompute virtual window offset row. */
  if (uv_tty_virtual_offset == -1) {
    uv_tty_virtual_offset = info->dwCursorPosition.Y;
  } else if (uv_tty_virtual_offset < info->dwCursorPosition.Y -
             uv_tty_virtual_height + 1) {
    /* If suddenly find the cursor outside of the virtual window, it must have
     * somehow scrolled. Update the virtual window offset. */
    uv_tty_virtual_offset = info->dwCursorPosition.Y -
                            uv_tty_virtual_height + 1;
  }
  if (uv_tty_virtual_offset + uv_tty_virtual_height > info->dwSize.Y) {
    uv_tty_virtual_offset = info->dwSize.Y - uv_tty_virtual_height;
  }
  if (uv_tty_virtual_offset < 0) {
    uv_tty_virtual_offset = 0;
  }
}

static COORD uv_tty_make_real_coord(uv_tty_t* handle,
    CONSOLE_SCREEN_BUFFER_INFO* info, int x, unsigned char x_relative, int y,
    unsigned char y_relative) {
  (void) handle;

  uv_tty_update_virtual_window(info);

  /* Adjust y position */
  if (y_relative) {
    y = info->dwCursorPosition.Y + y;
  } else {
    y = uv_tty_virtual_offset + y;
  }
  /* Clip y to virtual client rectangle */
  if (y < uv_tty_virtual_offset) {
    y = uv_tty_virtual_offset;
  } else if (y >= uv_tty_virtual_offset + uv_tty_virtual_height) {
    y = uv_tty_virtual_offset + uv_tty_virtual_height - 1;
  }

  /* Adjust x */
  if (x_relative) {
    x = info->dwCursorPosition.X + x;
  }
  /* Clip x */
  if (x < 0) {
    x = 0;
  } else if (x >= uv_tty_virtual_width) {
    x = uv_tty_virtual_width - 1;
  }

  auto Xx = static_cast<unsigned short>(x);
  auto Yy = static_cast<unsigned short>(y);
  auto result = COORD{ static_cast<short>(Xx), static_cast<short>(Yy) };
  return result;
}

static int uv_tty_emit_text(uv_tty_t* handle, WCHAR buffer[], DWORD length,
    DWORD* error) {

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  DWORD written;
  if (!WriteConsoleW(handle->handle,
                     static_cast<void*>(buffer),
                     length,
                     &written,
                     nullptr)) {
    *error = GetLastError();
    return -1;
  }

  return 0;
}

int uv_tty_move_caret_retry(uv_tty_t* handle, int x, unsigned char x_relative,
    int y, unsigned char y_relative, DWORD* error){
  CONSOLE_SCREEN_BUFFER_INFO info;
  if (!GetConsoleScreenBufferInfo(handle->handle, &info)) {
    *error = GetLastError();
  }

  auto pos = uv_tty_make_real_coord(handle, &info, x, x_relative, y, y_relative);

  if (!SetConsoleCursorPosition(handle->handle, pos)) {
    if (GetLastError() == ERROR_INVALID_PARAMETER) {
      /* The console may be resized - retry */
      return uv_tty_move_caret_retry(handle, x, x_relative, y, y_relative, error);
    } else {
      *error = GetLastError();
      return -1;
    }
  }

  return 0;
}

static int uv_tty_move_caret(uv_tty_t* handle, int x, unsigned char x_relative,
    int y, unsigned char y_relative, DWORD* error) {

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  return uv_tty_move_caret_retry(handle, x, x_relative, y, y_relative, error);  
}

int uv_tty_reset_retry(uv_tty_t* handle, DWORD* error, const COORD &origin, const WORD &char_attrs){

  CONSOLE_SCREEN_BUFFER_INFO screen_buffer_info;
  if (!GetConsoleScreenBufferInfo(handle->handle, &screen_buffer_info)) {
    *error = GetLastError();
    return -1;
  }

  auto count = static_cast<DWORD>(screen_buffer_info.dwSize.X * screen_buffer_info.dwSize.Y);

  decltype(count) written;
  if (!(FillConsoleOutputCharacterW(handle->handle,
                                    L'\x20',
                                    count,
                                    origin,
                                    &written) &&
        FillConsoleOutputAttribute(handle->handle,
                                   char_attrs,
                                   written,
                                   origin,
                                   &written))) {
    if (GetLastError() == ERROR_INVALID_PARAMETER) {
      /* The console may be resized - retry */
      return uv_tty_reset_retry(handle, error, origin, char_attrs);
    } else {
      *error = GetLastError();
      return -1;
    }
  }

  /* Move the virtual window up to the top. */
  uv_tty_virtual_offset = 0;
  uv_tty_update_virtual_window(&screen_buffer_info);

  /* Reset the cursor size and the cursor state. */
  if (!SetConsoleCursorInfo(handle->handle, &uv_tty_default_cursor_info)) {
    *error = GetLastError();
    return -1;
  }

  return 0;
}

static int uv_tty_reset(uv_tty_t* handle, DWORD* error) {
  const auto origin = COORD{0, 0};
  const auto char_attrs = uv_tty_default_text_attributes;

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  /* Reset original text attributes. */
  if (!SetConsoleTextAttribute(handle->handle, char_attrs)) {
    *error = GetLastError();
    return -1;
  }

  /* Move the cursor position to (0, 0). */
  if (!SetConsoleCursorPosition(handle->handle, origin)) {
    *error = GetLastError();
    return -1;
  }

  /* Clear the screen buffer. */
  return uv_tty_reset_retry(handle, error, origin, char_attrs);
}

int uv_tty_clear_retry(uv_tty_t *handle, DWORD *error, int x1, int x2, int y1, int y2,
              int x1r, int x2r, int y1r, int y2r){
    CONSOLE_SCREEN_BUFFER_INFO info;
  if (!GetConsoleScreenBufferInfo(handle->handle, &info)) {
    *error = GetLastError();
    return -1;
  }

  auto start = uv_tty_make_real_coord(handle, &info, x1, static_cast<unsigned char>(x1r), y1, static_cast<unsigned char>(y1r));
  auto end = uv_tty_make_real_coord(handle, &info, x2, static_cast<unsigned char>(x2r), y2, static_cast<unsigned char>(y2r));
  auto count = static_cast<DWORD>((end.Y * info.dwSize.X + end.X) -
          (start.Y * info.dwSize.X + start.X) + 1);
  decltype(count) written;
  if (!(FillConsoleOutputCharacterW(handle->handle,
                              L'\x20',
                              count,
                              start,
                              &written) &&
        FillConsoleOutputAttribute(handle->handle,
                                   info.wAttributes,
                                   written,
                                   start,
                                   &written))) {
    if (GetLastError() == ERROR_INVALID_PARAMETER) {
      /* The console may be resized -        retry */
      return uv_tty_clear_retry(handle, error, x1, x2, y1, y2, x1r, x2r, y1r, y2r);
    } else {
      *error = GetLastError();
      return -1;
    }
  }

  return 0;
}

static int uv_tty_clear(uv_tty_t* handle, int dir, char entire_screen,
    DWORD* error) {

  int x1, x2, y1, y2;
  int x1r, x2r, y1r, y2r;

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  if (dir == 0) {
    /* Clear from current position */
    x1 = 0;
    x1r = 1;
  } else {
    /* Clear from column 0 */
    x1 = 0;
    x1r = 0;
  }

  if (dir == 1) {
    /* Clear to current position */
    x2 = 0;
    x2r = 1;
  } else {
    /* Clear to end of row. We pretend the console is 65536 characters wide,
     * uv_tty_make_real_coord will clip it to the actual console width. */
    x2 = 0xffff;
    x2r = 0;
  }

  if (!entire_screen) {
    /* Stay on our own row */
    y1 = y2 = 0;
    y1r = y2r = 1;
  } else {
    /* Apply columns direction to row */
    y1 = x1;
    y1r = x1r;
    y2 = x2;
    y2r = x2r;
  }

  return uv_tty_clear_retry(handle, error, x1, x2, y1, y2, x1r, x2r, y1r, y2r);
}

#define FLIP_FGBG                                                             \
    do {                                                                      \
      auto fg = info.wAttributes & 0xF;                                       \
      auto bg = info.wAttributes & 0xF0;                                      \
      info.wAttributes &= 0xFF00;                                             \
      info.wAttributes |= fg << 4;                                            \
      info.wAttributes |= bg >> 4;                                            \
    } while (0)

static int uv_tty_set_style(uv_tty_t* handle, DWORD* error) {
  auto argc = static_cast<unsigned short>(handle->tty.wr.ansi_csi_argc);
  auto *argv = handle->tty.wr.ansi_csi_argv;


  auto fg_color = static_cast<char>(-1), bg_color = static_cast<char>(-1);
  auto fg_bright = static_cast<char>(-1), bg_bright = static_cast<char>(-1);
  auto inverse = static_cast<char>(-1);

  if (argc == 0) {
    /* Reset mode */
    fg_color = uv_tty_default_fg_color;
    bg_color = uv_tty_default_bg_color;
    fg_bright = uv_tty_default_fg_bright;
    bg_bright = uv_tty_default_bg_bright;
    inverse = uv_tty_default_inverse;
  }

  for (auto i = 0; i < argc; i++) {
    auto arg = argv[i];

    if (arg == 0) {
      /* Reset mode */
      fg_color = uv_tty_default_fg_color;
      bg_color = uv_tty_default_bg_color;
      fg_bright = uv_tty_default_fg_bright;
      bg_bright = uv_tty_default_bg_bright;
      inverse = uv_tty_default_inverse;

    } else if (arg == 1) {
      /* Foreground bright on */
      fg_bright = 1;

    } else if (arg == 2) {
      /* Both bright off */
      fg_bright = 0;
      bg_bright = 0;

    } else if (arg == 5) {
      /* Background bright on */
      bg_bright = 1;

    } else if (arg == 7) {
      /* Inverse: on */
      inverse = 1;

    } else if (arg == 21 || arg == 22) {
      /* Foreground bright off */
      fg_bright = 0;

    } else if (arg == 25) {
      /* Background bright off */
      bg_bright = 0;

    } else if (arg == 27) {
      /* Inverse: off */
      inverse = 0;

    } else if (arg >= 30 && arg <= 37) {
      /* Set foreground color */
      fg_color = static_cast<char>(arg - 30);

    } else if (arg == 39) {
      /* Default text color */
      fg_color = uv_tty_default_fg_color;
      fg_bright = uv_tty_default_fg_bright;

    } else if (arg >= 40 && arg <= 47) {
      /* Set background color */
      bg_color = static_cast<char>(arg - 40);

    } else if (arg ==  49) {
      /* Default background color */
      bg_color = uv_tty_default_bg_color;
      bg_bright = uv_tty_default_bg_bright;

    } else if (arg >= 90 && arg <= 97) {
      /* Set bold foreground color */
      fg_bright = 1;
      fg_color = static_cast<char>(arg - 90);

    } else if (arg >= 100 && arg <= 107) {
      /* Set bold background color */
      bg_bright = 1;
      bg_color = static_cast<char>(arg - 100);

    }
  }

  if (fg_color == static_cast<char>(-1) && bg_color == static_cast<char>(-1) && 
      fg_bright == static_cast<char>(-1) && bg_bright == static_cast<char>(-1) && 
      inverse == static_cast<char>(-1)) {
    /* Nothing changed */
    return 0;
  }

  CONSOLE_SCREEN_BUFFER_INFO info;
  if (!GetConsoleScreenBufferInfo(handle->handle, &info)) {
    *error = GetLastError();
    return -1;
  }

  if ((info.wAttributes & COMMON_LVB_REVERSE_VIDEO) > 0) {
    FLIP_FGBG;
  }

  if (fg_color != static_cast<char>(-1)) {
    info.wAttributes &= ~(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (fg_color & static_cast<char>(1)) info.wAttributes |= FOREGROUND_RED;
    if (fg_color & static_cast<char>(2)) info.wAttributes |= FOREGROUND_GREEN;
    if (fg_color & static_cast<char>(4)) info.wAttributes |= FOREGROUND_BLUE;
  }

  if (fg_bright != static_cast<char>(-1)) {
    if (fg_bright) {
      info.wAttributes |= FOREGROUND_INTENSITY;
    } else {
      info.wAttributes &= ~FOREGROUND_INTENSITY;
    }
  }

  if (bg_color != static_cast<char>(-1)) {
    info.wAttributes &= ~(BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE);
    if (bg_color & 1) info.wAttributes |= BACKGROUND_RED;
    if (bg_color & 2) info.wAttributes |= BACKGROUND_GREEN;
    if (bg_color & 4) info.wAttributes |= BACKGROUND_BLUE;
  }

  if (bg_bright != static_cast<char>(-1)) {
    if (bg_bright) {
      info.wAttributes |= BACKGROUND_INTENSITY;
    } else {
      info.wAttributes &= ~BACKGROUND_INTENSITY;
    }
  }

  if (inverse != static_cast<char>(-1)) {
    if (inverse) {
      info.wAttributes |= COMMON_LVB_REVERSE_VIDEO;
    } else {
      info.wAttributes &= ~COMMON_LVB_REVERSE_VIDEO;
    }
  }

  if ((info.wAttributes & COMMON_LVB_REVERSE_VIDEO) > 0) {
    FLIP_FGBG;
  }

  if (!SetConsoleTextAttribute(handle->handle, info.wAttributes)) {
    *error = GetLastError();
    return -1;
  }

  return 0;
}

static int uv_tty_save_state(uv_tty_t* handle, unsigned char save_attributes,
    DWORD* error) {

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  CONSOLE_SCREEN_BUFFER_INFO info;
  if (!GetConsoleScreenBufferInfo(handle->handle, &info)) {
    *error = GetLastError();
    return -1;
  }

  uv_tty_update_virtual_window(&info);

  handle->tty.wr.saved_position.X = info.dwCursorPosition.X;
  handle->tty.wr.saved_position.Y = static_cast<short>(static_cast<int>(info.dwCursorPosition.Y) - uv_tty_virtual_offset);
  handle->flags |= UV_HANDLE_TTY_SAVED_POSITION;

  if (save_attributes) {
    handle->tty.wr.saved_attributes = info.wAttributes &
        (FOREGROUND_INTENSITY | BACKGROUND_INTENSITY);
    handle->flags |= UV_HANDLE_TTY_SAVED_ATTRIBUTES;
  }

  return 0;
}

static int uv_tty_restore_state(uv_tty_t* handle,
    unsigned char restore_attributes, DWORD* error) {

  if (*error != ERROR_SUCCESS) {
    return -1;
  }

  if (handle->flags & UV_HANDLE_TTY_SAVED_POSITION) {
    if (uv_tty_move_caret(handle,
                          handle->tty.wr.saved_position.X,
                          0,
                          handle->tty.wr.saved_position.Y,
                          0,
                          error) != 0) {
      return -1;
    }
  }

  if (restore_attributes &&
      (handle->flags & UV_HANDLE_TTY_SAVED_ATTRIBUTES)) {

    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(handle->handle, &info)) {
      *error = GetLastError();
      return -1;
    }

    auto new_attributes = info.wAttributes;
    new_attributes &= ~(FOREGROUND_INTENSITY | BACKGROUND_INTENSITY);
    new_attributes |= handle->tty.wr.saved_attributes;

    if (!SetConsoleTextAttribute(handle->handle, new_attributes)) {
      *error = GetLastError();
      return -1;
    }
  }

  return 0;
}

static int uv_tty_set_cursor_visibility(uv_tty_t* handle,
                                        BOOL visible,
                                        DWORD* error) {

  CONSOLE_CURSOR_INFO cursor_info;
  if (!GetConsoleCursorInfo(handle->handle, &cursor_info)) {
    *error = GetLastError();
    return -1;
  }

  cursor_info.bVisible = visible;

  if (!SetConsoleCursorInfo(handle->handle, &cursor_info)) {
    *error = GetLastError();
    return -1;
  }

  return 0;
}

static int uv_tty_set_cursor_shape(uv_tty_t* handle, int style, DWORD* error) {

  CONSOLE_CURSOR_INFO cursor_info;
  if (!GetConsoleCursorInfo(handle->handle, &cursor_info)) {
    *error = GetLastError();
    return -1;
  }

  if (style == 0) {
    cursor_info.dwSize = uv_tty_default_cursor_info.dwSize;
  } else if (style <= 2) {
    cursor_info.dwSize = CURSOR_SIZE_LARGE;
  } else {
    cursor_info.dwSize = CURSOR_SIZE_SMALL;
  }

  if (!SetConsoleCursorInfo(handle->handle, &cursor_info)) {
    *error = GetLastError();
    return -1;
  }

  return 0;
}

static int uv_tty_write_bufs(uv_tty_t* handle,
                             const uv_buf_t bufs[],
                             unsigned int nbufs,
                             DWORD* error) {
  /* We can only write 8k characters at a time. Windows can't handle much more
   * characters in a single console write anyway. */
  WCHAR utf16_buf[MAX_CONSOLE_CHAR];
  DWORD utf16_buf_used = 0;

#define FLUSH_TEXT()                                                \
  do {                                                              \
    if (utf16_buf_used > 0) {                                       \
      uv_tty_emit_text(handle, utf16_buf, utf16_buf_used, error);   \
      utf16_buf_used = 0;                                           \
    }                                                               \
  } while (0)

#define ENSURE_BUFFER_SPACE(wchars_needed)                          \
  if (wchars_needed > ARRAY_SIZE(utf16_buf) - utf16_buf_used) {     \
    FLUSH_TEXT();                                                   \
  }

  /* Cache for fast access */
  auto utf8_bytes_left = handle->tty.wr.utf8_bytes_left;
  auto utf8_codepoint = handle->tty.wr.utf8_codepoint;
  auto previous_eol = handle->tty.wr.previous_eol;
  auto ansi_parser_state = handle->tty.wr.ansi_parser_state;

  /* Store the error here. If we encounter an error, stop trying to do i/o but
   * keep parsing the buffer so we leave the parser in a consistent state. */
  *error = ERROR_SUCCESS;

  uv_sem_wait(&uv_tty_output_lock);

  for (auto i = 0U; i < nbufs; i++) {
    uv_buf_t buf = bufs[i];

    for (auto j = 0U; j < buf.len; j++) {
      auto c = static_cast<unsigned char>(buf.base[j]);

      /* Run the character through the utf8 decoder We happily accept non
       * shortest form encodings and invalid code points - there's no real harm
       * that can be done. */
      if (utf8_bytes_left == 0) {
        /* Read utf-8 start byte */
        DWORD first_zero_bit;
        auto not_c = static_cast<unsigned char>(~c);
#ifdef _MSC_VER /* msvc */
        if (_BitScanReverse(&first_zero_bit, not_c)) {
#else /* assume gcc */
        if (c != 0) {
          first_zero_bit = (sizeof(int) * 8) - 1 - __builtin_clz(not_c);
#endif
          if (first_zero_bit == 7) {
            /* Ascii - pass right through */
            utf8_codepoint = static_cast<unsigned int>(c);

          } else if (first_zero_bit <= 5) {
            /* Multibyte sequence */
            utf8_codepoint = (0xff >> (8 - first_zero_bit)) & c;
            utf8_bytes_left = static_cast<char>(6 - first_zero_bit);

          } else {
            /* Invalid continuation */
            utf8_codepoint = UNICODE_REPLACEMENT_CHARACTER;
          }

        } else {
          /* 0xff -- invalid */
          utf8_codepoint = UNICODE_REPLACEMENT_CHARACTER;
        }

      } else if ((c & 0xc0) == 0x80) {
        /* Valid continuation of utf-8 multibyte sequence */
        utf8_bytes_left--;
        utf8_codepoint <<= 6;
        utf8_codepoint |= (static_cast<unsigned int>(c) & 0x3f);

      } else {
        /* Start byte where continuation was expected. */
        utf8_bytes_left = 0;
        utf8_codepoint = UNICODE_REPLACEMENT_CHARACTER;
        /* Patch buf offset so this character will be parsed again as a start
         * byte. */
        j--;
      }

      /* Maybe we need to parse more bytes to find a character. */
      if (utf8_bytes_left != 0) {
        continue;
      }

      /* Parse vt100/ansi escape codes */
      if (uv__vterm_state == UV_TTY_SUPPORTED) {
        /* Pass through escape codes if conhost supports them. */
      } else if (ansi_parser_state == ANSI_NORMAL) {
        switch (utf8_codepoint) {
          case '\033':
            ansi_parser_state = ANSI_ESCAPE_SEEN;
            continue;

          case 0233:
            ansi_parser_state = ANSI_CSI;
            handle->tty.wr.ansi_csi_argc = 0;
            continue;
        }

      } else if (ansi_parser_state == ANSI_ESCAPE_SEEN) {
        switch (utf8_codepoint) {
          case '[':
            ansi_parser_state = ANSI_CSI;
            handle->tty.wr.ansi_csi_argc = 0;
            continue;

          case '^':
          case '_':
          case 'P':
          case ']':
            /* Not supported, but we'll have to parse until we see a stop code,
             * e. g. ESC \ or BEL. */
            ansi_parser_state = ANSI_ST_CONTROL;
            continue;

          case '\033':
            /* Ignore double escape. */
            continue;

          case 'c':
            /* Full console reset. */
            FLUSH_TEXT();
            uv_tty_reset(handle, error);
            ansi_parser_state = ANSI_NORMAL;
            continue;

          case '7':
            /* Save the cursor position and text attributes. */
            FLUSH_TEXT();
            uv_tty_save_state(handle, 1, error);
            ansi_parser_state = ANSI_NORMAL;
            continue;

          case '8':
            /* Restore the cursor position and text attributes */
            FLUSH_TEXT();
            uv_tty_restore_state(handle, 1, error);
            ansi_parser_state = ANSI_NORMAL;
            continue;

          default:
            if (utf8_codepoint >= '@' && utf8_codepoint <= '_') {
              /* Single-char control. */
              ansi_parser_state = ANSI_NORMAL;
              continue;
            } else {
              /* Invalid - proceed as normal, */
              ansi_parser_state = ANSI_NORMAL;
            }
        }

      } else if (ansi_parser_state == ANSI_IGNORE) {
        /* We're ignoring this command. Stop only on command character. */
        if (utf8_codepoint >= '@' && utf8_codepoint <= '~') {
          ansi_parser_state = ANSI_NORMAL;
        }
        continue;

      } else if (ansi_parser_state == ANSI_DECSCUSR) {
        /* So far we've the sequence `ESC [ arg space`, and we're waiting for
         * the final command byte. */
        if (utf8_codepoint >= '@' && utf8_codepoint <= '~') {
          /* Command byte */
          if (utf8_codepoint == 'q') {
            /* Change the cursor shape */
            auto style = handle->tty.wr.ansi_csi_argc
              ? handle->tty.wr.ansi_csi_argv[0] : 1;
            if (style >= 0 && style <= 6) {
              FLUSH_TEXT();
              uv_tty_set_cursor_shape(handle, style, error);
            }
          }

          /* Sequence ended - go back to normal state. */
          ansi_parser_state = ANSI_NORMAL;
          continue;
        }
        /* Unexpected character, but sequence hasn't ended yet. Ignore the rest
         * of the sequence. */
        ansi_parser_state = ANSI_IGNORE;

      } else if (ansi_parser_state & ANSI_CSI) {
        /* So far we've seen `ESC [`, and we may or may not have already parsed
         * some of the arguments that follow. */

        if (utf8_codepoint >= '0' && utf8_codepoint <= '9') {
          /* Parse a numerical argument. */
          if (!(ansi_parser_state & ANSI_IN_ARG)) {
            /* We were not currently parsing a number, add a new one. */
            /* Check for that there are too many arguments. */
            if (handle->tty.wr.ansi_csi_argc >=
                ARRAY_SIZE(handle->tty.wr.ansi_csi_argv)) {
              ansi_parser_state = ANSI_IGNORE;
              continue;
            }
            ansi_parser_state |= ANSI_IN_ARG;
            handle->tty.wr.ansi_csi_argc++;
            handle->tty.wr.ansi_csi_argv[handle->tty.wr.ansi_csi_argc - 1] =
                static_cast<unsigned short>(utf8_codepoint - '0');
            continue;

          } else {
            /* We were already parsing a number. Parse next digit. */
            uint32_t value = 10 *
                handle->tty.wr.ansi_csi_argv[handle->tty.wr.ansi_csi_argc - 1];

            /* Check for overflow. */
            if (value > std::numeric_limits<uint16_t>::max()) {
              ansi_parser_state = ANSI_IGNORE;
              continue;
            }

            handle->tty.wr.ansi_csi_argv[handle->tty.wr.ansi_csi_argc - 1] =
                static_cast<unsigned short>(value + (utf8_codepoint - '0'));
            continue;
          }

        } else if (utf8_codepoint == ';') {
          /* Denotes the end of an argument. */
          if (ansi_parser_state & ANSI_IN_ARG) {
            ansi_parser_state &= ~ANSI_IN_ARG;
            continue;

          } else {
            /* If ANSI_IN_ARG is not set, add another argument and default
             * it to 0. */

            /* Check for too many arguments */
            if (handle->tty.wr.ansi_csi_argc >=

                ARRAY_SIZE(handle->tty.wr.ansi_csi_argv)) {
              ansi_parser_state = ANSI_IGNORE;
              continue;
            }

            handle->tty.wr.ansi_csi_argc++;
            handle->tty.wr.ansi_csi_argv[handle->tty.wr.ansi_csi_argc - 1] = 0;
            continue;
          }

        } else if (utf8_codepoint == '?' &&
                   !(ansi_parser_state & ANSI_IN_ARG) &&
                   !(ansi_parser_state & ANSI_EXTENSION) &&
                   handle->tty.wr.ansi_csi_argc == 0) {
          /* Pass through '?' if it is the first character after CSI */
          /* This is an extension character from the VT100 codeset */
          /* that is supported and used by most ANSI terminals today. */
          ansi_parser_state |= ANSI_EXTENSION;
          continue;

        } else if (utf8_codepoint == ' ' &&
                   !(ansi_parser_state & ANSI_EXTENSION)) {
          /* We expect a command byte to follow after this space. The only
           * command that we current support is 'set cursor style'. */
          ansi_parser_state = ANSI_DECSCUSR;
          continue;

        } else if (utf8_codepoint >= '@' && utf8_codepoint <= '~') {
          /* Command byte */
          if (ansi_parser_state & ANSI_EXTENSION) {
            /* Sequence is `ESC [ ? args command`. */
            switch (utf8_codepoint) {
              case 'l':
                /* Hide the cursor */
                if (handle->tty.wr.ansi_csi_argc == 1 &&
                    handle->tty.wr.ansi_csi_argv[0] == 25) {
                  FLUSH_TEXT();
                  uv_tty_set_cursor_visibility(handle, 0, error);
                }
                break;

              case 'h':
                /* Show the cursor */
                if (handle->tty.wr.ansi_csi_argc == 1 &&
                    handle->tty.wr.ansi_csi_argv[0] == 25) {
                  FLUSH_TEXT();
                  uv_tty_set_cursor_visibility(handle, 1, error);
                }
                break;
            }

          } else {
            /* Sequence is `ESC [ args command`. */
            int x, y, d;
            switch (utf8_codepoint) {
              case 'A':
                /* cursor up */
                FLUSH_TEXT();
                y = -(handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1);
                uv_tty_move_caret(handle, 0, 1, y, 1, error);
                break;

              case 'B':
                /* cursor down */
                FLUSH_TEXT();
                y = handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1;
                uv_tty_move_caret(handle, 0, 1, y, 1, error);
                break;

              case 'C':
                /* cursor forward */
                FLUSH_TEXT();
                x = handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1;
                uv_tty_move_caret(handle, x, 1, 0, 1, error);
                break;

              case 'D':
                /* cursor back */
                FLUSH_TEXT();
                x = -(handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1);
                uv_tty_move_caret(handle, x, 1, 0, 1, error);
                break;

              case 'E':
                /* cursor next line */
                FLUSH_TEXT();
                y = handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1;
                uv_tty_move_caret(handle, 0, 0, y, 1, error);
                break;

              case 'F':
                /* cursor previous line */
                FLUSH_TEXT();
                y = -(handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 1);
                uv_tty_move_caret(handle, 0, 0, y, 1, error);
                break;

              case 'G':
                /* cursor horizontal move absolute */
                FLUSH_TEXT();
                x = (handle->tty.wr.ansi_csi_argc >= 1 &&
                     handle->tty.wr.ansi_csi_argv[0])
                  ? handle->tty.wr.ansi_csi_argv[0] - 1 : 0;
                uv_tty_move_caret(handle, x, 0, 0, 1, error);
                break;

              case 'H':
              case 'f':
                /* cursor move absolute */
                FLUSH_TEXT();
                y = (handle->tty.wr.ansi_csi_argc >= 1 &&
                     handle->tty.wr.ansi_csi_argv[0])
                  ? handle->tty.wr.ansi_csi_argv[0] - 1 : 0;
                x = (handle->tty.wr.ansi_csi_argc >= 2 &&
                     handle->tty.wr.ansi_csi_argv[1])
                  ? handle->tty.wr.ansi_csi_argv[1] - 1 : 0;
                uv_tty_move_caret(handle, x, 0, y, 0, error);
                break;

              case 'J':
                /* Erase screen */
                FLUSH_TEXT();
                d = handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 0;
                if (d >= 0 && d <= 2) {
                  uv_tty_clear(handle, d, 1, error);
                }
                break;

              case 'K':
                /* Erase line */
                FLUSH_TEXT();
                d = handle->tty.wr.ansi_csi_argc
                  ? handle->tty.wr.ansi_csi_argv[0] : 0;
                if (d >= 0 && d <= 2) {
                  uv_tty_clear(handle, d, 0, error);
                }
                break;

              case 'm':
                /* Set style */
                FLUSH_TEXT();
                uv_tty_set_style(handle, error);
                break;

              case 's':
                /* Save the cursor position. */
                FLUSH_TEXT();
                uv_tty_save_state(handle, 0, error);
                break;

              case 'u':
                /* Restore the cursor position */
                FLUSH_TEXT();
                uv_tty_restore_state(handle, 0, error);
                break;
            }
          }

          /* Sequence ended - go back to normal state. */
          ansi_parser_state = ANSI_NORMAL;
          continue;

        } else {
          /* We don't support commands that use private mode characters or
           * intermediaries. Ignore the rest of the sequence. */
          ansi_parser_state = ANSI_IGNORE;
          continue;
        }

      } else if (ansi_parser_state & ANSI_ST_CONTROL) {
        /* Unsupported control code.
         * Ignore everything until we see `BEL` or `ESC \`. */
        if (ansi_parser_state & ANSI_IN_STRING) {
          if (!(ansi_parser_state & ANSI_BACKSLASH_SEEN)) {
            if (utf8_codepoint == '"') {
              ansi_parser_state &= ~ANSI_IN_STRING;
            } else if (utf8_codepoint == '\\') {
              ansi_parser_state |= ANSI_BACKSLASH_SEEN;
            }
          } else {
            ansi_parser_state &= ~ANSI_BACKSLASH_SEEN;
          }
        } else {
          if (utf8_codepoint == '\007' || (utf8_codepoint == '\\' &&
              (ansi_parser_state & ANSI_ESCAPE_SEEN))) {
            /* End of sequence */
            ansi_parser_state = ANSI_NORMAL;
          } else if (utf8_codepoint == '\033') {
            /* Escape character */
            ansi_parser_state |= ANSI_ESCAPE_SEEN;
          } else if (utf8_codepoint == '"') {
             /* String starting */
            ansi_parser_state |= ANSI_IN_STRING;
            ansi_parser_state &= ~ANSI_ESCAPE_SEEN;
            ansi_parser_state &= ~ANSI_BACKSLASH_SEEN;
          } else {
            ansi_parser_state &= ~ANSI_ESCAPE_SEEN;
          }
        }
        continue;
      } else {
        /* Inconsistent state */
        abort();
      }

      /* We wouldn't mind emitting utf-16 surrogate pairs. Too bad, the windows
       * console doesn't really support UTF-16, so just emit the replacement
       * character. */
      if (utf8_codepoint > 0xffff) {
        utf8_codepoint = UNICODE_REPLACEMENT_CHARACTER;
      }

      if (utf8_codepoint == 0x0a || utf8_codepoint == 0x0d) {
        /* EOL conversion - emit \r\n when we see \n. */

        if (utf8_codepoint == 0x0a && previous_eol != 0x0d) {
          /* \n was not preceded by \r; print \r\n. */
          ENSURE_BUFFER_SPACE(2);
          utf16_buf[utf16_buf_used++] = L'\r';
          utf16_buf[utf16_buf_used++] = L'\n';
        } else if (utf8_codepoint == 0x0d && previous_eol == 0x0a) {
          /* \n was followed by \r; do not print the \r, since the source was
           * either \r\n\r (so the second \r is redundant) or was \n\r (so the
           * \n was processed by the last case and an \r automatically
           * inserted). */
        } else {
          /* \r without \n; print \r as-is. */
          ENSURE_BUFFER_SPACE(1);
          utf16_buf[utf16_buf_used++] = static_cast<WCHAR>(utf8_codepoint);
        }

        previous_eol = (char) utf8_codepoint;

      } else if (utf8_codepoint <= 0xffff) {
        /* Encode character into utf-16 buffer. */
        ENSURE_BUFFER_SPACE(1);
        utf16_buf[utf16_buf_used++] = static_cast<WCHAR>(utf8_codepoint);
        previous_eol = 0;
      }
    }
  }

  /* Flush remaining characters */
  FLUSH_TEXT();

  /* Copy cached values back to struct. */
  handle->tty.wr.utf8_bytes_left = utf8_bytes_left;
  handle->tty.wr.utf8_codepoint = utf8_codepoint;
  handle->tty.wr.previous_eol = previous_eol;
  handle->tty.wr.ansi_parser_state = ansi_parser_state;

  uv_sem_post(&uv_tty_output_lock);

  if (*error == STATUS_SUCCESS) {
    return 0;
  } else {
    return -1;
  }

#undef FLUSH_TEXT
}

int uv_tty_write(uv_loop_t* loop,
                 uv_write_t* req,
                 uv_tty_t* handle,
                 const uv_buf_t bufs[],
                 unsigned int nbufs,
                 uv_write_cb cb) {

  UV_REQ_INIT(req, UV_WRITE);
  req->handle = reinterpret_cast<uv_stream_t*>(handle);
  req->cb = cb;

  handle->reqs_pending++;
  handle->stream.conn.write_reqs_pending++;
  REGISTER_HANDLE_REQ(loop, handle, req);

  req->u.io.queued_bytes = 0;

  DWORD error;
  if (!uv_tty_write_bufs(handle, bufs, nbufs, &error)) {
    SET_REQ_SUCCESS(req);
  } else {
    SET_REQ_ERROR(req, error);
  }

  uv_insert_pending_req(loop, reinterpret_cast<uv_req_t*>(req));

  return 0;
}

int uv__tty_try_write(uv_tty_t* handle,
                      const uv_buf_t bufs[],
                      unsigned int nbufs) {

  if (handle->stream.conn.write_reqs_pending > 0)
    return UV_EAGAIN;

  DWORD error;
  if (uv_tty_write_bufs(handle, bufs, nbufs, &error))
    return uv_translate_sys_error(error);

  return static_cast<int>(uv__count_bufs(bufs, nbufs));
}

void uv_process_tty_write_req(uv_loop_t* loop, uv_tty_t* handle,
  uv_write_t* req) {

  handle->write_queue_size -= req->u.io.queued_bytes;
  UNREGISTER_HANDLE_REQ(loop, handle, req);

  if (req->cb) {
    auto err = GET_REQ_ERROR(req);
    req->cb(req, uv_translate_sys_error(err));
  }

  handle->stream.conn.write_reqs_pending--;
  if (handle->stream.conn.shutdown_req != nullptr &&
      handle->stream.conn.write_reqs_pending == 0) {
    uv_want_endgame(loop, reinterpret_cast<uv_handle_t*>(handle));
  }

  DECREASE_PENDING_REQ_COUNT(handle);
}

void uv_tty_close(uv_tty_t* handle) {
  assert(handle->u.fd == -1 || handle->u.fd > 2);
  if (handle->flags & UV_HANDLE_READING)
    uv_tty_read_stop(handle);

  if (handle->u.fd == -1)
    CloseHandle(handle->handle);
  else
    _close(handle->u.fd);

  handle->u.fd = -1;
  handle->handle = INVALID_HANDLE_VALUE;
  handle->flags &= ~(UV_HANDLE_READABLE | UV_HANDLE_WRITABLE);
  uv__handle_closing(handle);

  if (handle->reqs_pending == 0) {
    uv_want_endgame(handle->loop, reinterpret_cast<uv_handle_t*>(handle));
  }
}

void uv_tty_endgame(uv_loop_t* loop, uv_tty_t* handle) {
  if (!(handle->flags & UV_HANDLE_TTY_READABLE) &&
      handle->stream.conn.shutdown_req != nullptr &&
      handle->stream.conn.write_reqs_pending == 0) {
    UNREGISTER_HANDLE_REQ(loop, handle, handle->stream.conn.shutdown_req);

    /* TTY shutdown is really just a no-op */
    if (handle->stream.conn.shutdown_req->cb) {
      if (handle->flags & UV_HANDLE_CLOSING) {
        handle->stream.conn.shutdown_req->cb(handle->stream.conn.shutdown_req, UV_ECANCELED);
      } else {
        handle->stream.conn.shutdown_req->cb(handle->stream.conn.shutdown_req, 0);
      }
    }

    handle->stream.conn.shutdown_req = nullptr;

    DECREASE_PENDING_REQ_COUNT(handle);
    return;
  }

  if (handle->flags & UV_HANDLE_CLOSING &&
      handle->reqs_pending == 0) {
    /* The wait handle used for raw reading should be unregistered when the
     * wait callback runs. */
    assert(!(handle->flags & UV_HANDLE_TTY_READABLE) ||
           handle->tty.rd.read_raw_wait == nullptr);

    assert(!(handle->flags & UV_HANDLE_CLOSED));
    uv__handle_close(handle);
  }
}

/*
 * uv_process_tty_accept_req() is a stub to keep DELEGATE_STREAM_REQ working
 * TODO: find a way to remove it
 */
void uv_process_tty_accept_req(uv_loop_t* loop, uv_tty_t* handle,
    uv_req_t* raw_req) {
  (void) loop, handle, raw_req;
  abort();
}

/*
 * uv_process_tty_connect_req() is a stub to keep DELEGATE_STREAM_REQ working
 * TODO: find a way to remove it
 */
void uv_process_tty_connect_req(uv_loop_t* loop, uv_tty_t* handle,
    uv_connect_t* req) {
  (void) loop, handle, req;
  abort();
}

int uv_tty_reset_mode() {
  /* Not necessary to do anything. */
  return 0;
}

/* Determine whether or not this version of windows supports
 * proper ANSI color codes. Should be supported as of windows
 * 10 version 1511, build number 10.0.10586.
 */
static void uv__determine_vterm_state(HANDLE handle) {

  uv__need_check_vterm_state = false;
    
  DWORD dwMode = 0;
  if (!GetConsoleMode(handle, &dwMode)) {
    return;
  }

  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(handle, dwMode)) {
    return;
  }

  uv__vterm_state = UV_TTY_SUPPORTED;
}

static DWORD WINAPI uv__tty_console_resize_message_loop_thread(void* param) {
  (void) param;
  if (pSetWinEventHook == nullptr || pNtQueryInformationProcess == nullptr)
    return 0;

  ULONG_PTR conhost_pid;
  auto status = pNtQueryInformationProcess(GetCurrentProcess(),
                                      ProcessConsoleHostProcess,
                                      &conhost_pid,
                                      sizeof(decltype(conhost_pid)),
                                      nullptr);

  if (!NT_SUCCESS(status)) {
    /* We couldn't retrieve our console host process, probably because this
     * is a 32-bit process running on 64-bit Windows. Fall back to receiving
     * console events from the input stream only. */
    return 0;
  }

  /* Ensure the PID is a multiple of 4, which is required by SetWinEventHook */
  conhost_pid &= ~static_cast<ULONG_PTR>(0x3);

  uv__tty_console_resized = CreateEvent(nullptr, true, false, nullptr);
  if (uv__tty_console_resized == nullptr)
    return 0;
  if (QueueUserWorkItem(uv__tty_console_resize_watcher_thread,
                        nullptr,
                        WT_EXECUTELONGFUNCTION) == 0)
    return 0;

  if (!pSetWinEventHook(EVENT_CONSOLE_LAYOUT,
                        EVENT_CONSOLE_LAYOUT,
                        nullptr,
                        uv__tty_console_resize_event,
                        static_cast<DWORD>(conhost_pid),
                        0,
                        WINEVENT_OUTOFCONTEXT))
    return 0;

  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return 0;
}

static void CALLBACK uv__tty_console_resize_event(HWINEVENTHOOK hWinEventHook,
                                                  DWORD event,
                                                  HWND hwnd,
                                                  LONG idObject,
                                                  LONG idChild,
                                                  DWORD dwEventThread,
                                                  DWORD dwmsEventTime) {
  (void) hWinEventHook, event, 
          hwnd, idObject, idChild, 
            dwEventThread, dwmsEventTime;
  SetEvent(uv__tty_console_resized);
}

static DWORD WINAPI uv__tty_console_resize_watcher_thread(void* param) {
  (void)param;
  for (;;) {
    /* Make sure to not overwhelm the system with resize events */
    Sleep(33);
    WaitForSingleObject(uv__tty_console_resized, INFINITE);
    uv__tty_console_signal_resize();
    ResetEvent(uv__tty_console_resized);
  }
}

static void uv__tty_console_signal_resize() {

  CONSOLE_SCREEN_BUFFER_INFO sb_info;
  if (!GetConsoleScreenBufferInfo(uv__tty_console_handle, &sb_info))
    return;

  auto width = static_cast<int>(sb_info.dwSize.X);
  auto height = sb_info.srWindow.Bottom - sb_info.srWindow.Top + 1;

  uv_mutex_lock(&uv__tty_console_resize_mutex);
  assert(uv__tty_console_width != -1 && uv__tty_console_height != -1);
  if (width != uv__tty_console_width || height != uv__tty_console_height) {
    uv__tty_console_width = width;
    uv__tty_console_height = height;
    uv_mutex_unlock(&uv__tty_console_resize_mutex);
    uv__signal_dispatch(SIGWINCH);
  } else {
    uv_mutex_unlock(&uv__tty_console_resize_mutex);
  }
}

void uv_tty_set_vterm_state(uv_tty_vtermstate_t state) {
  uv_sem_wait(&uv_tty_output_lock);
  uv__need_check_vterm_state = false;
  uv__vterm_state = state;
  uv_sem_post(&uv_tty_output_lock);
}

int uv_tty_get_vterm_state(uv_tty_vtermstate_t* state) {
  uv_sem_wait(&uv_tty_output_lock);
  *state = uv__vterm_state;
  uv_sem_post(&uv_tty_output_lock);
  return 0;
}
