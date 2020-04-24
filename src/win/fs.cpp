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
#include <stdlib.h>
#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <stdio.h>

#include "uv.h"
#include "internal.h"
#include "req-inl.h"
#include "handle-inl.h"
#include "fs-fd-hash-inl.h"
#include "../utils/allocator.cpp"

#define UV_FS_FREE_PATHS         0x0002
#define UV_FS_FREE_PTR           0x0008
#define UV_FS_CLEANEDUP          0x0010


#define INIT(subtype)                                                         \
  do {                                                                        \
    if (req == nullptr)                                                          \
      return UV_EINVAL;                                                       \
    uv_fs_req_init(loop, req, subtype, cb);                                   \
  }                                                                           \
  while (0)

#define POST(X)                                                               \
  do {                                                                        \
    if (cb != nullptr) {                                                      \
      uv__req_register(loop, req);                                            \
      uv__work_submit(loop,                                                   \
                      &req->work_req,                                         \
                      UV__WORK_FAST_IO,                                       \
                      uv__fs_work,                                            \
                      uv__fs_done);                                           \
      return static_cast<X>(0);                                               \
    } else {                                                                  \
      uv__fs_work(&req->work_req);                                            \
      return static_cast<X>(req->result);                                     \
    }                                                                         \
  }                                                                           \
  while (0)

#define SET_REQ_RESULT(req, result_value)                                   \
  do {                                                                      \
    req->result = (result_value);                                           \
    if (req->result == -1) {                                                \
      req->sys_errno_ = _doserrno;                                          \
      req->result = uv_translate_sys_error(req->sys_errno_);                \
    }                                                                       \
  } while (0)

#define SET_REQ_WIN32_ERROR(req, sys_errno)                                 \
  do {                                                                      \
    req->sys_errno_ = static_cast<decltype(req->sys_errno_)>(sys_errno);    \
    req->result = uv_translate_sys_error(req->sys_errno_);                  \
  } while (0)

#define SET_REQ_UV_ERROR(req, uv_errno, sys_errno)                          \
  do {                                                                      \
    req->result = (uv_errno);                                               \
    req->sys_errno_ = (sys_errno);                                          \
  } while (0)

#define VERIFY_FD(fd, req)                                                  \
  if (fd == -1) {                                                           \
    req->result = UV_EBADF;                                                 \
    req->sys_errno_ = ERROR_INVALID_HANDLE;                                 \
    return;                                                                 \
  }

#define MILLIONu (1000U * 1000U)
#define BILLIONu (1000U * 1000U * 1000U)

#define FILETIME_TO_UINT(filetime)                                          \
   (*(reinterpret_cast<uint64_t*>(&(filetime))) - 116444736ull * BILLIONu)

#define FILETIME_TO_TIME_T(filetime)                                        \
   (FILETIME_TO_UINT(filetime) / (10u * MILLIONu))

#define FILETIME_TO_TIME_NS(filetime, secs)                                 \
   ((FILETIME_TO_UINT(filetime) - (secs * 10ull * MILLIONu)) * 100U)

#define FILETIME_TO_TIMESPEC(ts, filetime)                                  \
   do {                                                                     \
     (ts).tv_sec = (long) FILETIME_TO_TIME_T(filetime);                     \
     (ts).tv_nsec = (long) FILETIME_TO_TIME_NS(filetime, (ts).tv_sec);      \
   } while(0)

#define TIME_T_TO_FILETIME(time, filetime_ptr)                              \
  do {                                                                      \
    auto bigtime = (static_cast<uint64_t>((time) * 10ull * MILLIONu)) +     \
                       116444736ull * BILLIONu;                             \
    (filetime_ptr)->dwLowDateTime = bigtime & 0xFFFFFFFF;                   \
    (filetime_ptr)->dwHighDateTime = bigtime >> 32;                         \
  } while(0)

#define IS_SLASH(c) ((c) == L'\\' || (c) == L'/')
#define IS_LETTER(c) (((c) >= L'a' && (c) <= L'z') || \
  ((c) >= L'A' && (c) <= L'Z'))

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

const WCHAR JUNCTION_PREFIX[] = L"\\??\\";
const WCHAR JUNCTION_PREFIX_LEN = 4;

const WCHAR LONG_PATH_PREFIX[] = L"\\\\?\\";
const WCHAR LONG_PATH_PREFIX_LEN = 4;

const WCHAR UNC_PATH_PREFIX[] = L"\\\\?\\UNC\\";
const WCHAR UNC_PATH_PREFIX_LEN = 8;

static int uv__file_symlink_usermode_flag = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;

static DWORD uv__allocation_granularity;


void uv_fs_init() {
  auto system_info = SYSTEM_INFO{};

  GetSystemInfo(&system_info);
  uv__allocation_granularity = system_info.dwAllocationGranularity;

  uv__fd_hash_init();
}

INLINE static int fs__capture_path(uv_fs_t* req, const char* path,
    const char* new_path, const int copy_path) {

  /* new_path can only be set if path is also set. */
  assert(new_path == nullptr || path != nullptr);

  auto buf_sz = ssize_t{0};
  auto pathw_len = ssize_t{0};
  if (path != nullptr) {
    pathw_len = MultiByteToWideChar(CP_UTF8,
                                    0,
                                    path,
                                    -1,
                                    nullptr,
                                    0);
    if (pathw_len == 0) {
      return GetLastError();
    }

    buf_sz += pathw_len * sizeof(WCHAR);
  }

  auto path_len = ssize_t{0};
  if (path != nullptr && copy_path) {
    path_len = 1 + strlen(path);
    buf_sz += path_len;
  }

  auto new_pathw_len = ssize_t{0};
  if (new_path != nullptr) {
    new_pathw_len = MultiByteToWideChar(CP_UTF8,
                                        0,
                                        new_path,
                                        -1,
                                        nullptr,
                                        0);
    if (new_pathw_len == 0) {
      return GetLastError();
    }

    buf_sz += new_pathw_len * sizeof(WCHAR);
  }


  if (buf_sz == 0) {
    req->file.pathw = nullptr;
    req->fs.info.new_pathw = nullptr;
    req->path = nullptr;
    return 0;
  }

  auto buf = (char*) uv__malloc(buf_sz);
  if (buf == nullptr) {
    return ERROR_OUTOFMEMORY;
  }

  auto pos = buf;

  if (path != nullptr) {
    auto r = MultiByteToWideChar(CP_UTF8,
                                  0,
                                  path,
                                  -1,
                                  reinterpret_cast<WCHAR*>(pos),
                                  static_cast<int>(pathw_len));
    assert(r == static_cast<decltype(r)>(pathw_len));
    req->file.pathw = reinterpret_cast<WCHAR*>(pos);
    pos += r * sizeof(WCHAR);
  } else {
    req->file.pathw = nullptr;
  }

  if (new_path != nullptr) {
    auto r = MultiByteToWideChar(CP_UTF8,
                                  0,
                                  new_path,
                                  -1,
                                  reinterpret_cast<WCHAR*>(pos),
                                  static_cast<int>(new_pathw_len));
    assert(r == static_cast<decltype(r)>(new_pathw_len));
    req->fs.info.new_pathw = reinterpret_cast<WCHAR*>(pos);
    pos += r * sizeof(WCHAR);
  } else {
    req->fs.info.new_pathw = nullptr;
  }

  req->path = path;
  if (path != nullptr && copy_path) {
    memcpy(pos, path, path_len);
    assert(path_len == buf_sz - (pos - buf));
    req->path = pos;
  }

  req->flags |= UV_FS_FREE_PATHS;

  return 0;
}

INLINE static void uv_fs_req_init(uv_loop_t* loop, uv_fs_t* req,
    uv_fs_type fs_type, const uv_fs_cb cb) {
  uv__once_init();
  UV_REQ_INIT(req, UV_FS);
  req->loop = loop;
  req->flags = 0;
  req->fs_type = fs_type;
  req->result = 0;
  req->ptr = nullptr;
  req->path = nullptr;
  req->cb = cb;
  memset(&req->fs, 0, sizeof(decltype(req->fs)));
}

static int fs__wide_to_utf8(WCHAR* w_source_ptr,
                               DWORD w_source_len,
                               char** target_ptr,
                               uint64_t* target_len_ptr) {

  auto target_len = WideCharToMultiByte(CP_UTF8,
                                   0,
                                   w_source_ptr,
                                   w_source_len,
                                   nullptr,
                                   0,
                                   nullptr,
                                   nullptr);

  if (target_len == 0) {
    return -1;
  }

  if (target_len_ptr != nullptr) {
    *target_len_ptr = target_len;
  }

  if (target_ptr == nullptr) {
    return 0;
  }

  auto target = create_ptrstruct<char>(target_len + 1);
  if (target == nullptr) {
    SetLastError(ERROR_OUTOFMEMORY);
    return -1;
  }

  auto r = WideCharToMultiByte(CP_UTF8,
                          0,
                          w_source_ptr,
                          w_source_len,
                          target,
                          target_len,
                          nullptr,
                          nullptr);
  assert(r == target_len);
  target[target_len] = '\0';
  *target_ptr = target;
  return 0;
}

INLINE static int fs__readlink_handle(HANDLE handle, char** target_ptr,
    uint64_t* target_len_ptr) {

  char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
  auto* reparse_data = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer);
  auto bytes = DWORD{};
  if (!DeviceIoControl(handle,
                       FSCTL_GET_REPARSE_POINT,
                       nullptr,
                       0,
                       buffer,
                       sizeof(decltype(buffer)),
                       &bytes,
                       nullptr)) {
    return -1;
  }

  WCHAR* w_target;
  auto w_target_len = DWORD{};
  if (reparse_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
    /* Real symlink */
    w_target = reparse_data->SymbolicLinkReparseBuffer.PathBuffer +
        (reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset /
        sizeof(WCHAR));
    w_target_len =
        reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength /
        sizeof(WCHAR);

    /* Real symlinks can contain pretty much everything, but the only thing we
     * really care about is undoing the implicit conversion to an NT namespaced
     * path that CreateSymbolicLink will perform on absolute paths. If the path
     * is win32-namespaced then the user must have explicitly made it so, and
     * we better just return the unmodified reparse data. */
    if (w_target_len >= 4 &&
        w_target[0] == L'\\' &&
        w_target[1] == L'?' &&
        w_target[2] == L'?' &&
        w_target[3] == L'\\') {
      /* Starts with \??\ */
      if (w_target_len >= 6 &&
          ((w_target[4] >= L'A' && w_target[4] <= L'Z') ||
           (w_target[4] >= L'a' && w_target[4] <= L'z')) &&
          w_target[5] == L':' &&
          (w_target_len == 6 || w_target[6] == L'\\')) {
        /* \??\<drive>:\ */
        w_target += 4;
        w_target_len -= 4;

      } else if (w_target_len >= 8 &&
                 (w_target[4] == L'U' || w_target[4] == L'u') &&
                 (w_target[5] == L'N' || w_target[5] == L'n') &&
                 (w_target[6] == L'C' || w_target[6] == L'c') &&
                 w_target[7] == L'\\') {
        /* \??\UNC\<server>\<share>\ - make sure the final path looks like
         * \\<server>\<share>\ */
        w_target += 6;
        w_target[0] = L'\\';
        w_target_len -= 6;
      }
    }

  } else if (reparse_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
    /* Junction. */
    w_target = reparse_data->MountPointReparseBuffer.PathBuffer +
        (reparse_data->MountPointReparseBuffer.SubstituteNameOffset /
        sizeof(WCHAR));
    w_target_len = reparse_data->MountPointReparseBuffer.SubstituteNameLength /
        sizeof(WCHAR);

    /* Only treat junctions that look like \??\<drive>:\ as symlink. Junctions
     * can also be used as mount points, like \??\Volume{<guid>}, but that's
     * confusing for programs since they wouldn't be able to actually
     * understand such a path when returned by uv_readlink(). UNC paths are
     * never valid for junctions so we don't care about them. */
    if (!(w_target_len >= 6 &&
          w_target[0] == L'\\' &&
          w_target[1] == L'?' &&
          w_target[2] == L'?' &&
          w_target[3] == L'\\' &&
          ((w_target[4] >= L'A' && w_target[4] <= L'Z') ||
           (w_target[4] >= L'a' && w_target[4] <= L'z')) &&
          w_target[5] == L':' &&
          (w_target_len == 6 || w_target[6] == L'\\'))) {
      SetLastError(ERROR_SYMLINK_NOT_SUPPORTED);
      return -1;
    }

    /* Remove leading \??\ */
    w_target += 4;
    w_target_len -= 4;

  } else {
    /* Reparse tag does not indicate a symlink. */
    SetLastError(ERROR_SYMLINK_NOT_SUPPORTED);
    return -1;
  }

  return fs__wide_to_utf8(w_target, w_target_len, target_ptr, target_len_ptr);
}

void fs__open(uv_fs_t* req) {

  /* Adjust flags to be compatible with the memory file mapping. Save the
   * original flags to emulate the correct behavior. */
  auto flags = req->fs.info.file_flags;
  auto fd_info = uv__fd_info_s{};
  if (flags & UV_FS_O_FILEMAP) {
    fd_info.flags = flags;
    fd_info.current_pos.QuadPart = 0;

    if ((flags & (UV_FS_O_RDONLY | UV_FS_O_WRONLY | UV_FS_O_RDWR)) ==
        UV_FS_O_WRONLY) {
      /* CreateFileMapping always needs read access */
      flags = (flags & ~UV_FS_O_WRONLY) | UV_FS_O_RDWR;
    }

    if (flags & UV_FS_O_APPEND) {
      /* Clear the append flag and ensure RDRW mode */
      flags &= ~UV_FS_O_APPEND;
      flags &= ~(UV_FS_O_RDONLY | UV_FS_O_WRONLY | UV_FS_O_RDWR);
      flags |= UV_FS_O_RDWR;
    }
  }

  /* Obtain the active umask. umask() never fails and returns the previous
   * umask. */
  auto current_umask = _umask(0);
  _umask(current_umask);

  /* convert flags and mode to CreateFile parameters */
  auto access = DWORD{};
  switch (flags & (UV_FS_O_RDONLY | UV_FS_O_WRONLY | UV_FS_O_RDWR)) {
  case UV_FS_O_RDONLY:
    access = FILE_GENERIC_READ;
    break;
  case UV_FS_O_WRONLY:
    access = FILE_GENERIC_WRITE;
    break;
  case UV_FS_O_RDWR:
    access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    break;
  default:
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
    return;
  }

  if (flags & UV_FS_O_APPEND) {
    access &= ~FILE_WRITE_DATA;
    access |= FILE_APPEND_DATA;
  }

  /*
   * Here is where we deviate significantly from what CRT's _open()
   * does. We indiscriminately use all the sharing modes, to match
   * UNIX semantics. In particular, this ensures that the file can
   * be deleted even whilst it's open, fixing issue
   * https://github.com/nodejs/node-v0.x-archive/issues/1449.
   * We still support exclusive sharing mode, since it is necessary
   * for opening raw block devices, otherwise Windows will prevent
   * any attempt to write past the master boot record.
   */
  auto share = DWORD{};
  if (flags & UV_FS_O_EXLOCK) {
    share = 0;
  } else {
    share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  }

  auto disposition = DWORD{};
  switch (flags & (UV_FS_O_CREAT | UV_FS_O_EXCL | UV_FS_O_TRUNC)) {
  case 0:
  case UV_FS_O_EXCL:
    disposition = OPEN_EXISTING;
    break;
  case UV_FS_O_CREAT:
    disposition = OPEN_ALWAYS;
    break;
  case UV_FS_O_CREAT | UV_FS_O_EXCL:
  case UV_FS_O_CREAT | UV_FS_O_TRUNC | UV_FS_O_EXCL:
    disposition = CREATE_NEW;
    break;
  case UV_FS_O_TRUNC:
  case UV_FS_O_TRUNC | UV_FS_O_EXCL:
    disposition = TRUNCATE_EXISTING;
    break;
  case UV_FS_O_CREAT | UV_FS_O_TRUNC:
    disposition = CREATE_ALWAYS;
    break;
  default:
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
    return;
  }

  auto attributes = DWORD{0};
  attributes |= FILE_ATTRIBUTE_NORMAL;
  if (flags & UV_FS_O_CREAT) {
    if (!((req->fs.info.mode & ~current_umask) & _S_IWRITE)) {
      attributes |= FILE_ATTRIBUTE_READONLY;
    }
  }

  if (flags & UV_FS_O_TEMPORARY ) {
    attributes |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
    access |= DELETE;
  }

  if (flags & UV_FS_O_SHORT_LIVED) {
    attributes |= FILE_ATTRIBUTE_TEMPORARY;
  }

  switch (flags & (UV_FS_O_SEQUENTIAL | UV_FS_O_RANDOM)) {
  case 0:
    break;
  case UV_FS_O_SEQUENTIAL:
    attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
    break;
  case UV_FS_O_RANDOM:
    attributes |= FILE_FLAG_RANDOM_ACCESS;
    break;
  default:
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
    return;
  }

  if (flags & UV_FS_O_DIRECT) {
    /*
     * FILE_APPEND_DATA and FILE_FLAG_NO_BUFFERING are mutually exclusive.
     * Windows returns 87, ERROR_INVALID_PARAMETER if these are combined.
     *
     * FILE_APPEND_DATA is included in FILE_GENERIC_WRITE:
     *
     * FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE |
     *                      FILE_WRITE_DATA |
     *                      FILE_WRITE_ATTRIBUTES |
     *                      FILE_WRITE_EA |
     *                      FILE_APPEND_DATA |
     *                      SYNCHRONIZE
     *
     * Note: Appends are also permitted by FILE_WRITE_DATA.
     *
     * In order for direct writes and direct appends to succeed, we therefore
     * exclude FILE_APPEND_DATA if FILE_WRITE_DATA is specified, and otherwise
     * fail if the user's sole permission is a direct append, since this
     * particular combination is invalid.
     */
    if (access & FILE_APPEND_DATA) {
      if (access & FILE_WRITE_DATA) {
        access &= ~FILE_APPEND_DATA;
      } else {
        SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
        return;
      }
    }
    attributes |= FILE_FLAG_NO_BUFFERING;
  }

  switch (flags & (UV_FS_O_DSYNC | UV_FS_O_SYNC)) {
  case 0:
    break;
  case UV_FS_O_DSYNC:
  case UV_FS_O_SYNC:
    attributes |= FILE_FLAG_WRITE_THROUGH;
    break;
  default:
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
    return;
  }

  /* Setting this flag makes it possible to open a directory. */
  attributes |= FILE_FLAG_BACKUP_SEMANTICS;

  auto file = CreateFileW(req->file.pathw,
                     access,
                     share,
                     nullptr,
                     disposition,
                     attributes,
                     nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    auto error = GetLastError();
    if (error == ERROR_FILE_EXISTS && (flags & UV_FS_O_CREAT) &&
        !(flags & UV_FS_O_EXCL)) {
      /* Special case: when ERROR_FILE_EXISTS happens and UV_FS_O_CREAT was
       * specified, it means the path referred to a directory. */
      SET_REQ_UV_ERROR(req, UV_EISDIR, error);
    } else {
      SET_REQ_WIN32_ERROR(req, GetLastError());
    }
    return;
  }

  auto fd = _open_osfhandle(reinterpret_cast<intptr_t>(file), flags);
  if (fd < 0) {
    /* The only known failure mode for _open_osfhandle() is EMFILE, in which
     * case GetLastError() will return zero. However we'll try to handle other
     * errors as well, should they ever occur.
     */
    if (errno == EMFILE)
      SET_REQ_UV_ERROR(req, UV_EMFILE, ERROR_TOO_MANY_OPEN_FILES);
    else if (GetLastError() != ERROR_SUCCESS)
      SET_REQ_WIN32_ERROR(req, GetLastError());
    else
      SET_REQ_WIN32_ERROR(req, static_cast<DWORD>(UV_UNKNOWN));
    CloseHandle(file);
    return;
  }

  if (flags & UV_FS_O_FILEMAP) {
    auto file_info = FILE_STANDARD_INFO{};
    if (!GetFileInformationByHandleEx(file,
                                      FileStandardInfo,
                                      &file_info,
                                      sizeof(decltype(file_info)))) {
      SET_REQ_WIN32_ERROR(req, GetLastError());
      CloseHandle(file);
      return;
    }
    fd_info.is_directory = file_info.Directory;

    if (fd_info.is_directory) {
      fd_info.size.QuadPart = 0;
      fd_info.mapping = INVALID_HANDLE_VALUE;
    } else {
      if (!GetFileSizeEx(file, &fd_info.size)) {
        SET_REQ_WIN32_ERROR(req, GetLastError());
        CloseHandle(file);
        return;
      }

      if (fd_info.size.QuadPart == 0) {
        fd_info.mapping = INVALID_HANDLE_VALUE;
      } else {
        auto flProtect = (fd_info.flags & (UV_FS_O_RDONLY | UV_FS_O_WRONLY |
          UV_FS_O_RDWR)) == UV_FS_O_RDONLY ? PAGE_READONLY : PAGE_READWRITE;
        fd_info.mapping = CreateFileMapping(file,
                                            nullptr,
                                            flProtect,
                                            fd_info.size.HighPart,
                                            fd_info.size.LowPart,
                                            nullptr);
        if (fd_info.mapping == nullptr) {
          SET_REQ_WIN32_ERROR(req, GetLastError());
          CloseHandle(file);
          return;
        }
      }
    }

    uv__fd_hash_add(fd, &fd_info);
  }

  SET_REQ_RESULT(req, fd);
  return;
}

void fs__close(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto fd_info = uv__fd_info_s{};
  if (uv__fd_hash_remove(fd, &fd_info)) {
    if (fd_info.mapping != INVALID_HANDLE_VALUE) {
      CloseHandle(fd_info.mapping);
    }
  }

  auto result = int{};
  if (fd > 2)
    result = _close(fd);
  else
    result = 0;

  /* _close doesn't set _doserrno on failure, but it does always set errno
   * to EBADF on failure.
   */
  if (result == -1) {
    assert(errno == EBADF);
    SET_REQ_UV_ERROR(req, UV_EBADF, ERROR_INVALID_HANDLE);
  } else {
    req->result = 0;
  }
}

LONG fs__filemap_ex_filter(LONG excode, PEXCEPTION_POINTERS pep,
                           int* perror) {
  if (excode != EXCEPTION_IN_PAGE_ERROR) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  assert(perror != nullptr);
  if (pep != nullptr && pep->ExceptionRecord != nullptr &&
      pep->ExceptionRecord->NumberParameters >= 3) {
    auto status = static_cast<NTSTATUS>(pep->ExceptionRecord->ExceptionInformation[3]);
    *perror = pRtlNtStatusToDosError(status);
    if (*perror != ERROR_SUCCESS) {
      return EXCEPTION_EXECUTE_HANDLER;
    }
  }
  *perror = UV_UNKNOWN;
  return EXCEPTION_EXECUTE_HANDLER;
}

void fs__read_filemap(uv_fs_t* req, struct uv__fd_info_s* fd_info) {

  auto rw_flags = fd_info->flags &
    (UV_FS_O_RDONLY | UV_FS_O_WRONLY | UV_FS_O_RDWR);
  if (rw_flags == UV_FS_O_WRONLY) {
    SET_REQ_WIN32_ERROR(req, ERROR_ACCESS_DENIED);
    return;
  }
  if (fd_info->is_directory) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_FUNCTION);
    return;
  }

  auto pos = LARGE_INTEGER{};
  if (req->fs.info.offset == -1) {
    pos = fd_info->current_pos;
  } else {
    pos.QuadPart = req->fs.info.offset;
  }

  /* Make sure we wont read past EOF. */
  if (pos.QuadPart >= fd_info->size.QuadPart) {
    SET_REQ_RESULT(req, 0);
    return;
  }

  auto read_size = 0ull;
  for (auto index = 0u; index < req->fs.info.nbufs; ++index) {
    read_size += req->fs.info.bufs[index].len;
  }
  read_size = static_cast<size_t>(MIN(static_cast<LONGLONG>(read_size),
                           fd_info->size.QuadPart - pos.QuadPart));
  if (read_size == 0) {
    SET_REQ_RESULT(req, 0);
    return;
  }

  auto end_pos = LARGE_INTEGER{};
  end_pos.QuadPart = pos.QuadPart + read_size;

  auto view_base = LARGE_INTEGER{};
  auto view_offset = static_cast<size_t>(pos.QuadPart % uv__allocation_granularity);
  view_base.QuadPart = pos.QuadPart - view_offset;
  auto view = MapViewOfFile(fd_info->mapping,
                       FILE_MAP_READ,
                       view_base.HighPart,
                       view_base.LowPart,
                       view_offset + read_size);
  if (view == nullptr) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  auto done_read = 0ull;
  for (auto index = 0u;
       index < req->fs.info.nbufs && done_read < read_size;
       ++index) {
    auto err = 0;
    auto this_read_size = MIN(req->fs.info.bufs[index].len,
                                read_size - done_read);
#ifdef _MSC_VER
    __try {
#endif
      memcpy(req->fs.info.bufs[index].base,
             (char*)view + view_offset + done_read,
             this_read_size);
#ifdef _MSC_VER
    }
    __except (fs__filemap_ex_filter(GetExceptionCode(),
                                    GetExceptionInformation(), &err)) {
      SET_REQ_WIN32_ERROR(req, err);
      UnmapViewOfFile(view);
      return;
    }
#endif
    done_read += this_read_size;
  }
  assert(done_read == read_size);

  if (!UnmapViewOfFile(view)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  if (req->fs.info.offset == -1) {
    fd_info->current_pos = end_pos;
    auto fd = req->file.fd; /* VERIFY_FD done in fs__read */
    uv__fd_hash_add(fd, fd_info);
  }

  SET_REQ_RESULT(req, read_size);
  return;
}

void fs__read(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto fd_info = uv__fd_info_s{};
  if (uv__fd_hash_get(fd, &fd_info)) {
    fs__read_filemap(req, &fd_info);
    return;
  }

  auto handle = uv__get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_HANDLE);
    return;
  }

  auto offset = req->fs.info.offset;
  auto restore_position = 0;
  auto original_position = LARGE_INTEGER{};
  auto overlapped = OVERLAPPED{};
  OVERLAPPED *overlapped_ptr;
  if (offset != -1) {
    memset(&overlapped, 0, sizeof(decltype(overlapped)));
    overlapped_ptr = &overlapped;
    auto zero_offset = LARGE_INTEGER{};
    zero_offset.QuadPart = 0;
    if (SetFilePointerEx(handle, zero_offset, &original_position,
                         FILE_CURRENT)) {
      restore_position = 1;
    }
  } else {
    overlapped_ptr = nullptr;
  }

  auto index = 0u;
  auto bytes = DWORD{0};
  auto result = int{};
  do {

    if (offset != -1) {
      auto offset_ = LARGE_INTEGER{};
      offset_.QuadPart = offset + bytes;
      overlapped.Offset = offset_.LowPart;
      overlapped.OffsetHigh = offset_.HighPart;
    }

    auto incremental_bytes = DWORD{};
    result = ReadFile(handle,
                      req->fs.info.bufs[index].base,
                      req->fs.info.bufs[index].len,
                      &incremental_bytes,
                      overlapped_ptr);
    bytes += incremental_bytes;
    ++index;
  } while (result && index < req->fs.info.nbufs);

  if (restore_position)
    SetFilePointerEx(handle, original_position, nullptr, FILE_BEGIN);

  if (result || bytes > 0) {
    SET_REQ_RESULT(req, bytes);
  } else {
    auto error = GetLastError();
    if (error == ERROR_HANDLE_EOF) {
      SET_REQ_RESULT(req, bytes);
    } else {
      SET_REQ_WIN32_ERROR(req, error);
    }
  }
}

void fs__write_filemap(uv_fs_t* req, HANDLE file,
                       uv__fd_info_s* fd_info) {
  
  auto rw_flags = fd_info->flags &
    (UV_FS_O_RDONLY | UV_FS_O_WRONLY | UV_FS_O_RDWR);
  if (rw_flags == UV_FS_O_RDONLY) {
    SET_REQ_WIN32_ERROR(req, ERROR_ACCESS_DENIED);
    return;
  }
  if (fd_info->is_directory) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_FUNCTION);
    return;
  }

  auto write_size = 0ull;
  for (auto index = 0u; index < req->fs.info.nbufs; ++index) {
    write_size += req->fs.info.bufs[index].len;
  }

  if (write_size == 0) {
    SET_REQ_RESULT(req, 0);
    return;
  }

  auto force_append = fd_info->flags & UV_FS_O_APPEND;
  auto zero = LARGE_INTEGER{};
  auto pos = LARGE_INTEGER{};
  auto end_pos = LARGE_INTEGER{};

  zero.QuadPart = 0;
  if (force_append) {
    pos = fd_info->size;
  } else if (req->fs.info.offset == -1) {
    pos = fd_info->current_pos;
  } else {
    pos.QuadPart = req->fs.info.offset;
  }

  end_pos.QuadPart = pos.QuadPart + write_size;

  /* Recreate the mapping to enlarge the file if needed */
  auto fd = req->file.fd; /* VERIFY_FD done in fs__write */
  if (end_pos.QuadPart > fd_info->size.QuadPart) {
    if (fd_info->mapping != INVALID_HANDLE_VALUE) {
      CloseHandle(fd_info->mapping);
    }

    fd_info->mapping = CreateFileMapping(file,
                                         nullptr,
                                         PAGE_READWRITE,
                                         end_pos.HighPart,
                                         end_pos.LowPart,
                                         nullptr);
    if (fd_info->mapping == nullptr) {
      SET_REQ_WIN32_ERROR(req, GetLastError());
      CloseHandle(file);
      fd_info->mapping = INVALID_HANDLE_VALUE;
      fd_info->size.QuadPart = 0;
      fd_info->current_pos.QuadPart = 0;
      uv__fd_hash_add(fd, fd_info);
      return;
    }

    fd_info->size = end_pos;
    uv__fd_hash_add(fd, fd_info);
  }

  auto view_base = LARGE_INTEGER{};
  auto view_offset = static_cast<size_t>(pos.QuadPart % uv__allocation_granularity);
  view_base.QuadPart = pos.QuadPart - view_offset;
  auto view = MapViewOfFile(fd_info->mapping,
                       FILE_MAP_WRITE,
                       view_base.HighPart,
                       view_base.LowPart,
                       view_offset + write_size);
  if (view == nullptr) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  auto done_write = 0ull;
  for (auto index = 0u; index < req->fs.info.nbufs; ++index) {
    int err = 0;
#ifdef _MSC_VER
    __try {
#endif
      memcpy((char*)view + view_offset + done_write,
             req->fs.info.bufs[index].base,
             req->fs.info.bufs[index].len);
#ifdef _MSC_VER
    }
    __except (fs__filemap_ex_filter(GetExceptionCode(),
                                    GetExceptionInformation(), &err)) {
      SET_REQ_WIN32_ERROR(req, err);
      UnmapViewOfFile(view);
      return;
    }
#endif
    done_write += req->fs.info.bufs[index].len;
  }
  assert(done_write == write_size);

  if (!FlushViewOfFile(view, 0)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    UnmapViewOfFile(view);
    return;
  }
  if (!UnmapViewOfFile(view)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  if (req->fs.info.offset == -1) {
    fd_info->current_pos = end_pos;
    uv__fd_hash_add(fd, fd_info);
  }

  auto ft = FILETIME{};
  GetSystemTimeAsFileTime(&ft);
  SetFileTime(file, nullptr, nullptr, &ft);

  SET_REQ_RESULT(req, done_write);
}

void fs__write(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto handle = uv__get_osfhandle(fd);
  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_HANDLE);
    return;
  }

  auto fd_info = uv__fd_info_s{};
  if (uv__fd_hash_get(fd, &fd_info)) {
    fs__write_filemap(req, handle, &fd_info);
    return;
  }

  auto offset = req->fs.info.offset;
  auto original_position = LARGE_INTEGER{};
  auto restore_position = 0;
  auto zero_offset = LARGE_INTEGER{};
  auto overlapped = OVERLAPPED{};
  OVERLAPPED *overlapped_ptr;

  zero_offset.QuadPart = 0;
  if (offset != -1) {
    memset(&overlapped, 0, sizeof(decltype(overlapped)));
    overlapped_ptr = &overlapped;
    if (SetFilePointerEx(handle, zero_offset, &original_position,
                         FILE_CURRENT)) {
      restore_position = 1;
    }
  } else {
    overlapped_ptr = nullptr;
  }

  auto index = 0u;
  auto bytes = DWORD{0};
  auto result = 0;
  do {

    if (offset != -1) {
      auto offset_ = LARGE_INTEGER{};
      offset_.QuadPart = offset + bytes;
      overlapped.Offset = offset_.LowPart;
      overlapped.OffsetHigh = offset_.HighPart;
    }

    auto incremental_bytes = DWORD{};
    result = WriteFile(handle,
                       req->fs.info.bufs[index].base,
                       req->fs.info.bufs[index].len,
                       &incremental_bytes,
                       overlapped_ptr);
    bytes += incremental_bytes;
    ++index;
  } while (result && index < req->fs.info.nbufs);

  if (restore_position)
    SetFilePointerEx(handle, original_position, nullptr, FILE_BEGIN);

  if (result || bytes > 0) {
    SET_REQ_RESULT(req, bytes);
  } else {
    SET_REQ_WIN32_ERROR(req, GetLastError());
  }
}

void fs__rmdir(uv_fs_t* req) {
  auto result = _wrmdir(req->file.pathw);
  SET_REQ_RESULT(req, result);
}

void fs__unlink(uv_fs_t* req) {

  const auto *pathw = req->file.pathw;
  auto handle = CreateFileW(pathw,
                       FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  auto info = BY_HANDLE_FILE_INFORMATION{};
  if (!GetFileInformationByHandle(handle, &info)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    CloseHandle(handle);
    return;
  }

  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    /* Do not allow deletion of directories, unless it is a symlink. When the
     * path refers to a non-symlink directory, report EPERM as mandated by
     * POSIX.1. */

    /* Check if it is a reparse point. If it's not, it's a normal directory. */
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
      SET_REQ_WIN32_ERROR(req, ERROR_ACCESS_DENIED);
      CloseHandle(handle);
      return;
    }

    /* Read the reparse point and check if it is a valid symlink. If not, don't
     * unlink. */
    if (fs__readlink_handle(handle, nullptr, nullptr) < 0) {
      auto error = GetLastError();
      if (error == ERROR_SYMLINK_NOT_SUPPORTED)
        error = ERROR_ACCESS_DENIED;
      SET_REQ_WIN32_ERROR(req, error);
      CloseHandle(handle);
      return;
    }
  }

  if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
    /* Remove read-only attribute */
    auto basic = FILE_BASIC_INFORMATION{ 0 };
    auto iosb = IO_STATUS_BLOCK{};

    basic.FileAttributes = (info.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY) |
                           FILE_ATTRIBUTE_ARCHIVE;

    auto status = pNtSetInformationFile(handle,
                                   &iosb,
                                   &basic,
                                   sizeof(decltype(basic)),
                                   FileBasicInformation);
    if (!NT_SUCCESS(status)) {
      SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(status));
      CloseHandle(handle);
      return;
    }
  }

  /* Try to set the delete flag. */
  auto disposition = FILE_DISPOSITION_INFORMATION{1};
  auto iosb = IO_STATUS_BLOCK{};
  auto status = pNtSetInformationFile(handle,
                                 &iosb,
                                 &disposition,
                                 sizeof(decltype(disposition)),
                                 FileDispositionInformation);
  if (NT_SUCCESS(status)) {
    SET_REQ_SUCCESS(req);
  } else {
    SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(status));
  }

  CloseHandle(handle);
}

void fs__mkdir(uv_fs_t* req) {
  /* TODO: use req->mode. */
  req->result = _wmkdir(req->file.pathw);
  if (req->result == -1) {
    req->sys_errno_ = _doserrno;
    req->result = req->sys_errno_ == ERROR_INVALID_NAME
                ? UV_EINVAL
                : uv_translate_sys_error(req->sys_errno_);
  }
}

typedef int (*uv__fs_mktemp_func)(uv_fs_t* req);

/* OpenBSD original: lib/libc/stdio/mktemp.c */
void fs__mktemp(uv_fs_t* req, uv__fs_mktemp_func func) {
  static const WCHAR *tempchars =
    L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  static const size_t num_chars = 62;
  static const size_t num_x = 6;

  auto len = wcslen(req->file.pathw);
  auto *ep = req->file.pathw + len;
  if (len < num_x || wcsncmp(ep - num_x, L"XXXXXX", num_x)) {
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_INVALID_PARAMETER);
    return;
  }

  auto tries = static_cast<unsigned int>(TMP_MAX);
  do {
    auto v = uint64_t{};
    if (uv__random_rtlgenrandom(static_cast<void *>(&v), sizeof(decltype(v))) < 0) {
      SET_REQ_UV_ERROR(req, UV_EIO, ERROR_IO_DEVICE);
      break;
    }

    auto *cp = ep - num_x;
    for (auto i = 0u; i < num_x; i++) {
      *cp++ = tempchars[v % num_chars];
      v /= num_chars;
    }

    if (func(req)) {
      if (req->result >= 0) {
        len = strlen(req->path);
        wcstombs((char*) req->path + len - num_x, ep - num_x, num_x);
      }
      break;
    }
  } while (--tries);

  if (tries == 0) {
    SET_REQ_RESULT(req, -1);
  }
}

static int fs__mkdtemp_func(uv_fs_t* req) {
  if (_wmkdir(req->file.pathw) == 0) {
    SET_REQ_RESULT(req, 0);
    return 1;
  } else if (errno != EEXIST) {
    SET_REQ_RESULT(req, -1);
    return 1;
  }

  return 0;
}

void fs__mkdtemp(uv_fs_t* req) {
  fs__mktemp(req, fs__mkdtemp_func);
}

static int fs__mkstemp_func(uv_fs_t* req) {

  auto file = CreateFileW(req->file.pathw,
                     GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     nullptr,
                     CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL,
                     nullptr);

  if (file == INVALID_HANDLE_VALUE) {
    auto error = GetLastError();

    /* If the file exists, the main fs__mktemp() function
       will retry. If it's another error, we want to stop. */
    if (error != ERROR_FILE_EXISTS) {
      SET_REQ_WIN32_ERROR(req, error);
      return 1;
    }

    return 0;
  }

  auto fd = _open_osfhandle(reinterpret_cast<intptr_t>(file), 0);
  if (fd < 0) {
    /* The only known failure mode for _open_osfhandle() is EMFILE, in which
     * case GetLastError() will return zero. However we'll try to handle other
     * errors as well, should they ever occur.
     */
    if (errno == EMFILE)
      SET_REQ_UV_ERROR(req, UV_EMFILE, ERROR_TOO_MANY_OPEN_FILES);
    else if (GetLastError() != ERROR_SUCCESS)
      SET_REQ_WIN32_ERROR(req, GetLastError());
    else
      SET_REQ_WIN32_ERROR(req, UV_UNKNOWN);
    CloseHandle(file);
    return 1;
  }

  SET_REQ_RESULT(req, fd);

  return 1;
}

void fs__mkstemp(uv_fs_t* req) {
  fs__mktemp(req, fs__mkstemp_func);
}

void fs__scandir(uv_fs_t* req) {

  static const size_t dirents_initial_size = 32;
  /* Buffer to hold directory entries returned by NtQueryDirectoryFile.
   * It's important that this buffer can hold at least one entry, regardless
   * of the length of the file names present in the enumerated directory.
   * A file name is at most 256 WCHARs long.
   * According to MSDN, the buffer must be aligned at an 8-byte boundary.
   */
#if _MSC_VER
  __declspec(align(8)) char buffer[8192];
#else
  __attribute__ ((aligned (8))) char buffer[8192];
#endif

  STATIC_ASSERT(sizeof(buffer) >=
                sizeof(FILE_DIRECTORY_INFORMATION) + 256 * sizeof(WCHAR));

  /* Open the directory. */
  auto dir_handle =
      CreateFileW(req->file.pathw,
                  FILE_LIST_DIRECTORY | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr,
                  OPEN_EXISTING,
                  FILE_FLAG_BACKUP_SEMANTICS,
                  nullptr);
  if (dir_handle == INVALID_HANDLE_VALUE){
    SET_REQ_WIN32_ERROR(req, GetLastError());
    if (dir_handle != INVALID_HANDLE_VALUE)
      CloseHandle(dir_handle);
    return;
  }

  /* Read the first chunk. */
  auto iosb = IO_STATUS_BLOCK{};
  auto status = pNtQueryDirectoryFile(dir_handle,
                                 nullptr,
                                 nullptr,
                                 nullptr,
                                 &iosb,
                                 &buffer,
                                 sizeof(buffer),
                                 FileDirectoryInformation,
                                 0,
                                 nullptr,
                                 1);

  /* If the handle is not a directory, we'll get STATUS_INVALID_PARAMETER.
   * This should be reported back as UV_ENOTDIR.
   */
  if (status == STATUS_INVALID_PARAMETER){
    SET_REQ_UV_ERROR(req, UV_ENOTDIR, ERROR_DIRECTORY);
    if (dir_handle != INVALID_HANDLE_VALUE)
      CloseHandle(dir_handle);
    return;
  }

  uv__dirent_t** dirents = nullptr;
  auto dirents_used = 0ull;
  
  while (NT_SUCCESS(status)) {
    char* position = buffer;
    auto next_entry_offset = 0ull;
    auto dirents_size = 0ull;

    do {

      /* Obtain a pointer to the current directory entry. */
      position += next_entry_offset;
      auto info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(position);

      /* Fetch the offset to the next directory entry. */
      next_entry_offset = info->NextEntryOffset;

      /* Compute the length of the filename in WCHARs. */
      auto wchar_len = info->FileNameLength / sizeof info->FileName[0];

      /* Skip over '.' and '..' entries.  It has been reported that
       * the SharePoint driver includes the terminating zero byte in
       * the filename length.  Strip those first.
       */
      while (wchar_len > 0 && info->FileName[wchar_len - 1] == L'\0')
        wchar_len -= 1;

      if (wchar_len == 0)
        continue;
      if (wchar_len == 1 && info->FileName[0] == L'.')
        continue;
      if (wchar_len == 2 && info->FileName[0] == L'.' &&
          info->FileName[1] == L'.')
        continue;

      /* Compute the space required to store the filename as UTF-8. */
      auto utf8_len = static_cast<size_t>(WideCharToMultiByte(
          CP_UTF8, 0, &info->FileName[0], static_cast<int>(wchar_len), nullptr, 0, nullptr, nullptr));
      if (utf8_len == 0){
        SET_REQ_WIN32_ERROR(req, GetLastError());
        if (dir_handle != INVALID_HANDLE_VALUE)
          CloseHandle(dir_handle);
        while (dirents_used > 0)
          uv__free(dirents[--dirents_used]);
        if (dirents != nullptr)
          uv__free(dirents);
        return;
      }

      /* Resize the dirent array if needed. */
      if (dirents_used >= dirents_size) {
        auto new_dirents_size =
            dirents_size == 0 ? dirents_initial_size : dirents_size << 1;
        auto new_dirents =
            create_ptrstruct<uv__dirent_t*>(dirents, new_dirents_size * sizeof(uv__dirent_t*));

        if (new_dirents == nullptr){
          SET_REQ_UV_ERROR(req, UV_ENOMEM, ERROR_OUTOFMEMORY);
          if (dir_handle != INVALID_HANDLE_VALUE)
            CloseHandle(dir_handle);
          while (dirents_used > 0)
            uv__free(dirents[--dirents_used]);
          if (dirents != nullptr)
            uv__free(dirents);
          return;
        }

        dirents_size = new_dirents_size;
        dirents = new_dirents;
      }

      /* Allocate space for the uv dirent structure. The dirent structure
       * includes room for the first character of the filename, but `utf8_len`
       * doesn't count the nullptr terminator at this point.
       */
      auto dirent = create_ptrstruct<uv__dirent_t>(sizeof(uv__dirent_t) + utf8_len);
      if (dirent == nullptr){
        SET_REQ_UV_ERROR(req, UV_ENOMEM, ERROR_OUTOFMEMORY);
        if (dir_handle != INVALID_HANDLE_VALUE)
          CloseHandle(dir_handle);
        while (dirents_used > 0)
          uv__free(dirents[--dirents_used]);
        if (dirents != nullptr)
          uv__free(dirents);
        return;
      }

      dirents[dirents_used++] = dirent;

      /* Convert file name to UTF-8. */
      if (WideCharToMultiByte(CP_UTF8,
                              0,
                              &info->FileName[0],
                              static_cast<int>(wchar_len),
                              &dirent->d_name[0],
                              static_cast<int>(utf8_len),
                              nullptr,
                              nullptr) == 0){
        SET_REQ_WIN32_ERROR(req, GetLastError());
        if (dir_handle != INVALID_HANDLE_VALUE)
          CloseHandle(dir_handle);
        while (dirents_used > 0)
          uv__free(dirents[--dirents_used]);
        if (dirents != nullptr)
          uv__free(dirents);
        return;
      }

      /* Add a null terminator to the filename. */
      dirent->d_name[utf8_len] = '\0';

      /* Fill out the type field. */
      if (info->FileAttributes & FILE_ATTRIBUTE_DEVICE)
        dirent->d_type = UV__DT_CHAR;
      else if (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        dirent->d_type = UV__DT_LINK;
      else if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        dirent->d_type = UV__DT_DIR;
      else
        dirent->d_type = UV__DT_FILE;
    } while (next_entry_offset != 0);

    /* Read the next chunk. */
    status = pNtQueryDirectoryFile(dir_handle,
                                   nullptr,
                                   nullptr,
                                   nullptr,
                                   &iosb,
                                   &buffer,
                                   sizeof(buffer),
                                   FileDirectoryInformation,
                                   FALSE,
                                   nullptr,
                                   FALSE);

    /* After the first pNtQueryDirectoryFile call, the function may return
     * STATUS_SUCCESS even if the buffer was too small to hold at least one
     * directory entry.
     */
    if (status == STATUS_SUCCESS && iosb.Information == 0)
      status = STATUS_BUFFER_OVERFLOW;
  }

  if (status != STATUS_NO_MORE_FILES){
    SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(status));
    if (dir_handle != INVALID_HANDLE_VALUE)
      CloseHandle(dir_handle);
    while (dirents_used > 0)
      uv__free(dirents[--dirents_used]);
    if (dirents != nullptr)
      uv__free(dirents);
    return;
  }

  CloseHandle(dir_handle);

  /* Store the result in the request object. */
  req->ptr = dirents;
  if (dirents != nullptr)
    req->flags |= UV_FS_FREE_PTR;

  SET_REQ_RESULT(req, dirents_used);

  /* `nbufs` will be used as index by uv_fs_scandir_next. */
  req->fs.info.nbufs = 0;

  return;
}

void fs__opendir(uv_fs_t* req) {

  auto pathw = req->file.pathw;

  /* Figure out whether path is a file or a directory. */
  if (!(GetFileAttributesW(pathw) & FILE_ATTRIBUTE_DIRECTORY)) {
    SET_REQ_UV_ERROR(req, UV_ENOTDIR, ERROR_DIRECTORY);
    req->ptr = nullptr;
    return;
  }

  auto dir = create_ptrstruct<uv_dir_t>(sizeof(uv_dir_t));
  if (dir == nullptr) {
    SET_REQ_UV_ERROR(req, UV_ENOMEM, ERROR_OUTOFMEMORY);
    uv__free(dir);
    req->ptr = nullptr;
    return;
  }

  auto len = wcslen(pathw);

  const WCHAR* fmt;
  if (len == 0)
    fmt = L"./*";
  else if (IS_SLASH(pathw[len - 1]))
    fmt = L"%s*";
  else
    fmt = L"%s\\*";

  auto find_path = create_ptrstruct<WCHAR>(sizeof(WCHAR) * (len + 4));
  if (find_path == nullptr) {
    SET_REQ_UV_ERROR(req, UV_ENOMEM, ERROR_OUTOFMEMORY);
    uv__free(dir);
    uv__free(find_path);
    req->ptr = nullptr;
    return;
  }

  _snwprintf(find_path, len + 3, fmt, pathw);
  dir->dir_handle = FindFirstFileW(find_path, &dir->find_data);
  uv__free(find_path);
  find_path = nullptr;
  if (dir->dir_handle == INVALID_HANDLE_VALUE &&
      GetLastError() != ERROR_FILE_NOT_FOUND) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    uv__free(dir);
    uv__free(find_path);
    req->ptr = nullptr;
    return;
  }

  dir->need_find_call = FALSE;
  req->ptr = dir;
  SET_REQ_RESULT(req, 0);
  return;
}

void fs__readdir(uv_fs_t* req) {

  req->flags |= UV_FS_FREE_PTR;
  auto dir = static_cast<uv_dir_t*>(req->ptr);
  auto dirents = dir->dirents;
  memset(dirents, 0, dir->nentries * sizeof(decltype(*dir->dirents)));
  auto find_data = &dir->find_data;

  auto dirent_idx = 0u;
  while (dirent_idx < dir->nentries) {
    if (dir->need_find_call && FindNextFileW(dir->dir_handle, find_data) == 0) {
      if (GetLastError() == ERROR_NO_MORE_FILES)
        break;
      SET_REQ_WIN32_ERROR(req, GetLastError());
      for (auto i = 0u; i < dirent_idx; ++i) {
        uv__free(const_cast<char*>(dirents[i].name));
        dirents[i].name = nullptr;
      }
    }

    /* Skip "." and ".." entries. */
    if (find_data->cFileName[0] == L'.' &&
        (find_data->cFileName[1] == L'\0' ||
        (find_data->cFileName[1] == L'.' &&
        find_data->cFileName[2] == L'\0'))) {
      dir->need_find_call = TRUE;
      continue;
    }

    auto r = uv__convert_utf16_to_utf8(reinterpret_cast<const WCHAR*>(&find_data->cFileName),
                                  -1,
                                  const_cast<char**>(&dirents[dirent_idx].name));
    if (r != 0){
      SET_REQ_WIN32_ERROR(req, GetLastError());
      for (auto i = 0u; i < dirent_idx; ++i) {
        uv__free(const_cast<char*>(dirents[i].name));
        dirents[i].name = nullptr;
      }
    }

    /* Copy file type. */
    auto dent = uv__dirent_t{};
    if ((find_data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
      dent.d_type = UV__DT_DIR;
    else if ((find_data->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      dent.d_type = UV__DT_LINK;
    else if ((find_data->dwFileAttributes & FILE_ATTRIBUTE_DEVICE) != 0)
      dent.d_type = UV__DT_CHAR;
    else
      dent.d_type = UV__DT_FILE;

    dirents[dirent_idx].type = uv__fs_get_dirent_type(&dent);
    dir->need_find_call = TRUE;
    ++dirent_idx;
  }

  SET_REQ_RESULT(req, dirent_idx);
  return;
}

void fs__closedir(uv_fs_t* req) {

  auto dir = static_cast<uv_dir_t*>(req->ptr);
  FindClose(dir->dir_handle);
  uv__free(req->ptr);
  SET_REQ_RESULT(req, 0);
}

INLINE static int fs__stat_handle(HANDLE handle, uv_stat_t* statbuf,
    int do_lstat) {

  auto io_status = IO_STATUS_BLOCK{};
  auto file_info = FILE_ALL_INFORMATION{};
  auto nt_status = pNtQueryInformationFile(handle,
                                      &io_status,
                                      &file_info,
                                      sizeof(decltype(file_info)),
                                      FileAllInformation);

  /* Buffer overflow (a warning status code) is expected here. */
  if (NT_ERROR(nt_status)) {
    SetLastError(pRtlNtStatusToDosError(nt_status));
    return -1;
  }

  auto volume_info = FILE_FS_VOLUME_INFORMATION{};
  nt_status = pNtQueryVolumeInformationFile(handle,
                                            &io_status,
                                            &volume_info,
                                            sizeof(decltype(volume_info)),
                                            FileFsVolumeInformation);

  /* Buffer overflow (a warning status code) is expected here. */
  if (io_status.Status == STATUS_NOT_IMPLEMENTED) {
    statbuf->st_dev = 0;
  } else if (NT_ERROR(nt_status)) {
    SetLastError(pRtlNtStatusToDosError(nt_status));
    return -1;
  } else {
    statbuf->st_dev = volume_info.VolumeSerialNumber;
  }

  /* Todo: st_mode should probably always be 0666 for everyone. We might also
   * want to report 0777 if the file is a .exe or a directory.
   *
   * Currently it's based on whether the 'readonly' attribute is set, which
   * makes little sense because the semantics are so different: the 'read-only'
   * flag is just a way for a user to protect against accidental deletion, and
   * serves no security purpose. Windows uses ACLs for that.
   *
   * Also people now use uv_fs_chmod() to take away the writable bit for good
   * reasons. Windows however just makes the file read-only, which makes it
   * impossible to delete the file afterwards, since read-only files can't be
   * deleted.
   *
   * IOW it's all just a clusterfuck and we should think of something that
   * makes slightly more sense.
   *
   * And uv_fs_chmod should probably just fail on windows or be a total no-op.
   * There's nothing sensible it can do anyway.
   */
  statbuf->st_mode = 0;

  /*
  * On Windows, FILE_ATTRIBUTE_REPARSE_POINT is a general purpose mechanism
  * by which filesystem drivers can intercept and alter file system requests.
  *
  * The only reparse points we care about are symlinks and mount points, both
  * of which are treated as POSIX symlinks. Further, we only care when
  * invoked via lstat, which seeks information about the link instead of its
  * target. Otherwise, reparse points must be treated as regular files.
  */
  if (do_lstat &&
      (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    /*
     * If reading the link fails, the reparse point is not a symlink and needs
     * to be treated as a regular file. The higher level lstat function will
     * detect this failure and retry without do_lstat if appropriate.
     */
    if (fs__readlink_handle(handle, nullptr, &statbuf->st_size) != 0)
      return -1;
    statbuf->st_mode |= S_IFLNK;
  }

  if (statbuf->st_mode == 0) {
    if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      statbuf->st_mode |= _S_IFDIR;
      statbuf->st_size = 0;
    } else {
      statbuf->st_mode |= _S_IFREG;
      statbuf->st_size = file_info.StandardInformation.EndOfFile.QuadPart;
    }
  }

  if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_READONLY)
    statbuf->st_mode |= _S_IREAD | (_S_IREAD >> 3) | (_S_IREAD >> 6);
  else
    statbuf->st_mode |= (_S_IREAD | _S_IWRITE) | ((_S_IREAD | _S_IWRITE) >> 3) |
                        ((_S_IREAD | _S_IWRITE) >> 6);

  FILETIME_TO_TIMESPEC(statbuf->st_atim, file_info.BasicInformation.LastAccessTime);
  FILETIME_TO_TIMESPEC(statbuf->st_ctim, file_info.BasicInformation.ChangeTime);
  FILETIME_TO_TIMESPEC(statbuf->st_mtim, file_info.BasicInformation.LastWriteTime);
  FILETIME_TO_TIMESPEC(statbuf->st_birthtim, file_info.BasicInformation.CreationTime);

  statbuf->st_ino = file_info.InternalInformation.IndexNumber.QuadPart;

  /* st_blocks contains the on-disk allocation size in 512-byte units. */
  statbuf->st_blocks =
      static_cast<uint64_t>(file_info.StandardInformation.AllocationSize.QuadPart >> 9);

  statbuf->st_nlink = file_info.StandardInformation.NumberOfLinks;

  /* The st_blksize is supposed to be the 'optimal' number of bytes for reading
   * and writing to the disk. That is, for any definition of 'optimal' - it's
   * supposed to at least avoid read-update-write behavior when writing to the
   * disk.
   *
   * However nobody knows this and even fewer people actually use this value,
   * and in order to fill it out we'd have to make another syscall to query the
   * volume for FILE_FS_SECTOR_SIZE_INFORMATION.
   *
   * Therefore we'll just report a sensible value that's quite commonly okay
   * on modern hardware.
   *
   * 4096 is the minimum required to be compatible with newer Advanced Format
   * drives (which have 4096 bytes per physical sector), and to be backwards
   * compatible with older drives (which have 512 bytes per physical sector).
   */
  statbuf->st_blksize = 4096;

  /* Todo: set st_flags to something meaningful. Also provide a wrapper for
   * chattr(2).
   */
  statbuf->st_flags = 0;

  /* Windows has nothing sensible to say about these values, so they'll just
   * remain empty.
   */
  statbuf->st_gid = 0;
  statbuf->st_uid = 0;
  statbuf->st_rdev = 0;
  statbuf->st_gen = 0;

  return 0;
}

INLINE static void fs__stat_prepare_path(WCHAR* pathw) {
  auto len = wcslen(pathw);

  /* TODO: ignore namespaced paths. */
  if (len > 1 && pathw[len - 2] != L':' &&
      (pathw[len - 1] == L'\\' || pathw[len - 1] == L'/')) {
    pathw[len - 1] = '\0';
  }
}

INLINE static DWORD fs__stat_impl_from_path(WCHAR* path,
                                            int do_lstat,
                                            uv_stat_t* statbuf) {

  auto flags = static_cast<DWORD>(FILE_FLAG_BACKUP_SEMANTICS);
  if (do_lstat)
    flags |= FILE_FLAG_OPEN_REPARSE_POINT;

  auto handle = CreateFileW(path,
                       FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr,
                       OPEN_EXISTING,
                       flags,
                       nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    CloseHandle(handle);
    return GetLastError();
  }
  else if (fs__stat_handle(handle, statbuf, do_lstat) != 0) {
    CloseHandle(handle);
    return GetLastError();
  }
  else {
    CloseHandle(handle);
    return GetLastError();
  }
}

INLINE static void fs__stat_impl(uv_fs_t* req, int do_lstat) {

  auto error = fs__stat_impl_from_path(req->file.pathw, do_lstat, &req->statbuf);
  if (error != 0) {
    if (do_lstat &&
        (error == ERROR_SYMLINK_NOT_SUPPORTED ||
         error == ERROR_NOT_A_REPARSE_POINT)) {
      /* We opened a reparse point but it was not a symlink. Try again. */
      fs__stat_impl(req, 0);
    } else {
      /* Stat failed. */
      SET_REQ_WIN32_ERROR(req, error);
    }

    return;
  }

  req->ptr = &req->statbuf;
  req->result = 0;
}

static void fs__stat(uv_fs_t* req) {
  fs__stat_prepare_path(req->file.pathw);
  fs__stat_impl(req, 0);
}

static void fs__lstat(uv_fs_t* req) {
  fs__stat_prepare_path(req->file.pathw);
  fs__stat_impl(req, 1);
}

static void fs__fstat(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto handle = uv__get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_HANDLE);
    return;
  }

  if (fs__stat_handle(handle, &req->statbuf, 0) != 0) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  req->ptr = &req->statbuf;
  req->result = 0;
}

static void fs__rename(uv_fs_t* req) {
  if (!MoveFileExW(req->file.pathw, req->fs.info.new_pathw, MOVEFILE_REPLACE_EXISTING)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  SET_REQ_RESULT(req, 0);
}

INLINE static void fs__sync_impl(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto result = FlushFileBuffers(uv__get_osfhandle(fd)) ? 0 : -1;
  if (result == -1) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
  } else {
    SET_REQ_RESULT(req, result);
  }
}

static void fs__fsync(uv_fs_t* req) {
  fs__sync_impl(req);
}

static void fs__fdatasync(uv_fs_t* req) {
  fs__sync_impl(req);
}

static void fs__ftruncate(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto handle = uv__get_osfhandle(fd);

  auto fd_info = uv__fd_info_s{ 0 };
  if (uv__fd_hash_get(fd, &fd_info)) {
    if (fd_info.is_directory) {
      SET_REQ_WIN32_ERROR(req, ERROR_ACCESS_DENIED);
      return;
    }

    if (fd_info.mapping != INVALID_HANDLE_VALUE) {
      CloseHandle(fd_info.mapping);
    }
  }

  auto eof_info = FILE_END_OF_FILE_INFORMATION{};
  eof_info.EndOfFile.QuadPart = req->fs.info.offset;

  auto io_status = IO_STATUS_BLOCK{};
  auto status = pNtSetInformationFile(handle,
                                 &io_status,
                                 &eof_info,
                                 sizeof eof_info,
                                 FileEndOfFileInformation);

  if (NT_SUCCESS(status)) {
    SET_REQ_RESULT(req, 0);
  } else {
    SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(status));

    if (fd_info.flags) {
      CloseHandle(handle);
      fd_info.mapping = INVALID_HANDLE_VALUE;
      fd_info.size.QuadPart = 0;
      fd_info.current_pos.QuadPart = 0;
      uv__fd_hash_add(fd, &fd_info);
      return;
    }
  }

  if (fd_info.flags) {
    fd_info.size = eof_info.EndOfFile;

    if (fd_info.size.QuadPart == 0) {
      fd_info.mapping = INVALID_HANDLE_VALUE;
    } else {
      auto flProtect = (fd_info.flags & (UV_FS_O_RDONLY | UV_FS_O_WRONLY |
        UV_FS_O_RDWR)) == UV_FS_O_RDONLY ? PAGE_READONLY : PAGE_READWRITE;
      fd_info.mapping = CreateFileMapping(handle,
                                          nullptr,
                                          flProtect,
                                          fd_info.size.HighPart,
                                          fd_info.size.LowPart,
                                          nullptr);
      if (fd_info.mapping == nullptr) {
        SET_REQ_WIN32_ERROR(req, GetLastError());
        CloseHandle(handle);
        fd_info.mapping = INVALID_HANDLE_VALUE;
        fd_info.size.QuadPart = 0;
        fd_info.current_pos.QuadPart = 0;
        uv__fd_hash_add(fd, &fd_info);
        return;
      }
    }

    uv__fd_hash_add(fd, &fd_info);
  }
}

static void fs__copyfile(uv_fs_t* req) {

  auto flags = req->fs.info.file_flags;
  if (flags & UV_FS_COPYFILE_FICLONE_FORCE) {
    SET_REQ_UV_ERROR(req, UV_ENOSYS, ERROR_NOT_SUPPORTED);
    return;
  }

  auto overwrite = flags & UV_FS_COPYFILE_EXCL;
  if (CopyFileW(req->file.pathw, req->fs.info.new_pathw, overwrite) != 0) {
    SET_REQ_RESULT(req, 0);
    return;
  }

  SET_REQ_WIN32_ERROR(req, GetLastError());
  if (req->result != UV_EBUSY)
    return;

  /* if error UV_EBUSY check if src and dst file are the same */
  auto statbuf = uv_stat_t{};
  auto new_statbuf = uv_stat_t{};
  if (fs__stat_impl_from_path(req->file.pathw, 0, &statbuf) != 0 ||
      fs__stat_impl_from_path(req->fs.info.new_pathw, 0, &new_statbuf) != 0) {
    return;
  }

  if (statbuf.st_dev == new_statbuf.st_dev &&
      statbuf.st_ino == new_statbuf.st_ino) {
    SET_REQ_RESULT(req, 0);
  }
}

static void fs__sendfile(uv_fs_t* req) {
  const size_t max_buf_size = 65536;

  auto length = req->fs.info.bufsml[0].len;
  auto buf_size = length < max_buf_size ? length : max_buf_size;
  auto *buf = (char*) uv__malloc(buf_size);
  if (!buf) {
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
  }

  auto result_offset = 0ll;
  auto offset = req->fs.info.offset;
  auto fd_in = req->file.fd, fd_out = req->fs.info.fd_out;
  if (offset != -1) {
    result_offset = _lseeki64(fd_in, offset, SEEK_SET);
  }

  auto result = 0;
  if (result_offset == -1) {
    result = -1;
  } else {
    while (length > 0) {
      auto n = _read(fd_in, buf, static_cast<unsigned int>(length < buf_size ? length : buf_size));
      if (n == 0) {
        break;
      } else if (n == -1) {
        result = -1;
        break;
      }

      length -= n;

      n = _write(fd_out, buf, n);
      if (n == -1) {
        result = -1;
        break;
      }

      result += n;
    }
  }

  uv__free(buf);

  SET_REQ_RESULT(req, result);
}

static void fs__access(uv_fs_t* req) {
  auto attr = GetFileAttributesW(req->file.pathw);

  if (attr == INVALID_FILE_ATTRIBUTES) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  /*
   * Access is possible if
   * - write access wasn't requested,
   * - or the file isn't read-only,
   * - or it's a directory.
   * (Directories cannot be read-only on Windows.)
   */
  if (!(req->fs.info.mode & W_OK) ||
      !(attr & FILE_ATTRIBUTE_READONLY) ||
      (attr & FILE_ATTRIBUTE_DIRECTORY)) {
    SET_REQ_RESULT(req, 0);
  } else {
    SET_REQ_WIN32_ERROR(req, UV_EPERM);
  }

}

static void fs__chmod(uv_fs_t* req) {
  auto result = _wchmod(req->file.pathw, req->fs.info.mode);
  SET_REQ_RESULT(req, result);
}

static void fs__fchmod(uv_fs_t* req) {

  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto handle = ReOpenFile(uv__get_osfhandle(fd), FILE_WRITE_ATTRIBUTES, 0, 0);
  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  auto io_status = IO_STATUS_BLOCK{};
  auto file_info = FILE_BASIC_INFORMATION{};
  auto nt_status = pNtQueryInformationFile(handle,
                                      &io_status,
                                      &file_info,
                                      sizeof(decltype(file_info)),
                                      FileBasicInformation);

  if (!NT_SUCCESS(nt_status)) {
    SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(nt_status));
        
    CloseHandle(handle);
    return;
  }

  auto clear_archive_flag = int{};
  /* Test if the Archive attribute is cleared */
  if ((file_info.FileAttributes & FILE_ATTRIBUTE_ARCHIVE) == 0) {
      /* Set Archive flag, otherwise setting or clearing the read-only
         flag will not work */
      file_info.FileAttributes |= FILE_ATTRIBUTE_ARCHIVE;
      nt_status = pNtSetInformationFile(handle,
                                        &io_status,
                                        &file_info,
                                        sizeof(decltype(file_info)),
                                        FileBasicInformation);
      if (!NT_SUCCESS(nt_status)) {
        SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(nt_status));
        
        CloseHandle(handle);
        return;
      }
      /* Remeber to clear the flag later on */
      clear_archive_flag = 1;
  } else {
      clear_archive_flag = 0;
  }

  if (req->fs.info.mode & _S_IWRITE) {
    file_info.FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
  } else {
    file_info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
  }

  nt_status = pNtSetInformationFile(handle,
                                    &io_status,
                                    &file_info,
                                    sizeof(decltype(file_info)),
                                    FileBasicInformation);

  if (!NT_SUCCESS(nt_status)) {
    SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(nt_status));
        
    CloseHandle(handle);
    return;
  }

  if (clear_archive_flag) {
      file_info.FileAttributes &= ~FILE_ATTRIBUTE_ARCHIVE;
      if (file_info.FileAttributes == 0) {
          file_info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
      }
      nt_status = pNtSetInformationFile(handle,
                                        &io_status,
                                        &file_info,
                                        sizeof(decltype(file_info)),
                                        FileBasicInformation);
      if (!NT_SUCCESS(nt_status)) {
        SET_REQ_WIN32_ERROR(req, pRtlNtStatusToDosError(nt_status));

        CloseHandle(handle);
        return;
      }
  }

  SET_REQ_SUCCESS(req);
  CloseHandle(handle);
}

INLINE static int fs__utime_handle(HANDLE handle, double atime, double mtime) {
  auto filetime_a = FILETIME{};
  auto filetime_m = FILETIME{};

  TIME_T_TO_FILETIME(atime, &filetime_a);
  TIME_T_TO_FILETIME(mtime, &filetime_m);

  if (!SetFileTime(handle, nullptr, &filetime_a, &filetime_m)) {
    return -1;
  }

  return 0;
}

static void fs__utime(uv_fs_t* req) {

  auto handle = CreateFileW(req->file.pathw,
                       FILE_WRITE_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  if (fs__utime_handle(handle, req->fs.time.atime, req->fs.time.mtime) != 0) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    CloseHandle(handle);
    return;
  }

  CloseHandle(handle);

  req->result = 0;
}

static void fs__futime(uv_fs_t* req) {
  auto fd = req->file.fd;
  VERIFY_FD(fd, req);

  auto handle = uv__get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, ERROR_INVALID_HANDLE);
    return;
  }

  if (fs__utime_handle(handle, req->fs.time.atime, req->fs.time.mtime) != 0) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  req->result = 0;
}

static void fs__link(uv_fs_t* req) {
  auto r = CreateHardLinkW(req->fs.info.new_pathw, req->file.pathw, nullptr);
  if (r == 0) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
  } else {
    req->result = 0;
  }
}

static void fs__create_junction(uv_fs_t* req, const WCHAR* path,
    const WCHAR* new_path) {

  auto target_len = wcslen(path);
  auto is_long_path = wcsncmp(path, LONG_PATH_PREFIX, LONG_PATH_PREFIX_LEN) == 0;
  auto is_absolute = int{};

  if (is_long_path) {
    is_absolute = 1;
  } else {
    is_absolute = target_len >= 3 && IS_LETTER(path[0]) &&
      path[1] == L':' && IS_SLASH(path[2]);
  }

  if (!is_absolute) {
    /* Not supporting relative paths */
    SET_REQ_UV_ERROR(req, UV_EINVAL, ERROR_NOT_SUPPORTED);
    return;
  }

  /* Do a pessimistic calculation of the required buffer size */
  auto needed_buf_size =
      FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
      JUNCTION_PREFIX_LEN * sizeof(WCHAR) +
      2 * (target_len + 2) * sizeof(WCHAR);

  /* Allocate the buffer */
  auto buffer = (REPARSE_DATA_BUFFER*)uv__malloc(needed_buf_size);
  if (!buffer) {
    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
  }

  /* Grab a pointer to the part of the buffer where filenames go */
  auto path_buf = (WCHAR*)&(buffer->MountPointReparseBuffer.PathBuffer);
  auto path_buf_len = 0;

  /* Copy the substitute (internal) target path */
  auto start = path_buf_len;

  wcsncpy((WCHAR*)&path_buf[path_buf_len], JUNCTION_PREFIX,
    JUNCTION_PREFIX_LEN);
  path_buf_len += JUNCTION_PREFIX_LEN;

  auto add_slash = 0;
  for (auto i = is_long_path ? LONG_PATH_PREFIX_LEN : 0; path[i] != L'\0'; i++) {
    if (IS_SLASH(path[i])) {
      add_slash = 1;
      continue;
    }

    if (add_slash) {
      path_buf[path_buf_len++] = L'\\';
      add_slash = 0;
    }

    path_buf[path_buf_len++] = path[i];
  }
  path_buf[path_buf_len++] = L'\\';
  auto len = path_buf_len - start;

  /* Set the info about the substitute name */
  buffer->MountPointReparseBuffer.SubstituteNameOffset = static_cast<decltype(
                                buffer->MountPointReparseBuffer.SubstituteNameOffset)>(start * sizeof(WCHAR));
  buffer->MountPointReparseBuffer.SubstituteNameLength = static_cast<decltype(
                                buffer->MountPointReparseBuffer.SubstituteNameLength)>(len * sizeof(WCHAR));

  /* Insert null terminator */
  path_buf[path_buf_len++] = L'\0';

  /* Copy the print name of the target path */
  start = path_buf_len;
  add_slash = 0;
  for (auto i = is_long_path ? LONG_PATH_PREFIX_LEN : 0; path[i] != L'\0'; i++) {
    if (IS_SLASH(path[i])) {
      add_slash = 1;
      continue;
    }

    if (add_slash) {
      path_buf[path_buf_len++] = L'\\';
      add_slash = 0;
    }

    path_buf[path_buf_len++] = path[i];
  }
  len = path_buf_len - start;
  if (len == 2) {
    path_buf[path_buf_len++] = L'\\';
    len++;
  }

  /* Set the info about the print name */
  buffer->MountPointReparseBuffer.PrintNameOffset = static_cast<decltype(
                                      buffer->MountPointReparseBuffer.PrintNameOffset)>(start * sizeof(WCHAR));
  buffer->MountPointReparseBuffer.PrintNameLength = static_cast<decltype(
                                      buffer->MountPointReparseBuffer.PrintNameLength)>(len * sizeof(WCHAR));

  /* Insert another null terminator */
  path_buf[path_buf_len++] = L'\0';

  /* Calculate how much buffer space was actually used */
  auto used_buf_size = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
    path_buf_len * sizeof(WCHAR);
  auto used_data_size = used_buf_size -
    FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer);

  /* Put general info in the data buffer */
  buffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
  buffer->ReparseDataLength = static_cast<decltype(buffer->ReparseDataLength)>(used_data_size);
  buffer->Reserved = 0;

  /* Create a new directory */
  bool created = false;
  if (!CreateDirectoryW(new_path, nullptr)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());

    uv__free(buffer);
  }
  created = true;

  /* Open the directory */
  auto handle = CreateFileW(new_path,
                       GENERIC_WRITE,
                       0,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS |
                         FILE_FLAG_OPEN_REPARSE_POINT,
                       nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());

    uv__free(buffer);
    if (handle != INVALID_HANDLE_VALUE) {
      CloseHandle(handle);
    }
    if (created) {
      RemoveDirectoryW(new_path);
    }
  }

  /* Create the actual reparse point */
  auto bytes = DWORD{};
  if (!DeviceIoControl(handle,
                       FSCTL_SET_REPARSE_POINT,
                       buffer,
                       static_cast<DWORD>(used_buf_size),
                       nullptr,
                       0,
                       &bytes,
                       nullptr)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    
    uv__free(buffer);
    if (handle != INVALID_HANDLE_VALUE) {
      CloseHandle(handle);
    }
    if (created) {
      RemoveDirectoryW(new_path);
    }
  }

  /* Clean up */
  CloseHandle(handle);
  uv__free(buffer);

  SET_REQ_RESULT(req, 0);
  return;
}

static void fs__symlink(uv_fs_t* req) {

  auto pathw = req->file.pathw;
  auto new_pathw = req->fs.info.new_pathw;

  if (req->fs.info.file_flags & UV_FS_SYMLINK_JUNCTION) {
    fs__create_junction(req, pathw, new_pathw);
    return;
  }

  auto flags = int{};
  if (req->fs.info.file_flags & UV_FS_SYMLINK_DIR)
    flags = SYMBOLIC_LINK_FLAG_DIRECTORY | uv__file_symlink_usermode_flag;
  else
    flags = uv__file_symlink_usermode_flag;

  if (CreateSymbolicLinkW(new_pathw, pathw, flags)) {
    SET_REQ_RESULT(req, 0);
    return;
  }

  /* Something went wrong. We will test if it is because of user-mode
   * symlinks.
   */
  auto err = GetLastError();
  if (err == ERROR_INVALID_PARAMETER &&
      flags & SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) {
    /* This system does not support user-mode symlinks. We will clear the
     * unsupported flag and retry.
     */
    uv__file_symlink_usermode_flag = 0;
    fs__symlink(req);
  } else {
    SET_REQ_WIN32_ERROR(req, err);
  }
}

static void fs__readlink(uv_fs_t* req) {

  auto handle = CreateFileW(req->file.pathw,
                       0,
                       0,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  if (fs__readlink_handle(handle, reinterpret_cast<char**>(&req->ptr), nullptr) != 0) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    CloseHandle(handle);
    return;
  }

  req->flags |= UV_FS_FREE_PTR;
  SET_REQ_RESULT(req, 0);

  CloseHandle(handle);
}

static ssize_t fs__realpath_handle(HANDLE handle, char** realpath_ptr) {

  auto w_realpath_len = GetFinalPathNameByHandleW(handle, nullptr, 0, VOLUME_NAME_DOS);
  if (w_realpath_len == 0) {
    return -1;
  }

  auto w_realpath_buf = create_ptrstruct<WCHAR>((w_realpath_len + 1) * sizeof(WCHAR));
  if (w_realpath_buf == nullptr) {
    SetLastError(ERROR_OUTOFMEMORY);
    return -1;
  }
  auto w_realpath_ptr = w_realpath_buf;

  if (GetFinalPathNameByHandleW(
          handle, w_realpath_ptr, w_realpath_len, VOLUME_NAME_DOS) == 0) {
    uv__free(w_realpath_buf);
    SetLastError(ERROR_INVALID_HANDLE);
    return -1;
  }

  /* convert UNC path to long path */
  if (wcsncmp(w_realpath_ptr,
              UNC_PATH_PREFIX,
              UNC_PATH_PREFIX_LEN) == 0) {
    w_realpath_ptr += 6;
    *w_realpath_ptr = L'\\';
    w_realpath_len -= 6;
  } else if (wcsncmp(w_realpath_ptr,
                      LONG_PATH_PREFIX,
                      LONG_PATH_PREFIX_LEN) == 0) {
    w_realpath_ptr += 4;
    w_realpath_len -= 4;
  } else {
    uv__free(w_realpath_buf);
    SetLastError(ERROR_INVALID_HANDLE);
    return -1;
  }

  auto r = fs__wide_to_utf8(w_realpath_ptr, w_realpath_len, realpath_ptr, nullptr);
  uv__free(w_realpath_buf);
  return r;
}

static void fs__realpath(uv_fs_t* req) {

  auto handle = CreateFileW(req->file.pathw,
                       0,
                       0,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  if (fs__realpath_handle(handle, reinterpret_cast<char**>(&req->ptr)) == -1) {
    CloseHandle(handle);
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  CloseHandle(handle);
  req->flags |= UV_FS_FREE_PTR;
  SET_REQ_RESULT(req, 0);
}

static void fs__chown(uv_fs_t* req) {
  req->result = 0;
}

static void fs__fchown(uv_fs_t* req) {
  req->result = 0;
}

static void fs__lchown(uv_fs_t* req) {
  req->result = 0;
}

static void fs__statfs(uv_fs_t* req) {

  auto sectors_per_cluster = DWORD{};
  auto bytes_per_sector = DWORD{};
  auto free_clusters = DWORD{};
  auto total_clusters = DWORD{};
  if (0 == GetDiskFreeSpaceW(req->file.pathw,
                             &sectors_per_cluster,
                             &bytes_per_sector,
                             &free_clusters,
                             &total_clusters)) {
    SET_REQ_WIN32_ERROR(req, GetLastError());
    return;
  }

  auto *stat_fs = create_ptrstruct<uv_statfs_t>(sizeof(uv_statfs_t));
  if (stat_fs == nullptr) {
    SET_REQ_UV_ERROR(req, UV_ENOMEM, ERROR_OUTOFMEMORY);
    return;
  }

  stat_fs->f_type = 0;
  stat_fs->f_bsize = bytes_per_sector * sectors_per_cluster;
  stat_fs->f_blocks = total_clusters;
  stat_fs->f_bfree = free_clusters;
  stat_fs->f_bavail = free_clusters;
  stat_fs->f_files = 0;
  stat_fs->f_ffree = 0;
  req->ptr = stat_fs;
  req->flags |= UV_FS_FREE_PTR;
  SET_REQ_RESULT(req, 0);
}

static void uv__fs_work(struct uv__work* w) {
  auto req = container_of(w, uv_fs_t, work_req);
  assert(req->type == UV_FS);

#define XX(uc, lc)  case UV_FS_##uc: fs__##lc(req); break;
  switch (req->fs_type) {
    XX(OPEN, open)
    XX(CLOSE, close)
    XX(READ, read)
    XX(WRITE, write)
    XX(COPYFILE, copyfile)
    XX(SENDFILE, sendfile)
    XX(STAT, stat)
    XX(LSTAT, lstat)
    XX(FSTAT, fstat)
    XX(FTRUNCATE, ftruncate)
    XX(UTIME, utime)
    XX(FUTIME, futime)
    XX(ACCESS, access)
    XX(CHMOD, chmod)
    XX(FCHMOD, fchmod)
    XX(FSYNC, fsync)
    XX(FDATASYNC, fdatasync)
    XX(UNLINK, unlink)
    XX(RMDIR, rmdir)
    XX(MKDIR, mkdir)
    XX(MKDTEMP, mkdtemp)
    XX(MKSTEMP, mkstemp)
    XX(RENAME, rename)
    XX(SCANDIR, scandir)
    XX(READDIR, readdir)
    XX(OPENDIR, opendir)
    XX(CLOSEDIR, closedir)
    XX(LINK, link)
    XX(SYMLINK, symlink)
    XX(READLINK, readlink)
    XX(REALPATH, realpath)
    XX(CHOWN, chown)
    XX(FCHOWN, fchown)
    XX(LCHOWN, lchown)
    XX(STATFS, statfs)
    default:
      assert(!"bad uv_fs_type");
  }
}

static void uv__fs_done(struct uv__work* w, int status) {

  auto req = container_of(w, uv_fs_t, work_req);
  uv__req_unregister(req->loop, req);

  if (status == UV_ECANCELED) {
    assert(req->result == 0);
    req->result = UV_ECANCELED;
  }

  req->cb(req);
}

void uv_fs_req_cleanup(uv_fs_t* req) {
  if (req == nullptr)
    return;

  if (req->flags & UV_FS_CLEANEDUP)
    return;

  if (req->flags & UV_FS_FREE_PATHS)
    uv__free(req->file.pathw);

  if (req->flags & UV_FS_FREE_PTR) {
    if (req->fs_type == UV_FS_SCANDIR && req->ptr != nullptr)
      uv__fs_scandir_cleanup(req);
    else if (req->fs_type == UV_FS_READDIR)
      uv__fs_readdir_cleanup(req);
    else
      uv__free(req->ptr);
  }

  if (req->fs.info.bufs != req->fs.info.bufsml)
    uv__free(req->fs.info.bufs);

  req->path = nullptr;
  req->file.pathw = nullptr;
  req->fs.info.new_pathw = nullptr;
  req->fs.info.bufs = nullptr;
  req->ptr = nullptr;

  req->flags |= UV_FS_CLEANEDUP;
}

int uv_fs_open(uv_loop_t* loop, uv_fs_t* req, const char* path, int flags,
    int mode, uv_fs_cb cb) {

  INIT(UV_FS_OPEN);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.info.file_flags = flags;
  req->fs.info.mode = mode;
  POST(int);
}

int uv_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  INIT(UV_FS_CLOSE);
  req->file.fd = fd;
  POST(int);
}

int uv_fs_read(uv_loop_t* loop,
               uv_fs_t* req,
               uv_file fd,
               const uv_buf_t bufs[],
               unsigned int nbufs,
               int64_t offset,
               uv_fs_cb cb) {
  INIT(UV_FS_READ);

  if (bufs == nullptr || nbufs == 0)
    return UV_EINVAL;

  req->file.fd = fd;

  req->fs.info.nbufs = nbufs;
  req->fs.info.bufs = req->fs.info.bufsml;
  if (nbufs > ARRAY_SIZE(req->fs.info.bufsml))
    req->fs.info.bufs = create_ptrstruct<uv_buf_t>(nbufs * sizeof(uv_buf_t));

  if (req->fs.info.bufs == nullptr)
    return UV_ENOMEM;

  memcpy(req->fs.info.bufs, bufs, nbufs * sizeof(decltype(*bufs)));

  req->fs.info.offset = offset;
  POST(int);
}

int uv_fs_write(uv_loop_t* loop,
                uv_fs_t* req,
                uv_file fd,
                const uv_buf_t bufs[],
                unsigned int nbufs,
                int64_t offset,
                uv_fs_cb cb) {
  INIT(UV_FS_WRITE);

  if (bufs == nullptr || nbufs == 0)
    return UV_EINVAL;

  req->file.fd = fd;

  req->fs.info.nbufs = nbufs;
  req->fs.info.bufs = req->fs.info.bufsml;
  if (nbufs > ARRAY_SIZE(req->fs.info.bufsml))
    req->fs.info.bufs = create_ptrstruct<uv_buf_t>(nbufs * sizeof(uv_buf_t));

  if (req->fs.info.bufs == nullptr)
    return UV_ENOMEM;

  memcpy(req->fs.info.bufs, bufs, nbufs * sizeof(decltype(*bufs)));

  req->fs.info.offset = offset;
  POST(int);
}

int uv_fs_unlink(uv_loop_t* loop, uv_fs_t* req, const char* path,
    uv_fs_cb cb) {

  INIT(UV_FS_UNLINK);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_mkdir(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode,
    uv_fs_cb cb) {

  INIT(UV_FS_MKDIR);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.info.mode = mode;
  POST(int);
}

int uv_fs_mkdtemp(uv_loop_t* loop,
                  uv_fs_t* req,
                  const char* tpl,
                  uv_fs_cb cb) {

  INIT(UV_FS_MKDTEMP);
  auto err = fs__capture_path(req, tpl, nullptr, TRUE);
  if (err)
    return uv_translate_sys_error(err);

  POST(int);
}

int uv_fs_mkstemp(uv_loop_t* loop,
                  uv_fs_t* req,
                  const char* tpl,
                  uv_fs_cb cb) {

  INIT(UV_FS_MKSTEMP);
  auto err = fs__capture_path(req, tpl, nullptr, TRUE);
  if (err)
    return uv_translate_sys_error(err);

  POST(int);
}

int uv_fs_rmdir(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {

  INIT(UV_FS_RMDIR);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_scandir(uv_loop_t* loop, uv_fs_t* req, const char* path, int flags,
    uv_fs_cb cb) {

  INIT(UV_FS_SCANDIR);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.info.file_flags = flags;
  POST(int);
}

int uv_fs_opendir(uv_loop_t* loop,
                  uv_fs_t* req,
                  const char* path,
                  uv_fs_cb cb) {

  INIT(UV_FS_OPENDIR);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err)
    return uv_translate_sys_error(err);
  POST(int);
}

int uv_fs_readdir(uv_loop_t* loop,
                  uv_fs_t* req,
                  uv_dir_t* dir,
                  uv_fs_cb cb) {
  INIT(UV_FS_READDIR);

  if (dir == nullptr ||
      dir->dirents == nullptr ||
      dir->dir_handle == INVALID_HANDLE_VALUE) {
    return UV_EINVAL;
  }

  req->ptr = dir;
  POST(int);
}

int uv_fs_closedir(uv_loop_t* loop,
                   uv_fs_t* req,
                   uv_dir_t* dir,
                   uv_fs_cb cb) {
  INIT(UV_FS_CLOSEDIR);
  if (dir == nullptr)
    return UV_EINVAL;
  req->ptr = dir;
  POST(int);
}

int uv_fs_link(uv_loop_t* loop, uv_fs_t* req, const char* path,
    const char* new_path, uv_fs_cb cb) {

  INIT(UV_FS_LINK);
  auto err = fs__capture_path(req, path, new_path, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_symlink(uv_loop_t* loop, uv_fs_t* req, const char* path,
    const char* new_path, int flags, uv_fs_cb cb) {

  INIT(UV_FS_SYMLINK);
  auto err = fs__capture_path(req, path, new_path, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.info.file_flags = flags;
  POST(int);
}

int uv_fs_readlink(uv_loop_t* loop, uv_fs_t* req, const char* path,
    uv_fs_cb cb) {

  INIT(UV_FS_READLINK);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_realpath(uv_loop_t* loop, uv_fs_t* req, const char* path,
    uv_fs_cb cb) {

  INIT(UV_FS_REALPATH);

  if (!path) {
    return UV_EINVAL;
  }

  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_chown(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_uid_t uid,
    uv_gid_t gid, uv_fs_cb cb) {
  (void) uid, gid;
  INIT(UV_FS_CHOWN);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_fchown(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_uid_t uid,
    uv_gid_t gid, uv_fs_cb cb) {
  (void) fd, uid, gid;
  INIT(UV_FS_FCHOWN);
  POST(int);
}

int uv_fs_lchown(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_uid_t uid,
    uv_gid_t gid, uv_fs_cb cb) {
  (void)uid, gid;

  INIT(UV_FS_LCHOWN);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }
  POST(int);
}

int uv_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {

  INIT(UV_FS_STAT);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_lstat(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {

  INIT(UV_FS_LSTAT);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_fstat(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  INIT(UV_FS_FSTAT);
  req->file.fd = fd;
  POST(int);
}

int uv_fs_rename(uv_loop_t* loop, uv_fs_t* req, const char* path,
    const char* new_path, uv_fs_cb cb) {

  INIT(UV_FS_RENAME);
  auto err = fs__capture_path(req, path, new_path, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  POST(int);
}

int uv_fs_fsync(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  INIT(UV_FS_FSYNC);
  req->file.fd = fd;
  POST(int);
}

int uv_fs_fdatasync(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  INIT(UV_FS_FDATASYNC);
  req->file.fd = fd;
  POST(int);
}

int uv_fs_ftruncate(uv_loop_t* loop, uv_fs_t* req, uv_file fd,
    int64_t offset, uv_fs_cb cb) {
  INIT(UV_FS_FTRUNCATE);
  req->file.fd = fd;
  req->fs.info.offset = offset;
  POST(int);
}

int uv_fs_copyfile(uv_loop_t* loop,
                   uv_fs_t* req,
                   const char* path,
                   const char* new_path,
                   int flags,
                   uv_fs_cb cb) {

  INIT(UV_FS_COPYFILE);

  if (flags & ~(UV_FS_COPYFILE_EXCL |
                UV_FS_COPYFILE_FICLONE |
                UV_FS_COPYFILE_FICLONE_FORCE)) {
    return UV_EINVAL;
  }

  auto err = fs__capture_path(req, path, new_path, cb != nullptr);

  if (err)
    return uv_translate_sys_error(err);

  req->fs.info.file_flags = flags;
  POST(int);
}

int uv_fs_sendfile(uv_loop_t* loop, uv_fs_t* req, uv_file fd_out,
    uv_file fd_in, int64_t in_offset, size_t length, uv_fs_cb cb) {
  INIT(UV_FS_SENDFILE);
  req->file.fd = fd_in;
  req->fs.info.fd_out = fd_out;
  req->fs.info.offset = in_offset;
  req->fs.info.bufsml[0].len = static_cast<decltype(req->fs.info.bufsml[0].len)>(length);
  POST(int);
}

int uv_fs_access(uv_loop_t* loop,
                 uv_fs_t* req,
                 const char* path,
                 int flags,
                 uv_fs_cb cb) {

  INIT(UV_FS_ACCESS);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err)
    return uv_translate_sys_error(err);

  req->fs.info.mode = flags;
  POST(int);
}

int uv_fs_chmod(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode,
    uv_fs_cb cb) {

  INIT(UV_FS_CHMOD);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.info.mode = mode;
  POST(int);
}

int uv_fs_fchmod(uv_loop_t* loop, uv_fs_t* req, uv_file fd, int mode,
    uv_fs_cb cb) {
  INIT(UV_FS_FCHMOD);
  req->file.fd = fd;
  req->fs.info.mode = mode;
  POST(int);
}

int uv_fs_utime(uv_loop_t* loop, uv_fs_t* req, const char* path, double atime,
    double mtime, uv_fs_cb cb) {

  INIT(UV_FS_UTIME);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err) {
    return uv_translate_sys_error(err);
  }

  req->fs.time.atime = atime;
  req->fs.time.mtime = mtime;
  POST(int);
}

int uv_fs_futime(uv_loop_t* loop, uv_fs_t* req, uv_file fd, double atime,
    double mtime, uv_fs_cb cb) {
  INIT(UV_FS_FUTIME);
  req->file.fd = fd;
  req->fs.time.atime = atime;
  req->fs.time.mtime = mtime;
  POST(int);
}

int uv_fs_statfs(uv_loop_t* loop,
                 uv_fs_t* req,
                 const char* path,
                 uv_fs_cb cb) {

  INIT(UV_FS_STATFS);
  auto err = fs__capture_path(req, path, nullptr, cb != nullptr);
  if (err)
    return static_cast<int>(uv_translate_sys_error(err));

  POST(int);
}
