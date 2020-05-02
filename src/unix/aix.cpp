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

#include "uv.h"
#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>
#include <libgen.h>

#include <sys/protosw.h>
#include <libperfstat.h>
#include <procinfo.h>
#include <sys/proc.h>
#include <sys/procfs.h>

#include <sys/poll.h>

#include <sys/pollset.h>
#include <ctype.h>
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
#include <sys/ahafs_evProds.h>
#endif

#include <sys/mntctl.h>
#include <sys/vmount.h>
#include <limits.h>
#include <strings.h>
#include <sys/vnode.h>

#define RDWR_BUF_SIZE   4096
#define EQ(a,b)         (strcmp(a,b) == 0)

static uv_mutex_t process_title_mutex;
static uv_once_t process_title_mutex_once = UV_ONCE_INIT;
static void* args_mem = nullptr;
static char** process_argv = nullptr;
static int process_argc = 0;
static char* process_title_ptr = nullptr;

static void init_process_title_mutex_once() {
  uv_mutex_init(&process_title_mutex);
}

int uv__platform_loop_init(uv_loop_t* loop) {
  loop->fs_fd = -1;

  /* Passing maxfd of -1 should mean the limit is determined
   * by the user's ulimit or the global limit as per the doc */
  loop->backend_fd = pollset_create(-1);

  if (loop->backend_fd == -1)
    return -1;

  return 0;
}

void uv__platform_loop_delete(uv_loop_t* loop) {
  if (loop->fs_fd != -1) {
    uv__close(loop->fs_fd);
    loop->fs_fd = -1;
  }

  if (loop->backend_fd != -1) {
    pollset_destroy(loop->backend_fd);
    loop->backend_fd = -1;
  }
}

int uv__io_fork(uv_loop_t* loop) {
  uv__platform_loop_delete(loop);

  return uv__platform_loop_init(loop);
}

int uv__io_check_fd(uv_loop_t* loop, int fd) {

  auto pc = poll_ctl{};
  pc.events = POLLIN;
  pc.cmd = PS_MOD;  /* Equivalent to PS_ADD if the fd is not in the pollset. */
  pc.fd = fd;

  if (pollset_ctl(loop->backend_fd, &pc, 1))
    return UV__ERR(errno);

  pc.cmd = PS_DELETE;
  if (pollset_ctl(loop->backend_fd, &pc, 1))
    abort();

  return 0;
}

void uv__io_poll(uv_loop_t* loop, int timeout) {

  if (loop->nfds == 0) {
    assert(QUEUE_EMPTY(&loop->watcher_queue));
    return;
  }

  auto pc = poll_ctl{};
  while (!QUEUE_EMPTY(&loop->watcher_queue)) {
    auto q = QUEUE_HEAD(&loop->watcher_queue);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);

    auto w = QUEUE_DATA(q, uv__io_t, watcher_queue);
    assert(w->pevents != 0);
    assert(w->fd >= 0);
    assert(w->fd < static_cast<int>(loop->nwatchers));

    pc.events = w->pevents;
    pc.fd = w->fd;

    auto add_failed = 0;
    if (w->events == 0) {
      pc.cmd = PS_ADD;
      if (pollset_ctl(loop->backend_fd, &pc, 1)) {
        if (errno != EINVAL) {
          assert(0 && "Failed to add file descriptor (pc.fd) to pollset");
          abort();
        }
        /* Check if the fd is already in the pollset */
        auto pqry = pollfd{};
        pqry.fd = pc.fd;
        auto rc = pollset_query(loop->backend_fd, &pqry);
        switch (rc) {
        case -1:
          assert(0 && "Failed to query pollset for file descriptor");
          abort();
        case 0:
          assert(0 && "Pollset does not contain file descriptor");
          abort();
        }
        /* If we got here then the pollset already contained the file descriptor even though
         * we didn't think it should. This probably shouldn't happen, but we can continue. */
        add_failed = 1;
      }
    }
    if (w->events != 0 || add_failed) {
      /* Modify, potentially removing events -- need to delete then add.
       * Could maybe mod if we knew for sure no events are removed, but
       * content of w->events is handled above as not reliable (falls back)
       * so may require a pollset_query() which would have to be pretty cheap
       * compared to a PS_DELETE to be worth optimizing. Alternatively, could
       * lazily remove events, squelching them in the mean time. */
      pc.cmd = PS_DELETE;
      if (pollset_ctl(loop->backend_fd, &pc, 1)) {
        assert(0 && "Failed to delete file descriptor (pc.fd) from pollset");
        abort();
      }
      pc.cmd = PS_ADD;
      if (pollset_ctl(loop->backend_fd, &pc, 1)) {
        assert(0 && "Failed to add file descriptor (pc.fd) to pollset");
        abort();
      }
    }

    w->events = w->pevents;
  }

  assert(timeout >= -1);
  auto base = loop->time;
  auto count = 48; /* Benchmarks suggest this gives the best throughput. */

  for (;;) {
    pollfd events[1024];
    auto nfds = pollset_poll(loop->backend_fd,
                        events,
                        ARRAY_SIZE(events),
                        timeout);

    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
    SAVE_ERRNO(uv__update_time(loop));

    if (nfds == 0) {
      assert(timeout != -1);
      return;
    }

    if (nfds == -1) {
      if (errno != EINTR) {
        abort();
      }

      if (timeout == -1)
        continue;

      if (timeout == 0)
        return;

      /* Interrupted by a signal. Update timeout and poll again. */
      assert(timeout > 0);

      auto diff = loop->time - base;
      if (diff >= static_cast<decltype(diff)>(timeout))
        return;

      timeout -= diff;
      return;
    }

    auto have_signals = 0;
    auto nevents = 0;

    assert(loop->watchers != nullptr);
    loop->watchers[loop->nwatchers] = (void*) events;
    loop->watchers[loop->nwatchers + 1] = (void*) (uintptr_t) nfds;

    for (auto i = 0; i < nfds; i++) {
      auto *pe = events + i;
      pc.cmd = PS_DELETE;
      pc.fd = pe->fd;

      /* Skip invalidated events, see uv__platform_invalidate_fd */
      if (pc.fd == -1)
        continue;

      assert(pc.fd >= 0);
      assert((unsigned) pc.fd < loop->nwatchers);

      auto w = loop->watchers[pc.fd];

      if (w == nullptr) {
        /* File descriptor that we've stopped watching, disarm it.
         *
         * Ignore all errors because we may be racing with another thread
         * when the file descriptor is closed.
         */
        pollset_ctl(loop->backend_fd, &pc, 1);
        continue;
      }

      /* Run signal watchers last.  This also affects child process watchers
       * because those are implemented in terms of signal watchers.
       */
      if (w == &loop->signal_io_watcher)
        have_signals = 1;
      else
        w->cb(loop, w, pe->revents);

      nevents++;
    }

    if (have_signals != 0)
      loop->signal_io_watcher.cb(loop, &loop->signal_io_watcher, POLLIN);

    loop->watchers[loop->nwatchers] = nullptr;
    loop->watchers[loop->nwatchers + 1] = nullptr;

    if (have_signals != 0)
      return;  /* Event loop should cycle now so don't poll again. */

    if (nevents != 0) {
      if (nfds == ARRAY_SIZE(events) && --count != 0) {
        /* Poll for more events but don't block this time. */
        timeout = 0;
        continue;
      }
      return;
    }

    if (timeout == 0)
      return;

    if (timeout == -1)
      continue;
  }
}

uint64_t uv_get_free_memory() {
  auto mem_total = perfstat_memory_total_t{};
  auto result = perfstat_memory_total(nullptr, &mem_total, sizeof(decltype(mem_total)), 1);
  if (result == -1) {
    return 0;
  }
  return mem_total.real_free * 4096;
}

uint64_t uv_get_total_memory() {
  auto mem_total = perfstat_memory_total_t{};
  auto result = perfstat_memory_total(nullptr, &mem_total, sizeof(decltype(mem_total)), 1);
  if (result == -1) {
    return 0;
  }
  return mem_total.real_total * 4096;
}

uint64_t uv_get_constrained_memory() {
  return 0;  /* Memory constraints are unknown. */
}

void uv_loadavg(double avg[3]) {
  auto ps_total = perfstat_cpu_total_t{};
  auto result = perfstat_cpu_total(nullptr, &ps_total, sizeof(decltype(ps_total)), 1);
  if (result == -1) {
    avg[0] = 0.; avg[1] = 0.; avg[2] = 0.;
    return;
  }
  avg[0] = ps_total.loadavg[0] / static_cast<double>(1 << SBITS);
  avg[1] = ps_total.loadavg[1] / static_cast<double>(1 << SBITS);
  avg[2] = ps_total.loadavg[2] / static_cast<double>(1 << SBITS);
}

#ifdef HAVE_SYS_AHAFS_EVPRODS_H
static char* uv__rawname(const char* cp, char (*dst)[FILENAME_MAX+1]) {

  auto *dp = rindex(cp, '/');
  if (dp == 0)
    return 0;

  snprintf(*dst, sizeof(*dst), "%.*s/r%s", static_cast<int>(dp - cp), cp, dp + 1);
  return *dst;
}

/*
 * Determine whether given pathname is a directory
 * Returns 0 if the path is a directory, -1 if not
 *
 * Note: Opportunity here for more detailed error information but
 *       that requires changing callers of this function as well
 */
static int uv__path_is_a_directory(char* filename) {
  auto statbuf = stat{};

  if (stat(filename, &statbuf) < 0)
    return -1;  /* failed: not a directory, assume it is a file */

  if (statbuf.st_type == VDIR)
    return 0;

  return -1;
}

/*
 * Check whether AHAFS is mounted.
 * Returns 0 if AHAFS is mounted, or an error code < 0 on failure
 */
static int uv__is_ahafs_mounted(){
  char rawbuf[FILENAME_MAX+1];
  const char *dev = "/aha";

  int size_multiplier = 10;
  size_t siz = sizeof(vmount)*size_multiplier;
  auto p = static_cast<vmount*>(uv__malloc(siz));
  if (p == nullptr)
    return UV__ERR(errno);

  /* Retrieve all mounted filesystems */
  auto rv = mntctl(MCTL_QUERY, siz, reinterpret_cast<char*>(p));
  if (rv < 0)
    return UV__ERR(errno);
  if (rv == 0) {
    /* buffer was not large enough, reallocate to correct size */
    siz = *reinterpret_cast<int*>(p);
    uv__free(p);
    p = static_cast<vmount*>(uv__malloc(siz));
    if (p == nullptr)
      return UV__ERR(errno);
    rv = mntctl(MCTL_QUERY, siz, reinterpret_cast<char*>(p));
    if (rv < 0)
      return UV__ERR(errno);
  }

  /* Look for dev in filesystems mount info */
  auto i = 0;
  auto *vmt = p;
  for(auto i = 0; i < rv; i++) {
    auto obj = vmt2dataptr(vmt, VMT_OBJECT);     /* device */
    auto stub = vmt2dataptr(vmt, VMT_STUB);      /* mount point */

    if (EQ(obj, dev) || EQ(uv__rawname(obj, &rawbuf), dev) || EQ(stub, dev)) {
      uv__free(p);  /* Found a match */
      return 0;
    }
    vmt = reinterpret_cast<vmount *>(reinterpret_cast<char *>(vmt) + vmt->vmt_length);
  }

  /* /aha is required for monitoring filesystem changes */
  return -1;
}

/*
 * Recursive call to mkdir() to create intermediate folders, if any
 * Returns code from mkdir call
 */
static int uv__makedir_p(const char *dir) {
  char tmp[256];

  /* TODO(bnoordhuis) Check uv__strscpy() return value. */
  uv__strscpy(tmp, dir, sizeof(tmp));
  auto len = strlen(tmp);
  if (tmp[len - 1] == '/')
    tmp[len - 1] = 0;
  for (auto p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      auto err = mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
      if (err != 0 && errno != EEXIST)
        return err;
      *p = '/';
    }
  }
  return mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

/*
 * Creates necessary subdirectories in the AIX Event Infrastructure
 * file system for monitoring the object specified.
 * Returns code from mkdir call
 */
static int uv__make_subdirs_p(const char *filename) {
  char cmd[2048];

  /* Strip off the monitor file name */
  auto *p = strrchr(filename, '/');

  if (p == nullptr)
    return 0;

  if (uv__path_is_a_directory(const_cast<char*>(filename)) == 0) {
    sprintf(cmd, "/aha/fs/modDir.monFactory");
  } else {
    sprintf(cmd, "/aha/fs/modFile.monFactory");
  }

  strncat(cmd, filename, (p - filename));
  auto rc = uv__makedir_p(cmd);

  if (rc == -1 && errno != EEXIST){
    return UV__ERR(errno);
  }

  return rc;
}

/*
 * Checks if /aha is mounted, then proceeds to set up the monitoring
 * objects for the specified file.
 * Returns 0 on success, or an error code < 0 on failure
 */
static int uv__setup_ahafs(const char* filename, int *fd) {
  char mon_file_write_string[RDWR_BUF_SIZE];
  char mon_file[PATH_MAX];

  /* Create monitor file name for object */
  /* -1 == NO, 0 == YES  */
  auto file_is_directory = uv__path_is_a_directory(const_cast<char*>(filename));

  if (file_is_directory == 0)
    sprintf(mon_file, "/aha/fs/modDir.monFactory");
  else
    sprintf(mon_file, "/aha/fs/modFile.monFactory");

  if ((strlen(mon_file) + strlen(filename) + 5) > PATH_MAX)
    return UV_ENAMETOOLONG;

  /* Make the necessary subdirectories for the monitor file */
  auto rc = uv__make_subdirs_p(filename);
  if (rc == -1 && errno != EEXIST)
    return rc;

  strcat(mon_file, filename);
  strcat(mon_file, ".mon");

  *fd = 0; errno = 0;

  /* Open the monitor file, creating it if necessary */
  *fd = open(mon_file, O_CREAT|O_RDWR);
  if (*fd < 0)
    return UV__ERR(errno);

  /* Write out the monitoring specifications.
   * In this case, we are monitoring for a state change event type
   *    CHANGED=YES
   * We will be waiting in select call, rather than a read:
   *    WAIT_TYPE=WAIT_IN_SELECT
   * We only want minimal information for files:
   *      INFO_LVL=1
   * For directories, we want more information to track what file
   * caused the change
   *      INFO_LVL=2
   */

  if (file_is_directory == 0)
    sprintf(mon_file_write_string, "CHANGED=YES;WAIT_TYPE=WAIT_IN_SELECT;INFO_LVL=2");
  else
    sprintf(mon_file_write_string, "CHANGED=YES;WAIT_TYPE=WAIT_IN_SELECT;INFO_LVL=1");

  rc = write(*fd, mon_file_write_string, strlen(mon_file_write_string)+1);
  if (rc < 0 && errno != EBUSY)
    return UV__ERR(errno);

  return 0;
}

/*
 * Skips a specified number of lines in the buffer passed in.
 * Walks the buffer pointed to by p and attempts to skip n lines.
 * Returns the total number of lines skipped
 */
static int uv__skip_lines(char **p, int n) {

  auto lines = 0;
  while(n > 0) {
    *p = strchr(*p, '\n');
    if (!p)
      return lines;

    (*p)++;
    n--;
    lines++;
  }
  return lines;
}

/*
 * Parse the event occurrence data to figure out what event just occurred
 * and take proper action.
 *
 * The buf is a pointer to the buffer containing the event occurrence data
 * Returns 0 on success, -1 if unrecoverable error in parsing
 *
 */
static int uv__parse_data(char *buf, int *events, uv_fs_event_t* handle) {
  char filename[PATH_MAX]; /* To be used when handling directories */

  auto p = buf;
  *events = 0;

  /* Clean the filename buffer*/
  for(auto i = 0; i < PATH_MAX; i++) {
    filename[i] = 0;
  }

  /* Check for BUF_WRAP */
  if (strncmp(buf, "BUF_WRAP", strlen("BUF_WRAP")) == 0) {
    assert(0 && "Buffer wrap detected, Some event occurrences lost!");
    return 0;
  }

  /* Since we are using the default buffer size (4K), and have specified
   * INFO_LVL=1, we won't see any EVENT_OVERFLOW conditions.  Applications
   * should check for this keyword if they are using an INFO_LVL of 2 or
   * higher, and have a buffer size of <= 4K
   */

  /* Skip to RC_FROM_EVPROD */
  if (uv__skip_lines(&p, 9) != 9)
    return -1;

  auto evp_rc = int{};
  if (sscanf(p, "RC_FROM_EVPROD=%d\nEND_EVENT_DATA", &evp_rc) == 1) {
    if (uv__path_is_a_directory(handle->path) == 0) { /* Directory */
      if (evp_rc == AHAFS_MODDIR_UNMOUNT || evp_rc == AHAFS_MODDIR_REMOVE_SELF) {
        /* The directory is no longer available for monitoring */
        *events = UV_RENAME;
        handle->dir_filename = nullptr;
      } else {
        /* A file was added/removed inside the directory */
        *events = UV_CHANGE;

        /* Get the EVPROD_INFO */
        if (uv__skip_lines(&p, 1) != 1)
          return -1;

        /* Scan out the name of the file that triggered the event*/
        if (sscanf(p, "BEGIN_EVPROD_INFO\n%sEND_EVPROD_INFO", filename) == 1) {
          handle->dir_filename = uv__strdup(const_cast<const char*>(&filename));
        } else
          return -1;
        }
    } else { /* Regular File */
      if (evp_rc == AHAFS_MODFILE_RENAME)
        *events = UV_RENAME;
      else
        *events = UV_CHANGE;
    }
  }
  else
    return -1;

  return 0;
}

/* This is the internal callback */
static void uv__ahafs_event(uv_loop_t* loop, uv__io_t* event_watch, unsigned int fflags) {
  char result_data[RDWR_BUF_SIZE];
  char fname[PATH_MAX];

  auto handle = container_of(event_watch, uv_fs_event_t, event_watcher);

  /* At this point, we assume that polling has been done on the
   * file descriptor, so we can just read the AHAFS event occurrence
   * data and parse its results without having to block anything
   */
  auto bytes = pread(event_watch->fd, result_data, RDWR_BUF_SIZE, 0);

  assert((bytes >= 0) && "uv__ahafs_event - Error reading monitor file");

  /* In file / directory move cases, AIX Event infrastructure
   * produces a second event with no data.
   * Ignore it and return gracefully.
   */
  if(bytes == 0)
    return;

  /* Parse the data */
  auto rc = 0;
  auto events = 0;
  if(bytes > 0)
    rc = uv__parse_data(result_data, &events, handle);

  /* Unrecoverable error */
  if (rc == -1)
    return;

  /* For directory changes, the name of the files that triggered the change
   * are never absolute pathnames
   */
  if (uv__path_is_a_directory(handle->path) == 0) {
    auto p = handle->dir_filename;
  } else {
    p = strrchr(handle->path, '/');
    if (p == nullptr)
      p = handle->path;
    else
      p++;
  }

  /* TODO(bnoordhuis) Check uv__strscpy() return value. */
  uv__strscpy(fname, p, sizeof(fname));

  handle->cb(handle, fname, events, 0);
}
#endif

int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
  uv__handle_init(loop, reinterpret_cast<uv_handle_t*>(handle), UV_FS_EVENT);
  return 0;
#else
  return UV_ENOSYS;
#endif
}

int uv_fs_event_start(uv_fs_event_t* handle,
                      uv_fs_event_cb cb,
                      const char* filename,
                      unsigned int flags) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
  char cwd[PATH_MAX];
  char absolute_path[PATH_MAX];
  char readlink_cwd[PATH_MAX];

  /* Figure out whether filename is absolute or not */
  if (filename[0] == '\0') {
    /* Missing a pathname */
    return UV_ENOENT;
  }
  else if (filename[0] == '/') {
    /* We have absolute pathname */
    /* TODO(bnoordhuis) Check uv__strscpy() return value. */
    uv__strscpy(absolute_path, filename, sizeof(absolute_path));
  } else {
    /* We have a relative pathname, compose the absolute pathname */
    snprintf(cwd, sizeof(cwd), "/proc/%lu/cwd", (unsigned long) getpid());
    auto rc = readlink(cwd, readlink_cwd, sizeof(readlink_cwd) - 1);
    if (rc < 0)
      return rc;
    /* readlink does not null terminate our string */
    readlink_cwd[rc] = '\0';

    auto str_offset = 0;
    if (filename[0] == '.' && filename[1] == '/')
      str_offset = 2;

    snprintf(absolute_path, sizeof(absolute_path), "%s%s", readlink_cwd,
             filename + str_offset);
  }

  if (uv__is_ahafs_mounted() < 0)  /* /aha checks failed */
    return UV_ENOSYS;

  /* Setup ahafs */
  auto rc = uv__setup_ahafs((const char *)absolute_path, &fd);
  if (rc != 0)
    return rc;

  /* Setup/Initialize all the libuv routines */
  uv__handle_start(handle);
  uv__io_init(&handle->event_watcher, uv__ahafs_event, fd);
  handle->path = uv__strdup(filename);
  handle->cb = cb;
  handle->dir_filename = nullptr;

  uv__io_start(handle->loop, &handle->event_watcher, POLLIN);

  /* AHAFS wants someone to poll for it to start mointoring.
   *  so kick-start it so that we don't miss an event in the
   *  eventuality of an event that occurs in the current loop. */
  do {
    auto zt = timeval{};
    auto fd = 0;
    auto pollfd = fd_set{};
    memset(&zt, 0, sizeof(zt));
    FD_ZERO(&pollfd);
    FD_SET(fd, &pollfd);
    rc = select(fd + 1, &pollfd, nullptr, nullptr, &zt);
  } while (rc == -1 && errno == EINTR);
  return 0;
#else
  return UV_ENOSYS;
#endif
}

int uv_fs_event_stop(uv_fs_event_t* handle) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
  if (!uv__is_active(handle))
    return 0;

  uv__io_close(handle->loop, &handle->event_watcher);
  uv__handle_stop(handle);

  if (uv__path_is_a_directory(handle->path) == 0) {
    uv__free(handle->dir_filename);
    handle->dir_filename = nullptr;
  }

  uv__free(handle->path);
  handle->path = nullptr;
  uv__close(handle->event_watcher.fd);
  handle->event_watcher.fd = -1;

  return 0;
#else
  return UV_ENOSYS;
#endif
}

void uv__fs_event_close(uv_fs_event_t* handle) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
  uv_fs_event_stop(handle);
#else
  UNREACHABLE();
#endif
}

char** uv_setup_args(int argc, char** argv) {

  if (argc <= 0)
    return argv;

  /* Save the original pointer to argv.
   * AIX uses argv to read the process name.
   * (Not the memory pointed to by argv[0..n] as on Linux.)
   */
  process_argv = argv;
  process_argc = argc;

  /* Calculate how much memory we need for the argv strings. */
  auto size = 0ull;
  for (auto i = 0; i < argc; i++)
    size += strlen(argv[i]) + 1;

  /* Add space for the argv pointers. */
  size += (argc + 1) * sizeof(char*);

  auto new_argv = static_cast<char**>(uv__malloc(size));
  if (new_argv == nullptr)
    return argv;
  args_mem = new_argv;

  /* Copy over the strings and set up the pointer table. */
  auto s = static_cast<char*>(&new_argv[argc + 1]);
  for (i = 0; i < argc; i++) {
    size = strlen(argv[i]) + 1;
    memcpy(s, argv[i], size);
    new_argv[i] = s;
    s += size;
  }
  new_argv[i] = nullptr;

  return new_argv;
}

int uv_set_process_title(const char* title) {
  /* We cannot free this pointer when libuv shuts down,
   * the process may still be using it.
   */
  auto new_title = uv__strdup(title);
  if (new_title == nullptr)
    return UV_ENOMEM;

  uv_once(&process_title_mutex_once, init_process_title_mutex_once);
  uv_mutex_lock(&process_title_mutex);

  /* If this is the first time this is set,
   * don't free and set argv[1] to nullptr.
   */
  if (process_title_ptr != nullptr)
    uv__free(process_title_ptr);

  process_title_ptr = new_title;

  process_argv[0] = process_title_ptr;
  if (process_argc > 1)
     process_argv[1] = nullptr;

  uv_mutex_unlock(&process_title_mutex);

  return 0;
}

int uv_get_process_title(char* buffer, size_t size) {
  if (buffer == nullptr || size == 0)
    return UV_EINVAL;

  uv_once(&process_title_mutex_once, init_process_title_mutex_once);
  uv_mutex_lock(&process_title_mutex);

  auto len = strlen(process_argv[0]);
  if (size <= len) {
    uv_mutex_unlock(&process_title_mutex);
    return UV_ENOBUFS;
  }

  memcpy(buffer, process_argv[0], len);
  buffer[len] = '\0';

  uv_mutex_unlock(&process_title_mutex);

  return 0;
}

UV_DESTRUCTOR(static void free_args_mem()) {
  uv__free(args_mem);  /* Keep valgrind happy. */
  args_mem = nullptr;
}

int uv_resident_set_memory(size_t* rss) {
  char pp[64];

  snprintf(pp, sizeof(pp), "/proc/%lu/psinfo", static_cast<unsigned long>(getpid()));

  auto fd = open(pp, O_RDONLY);
  if (fd == -1)
    return UV__ERR(errno);

  /* FIXME(bnoordhuis) Handle EINTR. */
  auto err = static_cast<int>(UV_EINVAL);
  auto psinfo = psinfo_t{};
  if (read(fd, &psinfo, sizeof(decltype(psinfo))) == sizeof(decltype(psinfo))) {
    *rss = static_cast<size_t>(psinfo.pr_rssize) * 1024;
    err = 0;
  }
  uv__close(fd);

  return err;
}

int uv_uptime(double* uptime) {
  utmpname(UTMP_FILE);

  setutent();

  entries = 0ull;
  auto boot_time = time_t{0};
  while ((auto utmp_buf = getutent()) != nullptr) {
    if (utmp_buf->ut_user[0] && utmp_buf->ut_type == USER_PROCESS)
      ++entries;
    if (utmp_buf->ut_type == BOOT_TIME)
      boot_time = utmp_buf->ut_time;
  }

  endutent();

  if (boot_time == 0)
    return UV_ENOSYS;

  *uptime = time(nullptr) - boot_time;
  return 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {

  auto ps_total = perfstat_cpu_total_t{};
  auto result = perfstat_cpu_total(nullptr, &ps_total, sizeof(ps_total), 1);
  if (result == -1) {
    return UV_ENOSYS;
  }

  auto ncpus = result = perfstat_cpu(nullptr, nullptr, sizeof(perfstat_cpu_t), 0);
  if (result == -1) {
    return UV_ENOSYS;
  }

  auto ps_cpus = static_cast<perfstat_cpu_t*>(uv__malloc(ncpus * sizeof(perfstat_cpu_t)));
  if (!ps_cpus) {
    return UV_ENOMEM;
  }

  /* TODO(bnoordhuis) Check uv__strscpy() return value. */
  auto cpu_id = perfstat_id_t{};
  uv__strscpy(cpu_id.name, FIRST_CPU, sizeof(decltype(cpu_id.name)));
  result = perfstat_cpu(&cpu_id, ps_cpus, sizeof(perfstat_cpu_t), ncpus);
  if (result == -1) {
    uv__free(ps_cpus);
    return UV_ENOSYS;
  }

  *cpu_infos = static_cast<uv_cpu_info_t*>(uv__malloc(ncpus * sizeof(uv_cpu_info_t)));
  if (!*cpu_infos) {
    uv__free(ps_cpus);
    return UV_ENOMEM;
  }

  *count = ncpus;

  auto cpu_info = *cpu_infos;
  auto idx = 0;
  while (idx < ncpus) {
    cpu_info->speed = static_cast<int>(ps_total.processorHZ / 1000000);
    cpu_info->model = uv__strdup(ps_total.description);
    cpu_info->cpu_times.user = ps_cpus[idx].user;
    cpu_info->cpu_times.sys = ps_cpus[idx].sys;
    cpu_info->cpu_times.idle = ps_cpus[idx].idle;
    cpu_info->cpu_times.irq = ps_cpus[idx].wait;
    cpu_info->cpu_times.nice = 0;
    cpu_info++;
    idx++;
  }

  uv__free(ps_cpus);
  return 0;
}

int uv_interface_addresses_syserror(uv_interface_address_t** addresses, 
                          int* count, int sockfd, int sock6fd, ifreq* ifcreq){
  uv_free_interface_addresses(*addresses, *count);
  *addresses = nullptr;
  *count = 0;
  auto r = static_cast<int>(UV_ENOSYS);
  return uv_interface_addresses_cleanup(sockfd, sock6fd, ifcreq, r);
}

int uv_interface_addresses_cleanup(int sockfd, int sock6fd, ifreq* ifcreq, int r){
  if (sockfd != -1)
    uv__close(sockfd);
  if (sock6fd != -1)
    uv__close(sock6fd);
  uv__free(ifcreq);
  return r;
}

int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  *count = 0;
  *addresses = nullptr;

  auto sockfd = int{};
  auto r = 0;
  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
    r = UV__ERR(errno);
    return uv_interface_addresses_cleanup(sockfd, -1, ifc.ifc_req, r);
  }

  auto sock6fd = -1;
  if (0 > (sock6fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP))) {
    r = UV__ERR(errno);
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }

  auto size = 1;
  if (ioctl(sockfd, SIOCGSIZIFCONF, &size) == -1) {
    r = UV__ERR(errno);
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }

  auto ifc = ifconf{};
  ifc.ifc_req = static_cast<ifreq*>(uv__malloc(size));
  if (ifc.ifc_req == nullptr) {
    r = UV_ENOMEM;
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }
  ifc.ifc_len = size;
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    r = UV__ERR(errno);
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }

#define ADDR_SIZE(p) MAX((p).sa_len, sizeof(p))

  /* Count all up and running ipv4/ipv6 addresses */
  auto flg = ifreq{};
  auto *ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    auto p = ifr;
    ifr = reinterpret_cast<ifreq*>
      (reinterpret_cast<char*>(ifr) + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      r = UV__ERR(errno);
      return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    (*count)++;
  }

  if (*count == 0){
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }

  /* Alloc the return interface structs */
  *addresses = uv__calloc(*count, sizeof(**addresses));
  if (!(*addresses)) {
    r = UV_ENOMEM;
    return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
  }
  auto address = *addresses;

  ifr = ifc.ifc_req;
  while (reinterpret_cast<char*>(ifr) < reinterpret_cast<char*>(ifc.ifc_req) + ifc.ifc_len) {
    auto p = ifr;
    ifr = reinterpret_cast<ifreq*>
      (reinterpret_cast<char*>(ifr) + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    auto inet6 = static_cast<int>(p->ifr_addr.sa_family == AF_INET6);

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1){
      return uv_interface_addresses_syserror(addresses, count, sockfd, sock6fd, ifc.ifc_req);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    /* All conditions above must match count loop */

    address->name = uv__strdup(p->ifr_name);

    if (inet6)
      address->address.address6 = *(reinterpret_cast<sockaddr_in6*>(&p->ifr_addr));
    else
      address->address.address4 = *(reinterpret_cast<sockaddr_in*>(&p->ifr_addr));

    if (inet6) {
      auto if6 = in6_ifreq{};
      memset(&if6, 0, sizeof(decltype(if6)));
      r = uv__strscpy(if6.ifr_name, p->ifr_name, sizeof(if6.ifr_name));
      if (r == UV_E2BIG){
        return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
      }
      r = 0;
      memcpy(&if6.ifr_Addr, &p->ifr_addr, sizeof(if6.ifr_Addr));
      if (ioctl(sock6fd, SIOCGIFNETMASK6, &if6) == -1){
        return uv_interface_addresses_syserror(addresses, count, sockfd, sock6fd, ifc.ifc_req);
      }
      address->netmask.netmask6 = *(reinterpret_cast<sockaddr_in6*>(&if6.ifr_Addr));
      /* Explicitly set family as the ioctl call appears to return it as 0. */
      address->netmask.netmask6.sin6_family = AF_INET6;
    } else {
      if (ioctl(sockfd, SIOCGIFNETMASK, p) == -1){
        return uv_interface_addresses_syserror(addresses, count, sockfd, sock6fd, ifc.ifc_req);
      }
      address->netmask.netmask4 = *(reinterpret_cast<sockaddr_in*>(&p->ifr_addr));
      /* Explicitly set family as the ioctl call appears to return it as 0. */
      address->netmask.netmask4.sin_family = AF_INET;
    }

    address->is_internal = flg.ifr_flags & IFF_LOOPBACK ? 1 : 0;

    address++;
  }

  /* Fill in physical addresses. */
  ifr = ifc.ifc_req;
  while (reinterpret_cast<char*>(ifr) < reinterpret_cast<char*>(ifc.ifc_req) + ifc.ifc_len) {
    p = ifr;
    ifr = reinterpret_cast<ifreq*>
      (reinterpret_cast<char*>(ifr) + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (p->ifr_addr.sa_family != AF_LINK)
      continue;

    address = *addresses;
    for (auto i = 0; i < *count; i++) {
      if (strcmp(address->name, p->ifr_name) == 0) {
        auto sa_addr = reinterpret_cast<sockaddr_dl*>(&p->ifr_addr);
        memcpy(address->phys_addr, LLADDR(sa_addr), sizeof(address->phys_addr));
      }
      address++;
    }
  }

#undef ADDR_SIZE
  return uv_interface_addresses_cleanup(sockfd, sock6fd, ifc.ifc_req, r);
}

void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {

  for (auto i = 0; i < count; ++i) {
    uv__free(addresses[i].name);
  }

  uv__free(addresses);
}

void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {

  assert(loop->watchers != nullptr);
  assert(fd >= 0);

  auto events = reinterpret_cast<pollfd*>(loop->watchers[loop->nwatchers]);
  auto nfds = static_cast<uintptr_t>(loop->watchers[loop->nwatchers + 1]);

  if (events != nullptr)
    /* Invalidate events with same file descriptor */
    for (auto i = 0ul; i < nfds; i++)
      if (static_cast<int>(events[i].fd) == fd)
        events[i].fd = -1;

  /* Remove the file descriptor from the poll set */
  auto pc = poll_ctl{};
  pc.events = 0;
  pc.cmd = PS_DELETE;
  pc.fd = fd;
  if(loop->backend_fd >= 0)
    pollset_ctl(loop->backend_fd, &pc, 1);
}
