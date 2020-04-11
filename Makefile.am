# Copyright (c) 2013, Ben Noordhuis <info@bnoordhuis.nl>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

include_HEADERS=include/uv.h

uvincludedir = $(includedir)/uv
uvinclude_HEADERS = include/uv/errno.h \
                    include/uv/threadpool.h \
                    include/uv/version.h

CLEANFILES =

lib_LTLIBRARIES = libuv.la
libuv_la_CFLAGS = @CFLAGS@
libuv_la_LDFLAGS = -no-undefined -version-info 1:0:0
libuv_la_SOURCES = src/fs-poll.cpp \
                   src/heap-inl.h \
                   src/idna.cpp \
                   src/idna.h \
                   src/inet.cpp \
                   src/queue.h \
                   src/random.cpp \
                   src/strscpy.cpp \
                   src/strscpy.h \
                   src/threadpool.cpp \
                   src/timer.cpp \
                   src/uv-data-getter-setters.cpp \
                   src/uv-common.cpp \
                   src/uv-common.h \
                   src/version.cpp

if SUNOS
# Can't be turned into a CC_CHECK_CFLAGS in configure.ac, it makes compilers
# on other platforms complain that the argument is unused during compilation.
libuv_la_CFLAGS += -pthreads
endif

if WINNT

uvinclude_HEADERS += include/uv/win.h include/uv/tree.h
AM_CPPFLAGS += -I$(top_srcdir)/src/win \
               -DWIN32_LEAN_AND_MEAN \
               -D_WIN32_WINNT=0x0600
libuv_la_SOURCES += src/win/async.cpp \
                    src/win/atomicops-inl.h \
                    src/win/core.cpp \
                    src/win/detect-wakeup.cpp \
                    src/win/dl.cpp \
                    src/win/error.cpp \
                    src/win/fs-event.cpp \
                    src/win/fs.cpp \
                    src/win/getaddrinfo.cpp \
                    src/win/getnameinfo.cpp \
                    src/win/handle.cpp \
                    src/win/handle-inl.h \
                    src/win/internal.h \
                    src/win/loop-watcher.cpp \
                    src/win/pipe.cpp \
                    src/win/poll.cpp \
                    src/win/process-stdio.cpp \
                    src/win/process.cpp \
                    src/win/req-inl.h \
                    src/win/signal.cpp \
                    src/win/stream.cpp \
                    src/win/stream-inl.h \
                    src/win/tcp.cpp \
                    src/win/thread.cpp \
                    src/win/tty.cpp \
                    src/win/udp.cpp \
                    src/win/util.cpp \
                    src/win/winapi.cpp \
                    src/win/winapi.h \
                    src/win/winsock.cpp \
                    src/win/winsock.h

else  # WINNT

uvinclude_HEADERS += include/uv/unix.h
AM_CPPFLAGS += -I$(top_srcdir)/src/unix
libuv_la_SOURCES += src/unix/async.cpp \
                   src/unix/atomic-ops.h \
                   src/unix/core.cpp \
                   src/unix/dl.cpp \
                   src/unix/fs.cpp \
                   src/unix/getaddrinfo.cpp \
                   src/unix/getnameinfo.cpp \
                   src/unix/internal.h \
                   src/unix/loop-watcher.cpp \
                   src/unix/loop.cpp \
                   src/unix/pipe.cpp \
                   src/unix/poll.cpp \
                   src/unix/process.cpp \
                   src/unix/random-devurandom.cpp \
                   src/unix/signal.cpp \
                   src/unix/spinlock.h \
                   src/unix/stream.cpp \
                   src/unix/tcp.cpp \
                   src/unix/thread.cpp \
                   src/unix/tty.cpp \
                   src/unix/udp.cpp

endif  # WINNT

EXTRA_DIST = test/fixtures/empty_file \
             test/fixtures/load_error.node \
             test/fixtures/lorem_ipsum.txt \
             include \
             docs \
             img \
             CONTRIBUTING.md \
             LICENSE \
             README.md



TESTS = test/run-tests
check_PROGRAMS = test/run-tests
test_run_tests_CFLAGS =

if SUNOS
# Can't be turned into a CC_CHECK_CFLAGS in configure.ac, it makes compilers
# on other platforms complain that the argument is unused during compilation.
test_run_tests_CFLAGS += -pthreads
endif

test_run_tests_LDFLAGS =
test_run_tests_SOURCES = test/blackhole-server.cpp \
                         test/dns-server.cpp \
                         test/echo-server.cpp \
                         test/run-tests.cpp \
                         test/runner.cpp \
                         test/runner.h \
                         test/task.h \
                         test/test-active.cpp \
                         test/test-async.cpp \
                         test/test-async-null-cb.cpp \
                         test/test-barrier.cpp \
                         test/test-callback-order.cpp \
                         test/test-callback-stack.cpp \
                         test/test-close-fd.cpp \
                         test/test-close-order.cpp \
                         test/test-condvar.cpp \
                         test/test-connect-unspecified.cpp \
                         test/test-connection-fail.cpp \
                         test/test-cwd-and-chdir.cpp \
                         test/test-default-loop-close.cpp \
                         test/test-delayed-accept.cpp \
                         test/test-dlerror.cpp \
                         test/test-eintr-handling.cpp \
                         test/test-embed.cpp \
                         test/test-emfile.cpp \
                         test/test-env-vars.cpp \
                         test/test-error.cpp \
                         test/test-fail-always.cpp \
                         test/test-fs-copyfile.cpp \
                         test/test-fs-event.cpp \
                         test/test-fs-poll.cpp \
                         test/test-fs.cpp \
                         test/test-fs-readdir.cpp \
                         test/test-fs-fd-hash.cpp \
                         test/test-fs-open-flags.cpp \
                         test/test-fork.cpp \
                         test/test-getters-setters.cpp \
                         test/test-get-currentexe.cpp \
                         test/test-get-loadavg.cpp \
                         test/test-get-memory.cpp \
                         test/test-get-passwd.cpp \
                         test/test-getaddrinfo.cpp \
                         test/test-gethostname.cpp \
                         test/test-getnameinfo.cpp \
                         test/test-getsockname.cpp \
                         test/test-gettimeofday.cpp \
                         test/test-handle-fileno.cpp \
                         test/test-homedir.cpp \
                         test/test-hrtime.cpp \
                         test/test-idle.cpp \
                         test/test-idna.cpp \
                         test/test-ip4-addr.cpp \
                         test/test-ip6-addr.cpp \
                         test/test-ipc-heavy-traffic-deadlock-bug.cpp \
                         test/test-ipc-send-recv.cpp \
                         test/test-ipc.cpp \
                         test/test-list.h \
                         test/test-loop-handles.cpp \
                         test/test-loop-alive.cpp \
                         test/test-loop-close.cpp \
                         test/test-loop-stop.cpp \
                         test/test-loop-time.cpp \
                         test/test-loop-configure.cpp \
                         test/test-multiple-listen.cpp \
                         test/test-mutexes.cpp \
                         test/test-osx-select.cpp \
                         test/test-pass-always.cpp \
                         test/test-ping-pong.cpp \
                         test/test-pipe-bind-error.cpp \
                         test/test-pipe-connect-error.cpp \
                         test/test-pipe-connect-multiple.cpp \
                         test/test-pipe-connect-prepare.cpp \
                         test/test-pipe-getsockname.cpp \
                         test/test-pipe-pending-instances.cpp \
                         test/test-pipe-sendmsg.cpp \
                         test/test-pipe-server-close.cpp \
                         test/test-pipe-close-stdout-read-stdin.cpp \
                         test/test-pipe-set-non-blocking.cpp \
                         test/test-pipe-set-fchmod.cpp \
                         test/test-platform-output.cpp \
                         test/test-poll.cpp \
                         test/test-poll-close.cpp \
                         test/test-poll-close-doesnt-corrupt-stack.cpp \
                         test/test-poll-closesocket.cpp \
                         test/test-poll-oob.cpp \
                         test/test-process-priority.cpp \
                         test/test-process-title.cpp \
                         test/test-process-title-threadsafe.cpp \
                         test/test-queue-foreach-delete.cpp \
                         test/test-random.cpp \
                         test/test-ref.cpp \
                         test/test-run-nowait.cpp \
                         test/test-run-once.cpp \
                         test/test-semaphore.cpp \
                         test/test-shutdown-close.cpp \
                         test/test-shutdown-eof.cpp \
                         test/test-shutdown-twice.cpp \
                         test/test-signal-multiple-loops.cpp \
                         test/test-signal-pending-on-close.cpp \
                         test/test-signal.cpp \
                         test/test-socket-buffer-size.cpp \
                         test/test-spawn.cpp \
                         test/test-stdio-over-pipes.cpp \
                         test/test-strscpy.cpp \
                         test/test-tcp-alloc-cb-fail.cpp \
                         test/test-tcp-bind-error.cpp \
                         test/test-tcp-bind6-error.cpp \
                         test/test-tcp-close-accept.cpp \
                         test/test-tcp-close-while-connecting.cpp \
                         test/test-tcp-close.cpp \
                         test/test-tcp-close-reset.cpp \
                         test/test-tcp-create-socket-early.cpp \
                         test/test-tcp-connect-error-after-write.cpp \
                         test/test-tcp-connect-error.cpp \
                         test/test-tcp-connect-timeout.cpp \
                         test/test-tcp-connect6-error.cpp \
                         test/test-tcp-flags.cpp \
                         test/test-tcp-open.cpp \
                         test/test-tcp-read-stop.cpp \
                         test/test-tcp-shutdown-after-write.cpp \
                         test/test-tcp-unexpected-read.cpp \
                         test/test-tcp-oob.cpp \
                         test/test-tcp-write-to-half-open-connection.cpp \
                         test/test-tcp-write-after-connect.cpp \
                         test/test-tcp-writealot.cpp \
                         test/test-tcp-write-fail.cpp \
                         test/test-tcp-try-write.cpp \
                         test/test-tcp-try-write-error.cpp \
                         test/test-tcp-write-queue-order.cpp \
                         test/test-thread-equal.cpp \
                         test/test-thread.cpp \
                         test/test-threadpool-cancel.cpp \
                         test/test-threadpool.cpp \
                         test/test-timer-again.cpp \
                         test/test-timer-from-check.cpp \
                         test/test-timer.cpp \
                         test/test-tmpdir.cpp \
                         test/test-tty-duplicate-key.cpp \
                         test/test-tty-escape-sequence-processing.cpp \
                         test/test-tty.cpp \
                         test/test-udp-alloc-cb-fail.cpp \
                         test/test-udp-bind.cpp \
                         test/test-udp-connect.cpp \
                         test/test-udp-create-socket-early.cpp \
                         test/test-udp-dgram-too-big.cpp \
                         test/test-udp-ipv6.cpp \
                         test/test-udp-multicast-interface.cpp \
                         test/test-udp-multicast-interface6.cpp \
                         test/test-udp-multicast-join.cpp \
                         test/test-udp-multicast-join6.cpp \
                         test/test-udp-multicast-ttl.cpp \
                         test/test-udp-open.cpp \
                         test/test-udp-options.cpp \
                         test/test-udp-send-and-recv.cpp \
                         test/test-udp-send-hang-loop.cpp \
                         test/test-udp-send-immediate.cpp \
                         test/test-udp-send-unreachable.cpp \
                         test/test-udp-try-send.cpp \
                         test/test-uname.cpp \
                         test/test-walk-handles.cpp \
                         test/test-watcher-cross-stop.cpp
test_run_tests_LDADD = libuv.la

if WINNT
test_run_tests_SOURCES += test/runner-win.cpp \
                          test/runner-win.h
else
test_run_tests_SOURCES += test/runner-unix.cpp \
                          test/runner-unix.h
endif

if AIX
test_run_tests_CFLAGS += -D_ALL_SOURCE \
                         -D_XOPEN_SOURCE=500 \
                         -D_LINUX_SOURCE_COMPAT
endif

if OS400
test_run_tests_CFLAGS += -D_ALL_SOURCE \
                         -D_XOPEN_SOURCE=500 \
                         -D_LINUX_SOURCE_COMPAT
endif

if HAIKU
test_run_tests_CFLAGS += -D_BSD_SOURCE
endif

if LINUX
test_run_tests_CFLAGS += -D_GNU_SOURCE
endif

if SUNOS
test_run_tests_CFLAGS += -D__EXTENSIONS__ \
                         -D_XOPEN_SOURCE=500 \
                         -D_REENTRANT
endif

if OS390
test_run_tests_CFLAGS += -D_ISOC99_SOURCE \
                         -D_UNIX03_THREADS \
                         -D_UNIX03_SOURCE \
                         -D_OPEN_SYS_IF_EXT=1 \
                         -D_OPEN_SYS_SOCK_IPV6 \
                         -D_OPEN_MSGQ_EXT \
                         -D_XOPEN_SOURCE_EXTENDED \
                         -D_ALL_SOURCE \
                         -D_LARGE_TIME_API \
                         -D_OPEN_SYS_FILE_EXT \
                         -DPATH_MAX=255 \
                         -qCHARS=signed \
                         -qXPLINK \
                         -qFLOAT=IEEE
endif

if AIX
libuv_la_CFLAGS += -D_ALL_SOURCE \
                   -D_XOPEN_SOURCE=500 \
                   -D_LINUX_SOURCE_COMPAT \
                   -D_THREAD_SAFE \
                   -DHAVE_SYS_AHAFS_EVPRODS_H
uvinclude_HEADERS += include/uv/aix.h
libuv_la_SOURCES += src/unix/aix.cpp src/unix/aix-common.cpp
endif

if OS400
libuv_la_CFLAGS += -D_ALL_SOURCE \
                   -D_XOPEN_SOURCE=500 \
                   -D_LINUX_SOURCE_COMPAT \
                   -D_THREAD_SAFE
uvinclude_HEADERS += include/uv/posix.h
libuv_la_SOURCES += src/unix/aix-common.cpp \
                    src/unix/ibmi.cpp \
                    src/unix/posix-poll.cpp \
                    src/unix/no-fsevents.cpp \
                    src/unix/no-proctitle.cpp
endif

if ANDROID
uvinclude_HEADERS += include/uv/android-ifaddrs.h
libuv_la_SOURCES += src/unix/android-ifaddrs.cpp \
                    src/unix/linux-core.cpp \
                    src/unix/linux-inotify.cpp \
                    src/unix/linux-syscalls.cpp \
                    src/unix/procfs-exepath.cpp \
                    src/unix/pthread-fixes.cpp \
                    src/unix/random-getrandom.cpp \
                    src/unix/random-sysctl-linux.cpp \
                    src/unix/sysinfo-loadavg.cpp
endif

if CYGWIN
uvinclude_HEADERS += include/uv/posix.h
libuv_la_CFLAGS += -D_GNU_SOURCE
libuv_la_SOURCES += src/unix/cygwin.cpp \
                    src/unix/bsd-ifaddrs.cpp \
                    src/unix/no-fsevents.cpp \
                    src/unix/no-proctitle.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/posix-poll.cpp \
                    src/unix/procfs-exepath.cpp \
                    src/unix/sysinfo-loadavg.cpp \
                    src/unix/sysinfo-memory.cpp
endif

if DARWIN
uvinclude_HEADERS += include/uv/darwin.h
libuv_la_CFLAGS += -D_DARWIN_USE_64_BIT_INODE=1
libuv_la_CFLAGS += -D_DARWIN_UNLIMITED_SELECT=1
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/darwin.cpp \
                    src/unix/darwin-proctitle.cpp \
                    src/unix/fsevents.cpp \
                    src/unix/kqueue.cpp \
                    src/unix/proctitle.cpp \
                    src/unix/random-getentropy.cpp
test_run_tests_LDFLAGS += -lutil
endif

if DRAGONFLY
uvinclude_HEADERS += include/uv/bsd.h
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/bsd-proctitle.cpp \
                    src/unix/freebsd.cpp \
                    src/unix/kqueue.cpp \
                    src/unix/posix-hrtime.cpp
test_run_tests_LDFLAGS += -lutil
endif

if FREEBSD
uvinclude_HEADERS += include/uv/bsd.h
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/bsd-proctitle.cpp \
                    src/unix/freebsd.cpp \
                    src/unix/kqueue.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/random-getrandom.cpp
test_run_tests_LDFLAGS += -lutil
endif

if HAIKU
uvinclude_HEADERS += include/uv/posix.h
libuv_la_CFLAGS += -D_BSD_SOURCE
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/haiku.cpp \
                    src/unix/no-fsevents.cpp \
                    src/unix/no-proctitle.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/posix-poll.cpp
endif

if HURD
uvinclude_HEADERS += include/uv/posix.h
libuv_la_SOURCES += src/unix/no-fsevents.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/posix-poll.cpp
endif

if LINUX
uvinclude_HEADERS += include/uv/linux.h
libuv_la_CFLAGS += -D_GNU_SOURCE
libuv_la_SOURCES += src/unix/linux-core.cpp \
                    src/unix/linux-inotify.cpp \
                    src/unix/linux-syscalls.cpp \
                    src/unix/linux-syscalls.h \
                    src/unix/procfs-exepath.cpp \
                    src/unix/proctitle.cpp \
                    src/unix/random-getrandom.cpp \
                    src/unix/random-sysctl-linux.cpp \
                    src/unix/sysinfo-loadavg.cpp
test_run_tests_LDFLAGS += -lutil
endif

if MSYS
libuv_la_CFLAGS += -D_GNU_SOURCE
libuv_la_SOURCES += src/unix/cygwin.cpp \
                    src/unix/bsd-ifaddrs.cpp \
                    src/unix/no-fsevents.cpp \
                    src/unix/no-proctitle.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/posix-poll.cpp \
                    src/unix/procfs-exepath.cpp \
                    src/unix/sysinfo-loadavg.cpp \
                    src/unix/sysinfo-memory.cpp
endif

if NETBSD
uvinclude_HEADERS += include/uv/bsd.h
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/bsd-proctitle.cpp \
                    src/unix/kqueue.cpp \
                    src/unix/netbsd.cpp \
                    src/unix/posix-hrtime.cpp
test_run_tests_LDFLAGS += -lutil
endif

if OPENBSD
uvinclude_HEADERS += include/uv/bsd.h
libuv_la_SOURCES += src/unix/bsd-ifaddrs.cpp \
                    src/unix/bsd-proctitle.cpp \
                    src/unix/kqueue.cpp \
                    src/unix/openbsd.cpp \
                    src/unix/posix-hrtime.cpp \
                    src/unix/random-getentropy.cpp
test_run_tests_LDFLAGS += -lutil
endif

if SUNOS
uvinclude_HEADERS += include/uv/sunos.h
libuv_la_CFLAGS += -D__EXTENSIONS__ \
                   -D_XOPEN_SOURCE=500 \
                   -D_REENTRANT
libuv_la_SOURCES += src/unix/no-proctitle.cpp \
                    src/unix/sunos.cpp
endif

if OS390
libuv_la_CFLAGS += -D_UNIX03_THREADS \
                   -D_UNIX03_SOURCE \
                   -D_OPEN_SYS_IF_EXT=1 \
                   -D_OPEN_MSGQ_EXT \
                   -D_XOPEN_SOURCE_EXTENDED \
                   -D_ALL_SOURCE \
                   -D_LARGE_TIME_API \
                   -D_OPEN_SYS_SOCK_EXT3 \
                   -D_OPEN_SYS_SOCK_IPV6 \
                   -D_OPEN_SYS_FILE_EXT \
                   -DUV_PLATFORM_SEM_T=int \
                   -DPATH_MAX=255 \
                   -qCHARS=signed \
                   -qXPLINK \
                   -qFLOAT=IEEE
libuv_la_LDFLAGS += -qXPLINK
libuv_la_SOURCES += src/unix/pthread-fixes.cpp \
                    src/unix/os390.cpp \
                    src/unix/os390-syscalls.cpp \
                    src/unix/proctitle.cpp
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc
