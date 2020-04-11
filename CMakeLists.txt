cmake_minimum_required(VERSION 3.4)

project(libuv LANGUAGES CXX)

cmake_policy(SET CMP0057 NEW) # Enable IN_LIST operator
cmake_policy(SET CMP0064 NEW) # Support if (TEST) operator

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(GNUInstallDirs)
include(CTest)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 17)

cmake_dependent_option(LIBUV_BUILD_TESTS
  "Build the unit tests when BUILD_TESTING is enabled and we are the root project" ON
  "BUILD_TESTING;CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)
cmake_dependent_option(LIBUV_BUILD_BENCH
  "Build the benchmarks when building unit tests and we are the root project" ON
  "LIBUV_BUILD_TESTS" OFF)

# Compiler check
string(CONCAT is-msvc $<OR:
  $<CXX_COMPILER_ID:MSVC>,
  $<STREQUAL:${CMAKE_CXX_COMPILER_FRONTEND_VARIANT},MSVC>
>)

check_cxx_compiler_flag(/W4 UV_LINT_W4)
check_cxx_compiler_flag(-Wall UV_LINT_WALL) # DO NOT use this under MSVC

# TODO: Place these into its own function
check_cxx_compiler_flag(-Wno-unused-parameter UV_LINT_NO_UNUSED_PARAMETER)
check_cxx_compiler_flag(-Wstrict-prototypes UV_LINT_STRICT_PROTOTYPES)
check_cxx_compiler_flag(-Wextra UV_LINT_EXTRA)

set(lint-no-unused-parameter $<$<BOOL:${UV_LINT_NO_UNUSED_PARAMETER}>:-Wno-unused-parameter>) 
set(lint-strict-prototypes $<$<BOOL:${UV_LINT_STRICT_PROTOTYPES}>:-Wstrict-prototypes>)
set(lint-extra $<$<BOOL:${UV_LINT_EXTRA}>:-Wextra>)
set(lint-w4 $<$<BOOL:${UV_LINT_W4}>:/W4>)
# Unfortunately, this one is complicated because MSVC and clang-cl support -Wall
# but using it is like calling -Weverything
string(CONCAT lint-default $<
  $<AND:$<BOOL:${UV_LINT_WALL}>,$<NOT:${is-msvc}>>:-Wall
>)

list(APPEND uv_cflags ${lint-strict-prototypes} ${lint-extra} ${lint-default} ${lint-w4})
list(APPEND uv_cflags ${lint-no-unused-parameter})

set(uv_sources
    src/fs-poll.cpp
    src/idna.cpp
    src/inet.cpp
    src/random.cpp
    src/strscpy.cpp
    src/threadpool.cpp
    src/timer.cpp
    src/uv-common.cpp
    src/uv-data-getter-setters.cpp
    src/version.cpp)

if(WIN32)
  if (CMAKE_SYSTEM_VERSION VERSION_GREATER 10) # Windows 10
    set(windows-version 0x0A00)
  elseif (CMAKE_SYSTEM_VERSION VERSION_GREATER 6.3) # Windows 8.1
    set(windows-version 0x0603)
  elseif (CMAKE_SYSTEM_VERSION VERSION_GREATER 6.2) # Windows 8
    set(windows-version 0x0602)
  elseif (CMAKE_SYSTEM_VERSION VERSION_GREATER 6.1) # Windows 7
    set(windows-version 0x0601)
  elseif (CMAKE_SYSTEM_VERSION VERSION_GREATER 6.0) # Windows Vista
    set(windows-version 0x0600)
  else()
    message(FATAL_ERROR "Windows Vista is the minimum version supported")
  endif()
  list(APPEND uv_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=${windows-version})
  list(APPEND uv_libraries
       $<$<STREQUAL:${windows-version},0x0600>:psapi>
       iphlpapi
       userenv
       ws2_32)
  list(APPEND uv_sources
       src/win/async.cpp
       src/win/core.cpp
       src/win/detect-wakeup.cpp
       src/win/dl.cpp
       src/win/error.cpp
       src/win/fs.cpp
       src/win/fs-event.cpp
       src/win/getaddrinfo.cpp
       src/win/getnameinfo.cpp
       src/win/handle.cpp
       src/win/loop-watcher.cpp
       src/win/pipe.cpp
       src/win/thread.cpp
       src/win/poll.cpp
       src/win/process.cpp
       src/win/process-stdio.cpp
       src/win/signal.cpp
       src/win/snprintf.cpp
       src/win/stream.cpp
       src/win/tcp.cpp
       src/win/tty.cpp
       src/win/udp.cpp
       src/win/util.cpp
       src/win/winapi.cpp
       src/win/winsock.cpp)
  list(APPEND uv_test_libraries ws2_32)
  list(APPEND uv_test_sources src/win/snprintf.cpp test/runner-win.cpp)
else()
  list(APPEND uv_defines _FILE_OFFSET_BITS=64 _LARGEFILE_SOURCE)
  if(NOT CMAKE_SYSTEM_NAME MATCHES "Android|OS390")
    # TODO: This should be replaced with find_package(Threads) if possible
    # Android has pthread as part of its c library, not as a separate
    # libpthread.so.
    list(APPEND uv_libraries pthread)
  endif()
  list(APPEND uv_sources
       src/unix/async.cpp
       src/unix/core.cpp
       src/unix/dl.cpp
       src/unix/fs.cpp
       src/unix/getaddrinfo.cpp
       src/unix/getnameinfo.cpp
       src/unix/loop-watcher.cpp
       src/unix/loop.cpp
       src/unix/pipe.cpp
       src/unix/poll.cpp
       src/unix/process.cpp
       src/unix/random-devurandom.cpp
       src/unix/signal.cpp
       src/unix/stream.cpp
       src/unix/tcp.cpp
       src/unix/thread.cpp
       src/unix/tty.cpp
       src/unix/udp.cpp)
  list(APPEND uv_test_sources test/runner-unix.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  list(APPEND uv_defines
       _ALL_SOURCE
       _LINUX_SOURCE_COMPAT
       _THREAD_SAFE
       _XOPEN_SOURCE=500
       HAVE_SYS_AHAFS_EVPRODS_H)
  list(APPEND uv_libraries perfstat)
  list(APPEND uv_sources
       src/unix/aix.cpp
       src/unix/aix-common.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  list(APPEND uv_libs dl)
  list(APPEND uv_sources
       src/unix/android-ifaddrs.cpp
       src/unix/linux-core.cpp
       src/unix/linux-inotify.cpp
       src/unix/linux-syscalls.cpp
       src/unix/procfs-exepath.cpp
       src/unix/pthread-fixes.cpp
       src/unix/random-getentropy.cpp
       src/unix/random-getrandom.cpp
       src/unix/random-sysctl-linux.cpp
       src/unix/sysinfo-loadavg.cpp)
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "Android|Linux|OS390")
  list(APPEND uv_sources src/unix/proctitle.cpp)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD")
  list(APPEND uv_sources src/unix/freebsd.cpp)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  list(APPEND uv_sources src/unix/posix-hrtime.cpp src/unix/bsd-proctitle.cpp)
  list(APPEND uv_libraries kvm)
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  list(APPEND uv_sources src/unix/bsd-ifaddrs.cpp src/unix/kqueue.cpp)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  list(APPEND uv_sources src/unix/random-getrandom.cpp)
endif()

if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND uv_sources src/unix/random-getentropy.cpp)
endif()

if(APPLE)
  list(APPEND uv_defines _DARWIN_UNLIMITED_SELECT=1 _DARWIN_USE_64_BIT_INODE=1)
  list(APPEND uv_sources
       src/unix/darwin-proctitle.cpp
       src/unix/darwin.cpp
       src/unix/fsevents.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND uv_defines _GNU_SOURCE _POSIX_C_SOURCE=200112)
  list(APPEND uv_libraries dl rt)
  list(APPEND uv_sources
       src/unix/linux-core.cpp
       src/unix/linux-inotify.cpp
       src/unix/linux-syscalls.cpp
       src/unix/procfs-exepath.cpp
       src/unix/random-getrandom.cpp
       src/unix/random-sysctl-linux.cpp
       src/unix/sysinfo-loadavg.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  list(APPEND uv_sources src/unix/netbsd.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND uv_sources src/unix/openbsd.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OS390")
  list(APPEND uv_defines PATH_MAX=255)
  list(APPEND uv_defines _AE_BIMODAL)
  list(APPEND uv_defines _ALL_SOURCE)
  list(APPEND uv_defines _ISOC99_SOURCE)
  list(APPEND uv_defines _LARGE_TIME_API)
  list(APPEND uv_defines _OPEN_MSGQ_EXT)
  list(APPEND uv_defines _OPEN_SYS_FILE_EXT)
  list(APPEND uv_defines _OPEN_SYS_IF_EXT)
  list(APPEND uv_defines _OPEN_SYS_SOCK_EXT3)
  list(APPEND uv_defines _OPEN_SYS_SOCK_IPV6)
  list(APPEND uv_defines _UNIX03_SOURCE)
  list(APPEND uv_defines _UNIX03_THREADS)
  list(APPEND uv_defines _UNIX03_WITHDRAWN)
  list(APPEND uv_defines _XOPEN_SOURCE_EXTENDED)
  list(APPEND uv_sources
       src/unix/pthread-fixes.cpp
       src/unix/os390.cpp
       src/unix/os390-syscalls.cpp)
  list(APPEND uv_cflags -Wc,DLL -Wc,exportall -Wc,xplink)
  list(APPEND uv_libraries -Wl,xplink)
  list(APPEND uv_test_libraries -Wl,xplink)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OS400")
  list(APPEND uv_defines
       _ALL_SOURCE
       _LINUX_SOURCE_COMPAT
       _THREAD_SAFE
       _XOPEN_SOURCE=500)
  list(APPEND uv_sources
    src/unix/aix-common.cpp
    src/unix/ibmi.cpp
    src/unix/no-fsevents.cpp
    src/unix/no-proctitle.cpp
    src/unix/posix-poll.cpp)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  list(APPEND uv_defines __EXTENSIONS__ _XOPEN_SOURCE=500)
  list(APPEND uv_libraries kstat nsl sendfile socket)
  list(APPEND uv_sources src/unix/no-proctitle.cpp src/unix/sunos.cpp)
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|Linux|NetBSD|OpenBSD")
  list(APPEND uv_test_libraries util)
endif()

add_library(uv SHARED ${uv_sources})
target_compile_definitions(uv
  INTERFACE
    USING_UV_SHARED=1
  PRIVATE
    BUILDING_UV_SHARED=1
    ${uv_defines})
target_compile_options(uv PRIVATE ${uv_cflags})
target_include_directories(uv
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
target_link_libraries(uv ${uv_libraries})

add_library(uv_a STATIC ${uv_sources})
target_compile_definitions(uv_a PRIVATE ${uv_defines})
target_compile_options(uv_a PRIVATE ${uv_cflags})
target_include_directories(uv_a
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
target_link_libraries(uv_a ${uv_libraries})

if(LIBUV_BUILD_TESTS)
  # Small hack: use ${uv_test_sources} now to get the runner skeleton,
  # before the actual tests are added.
  add_executable(
    uv_run_benchmarks_a
    ${uv_test_sources}
    test/benchmark-async-pummel.cpp
    test/benchmark-async.cpp
    test/benchmark-fs-stat.cpp
    test/benchmark-getaddrinfo.cpp
    test/benchmark-loop-count.cpp
    test/benchmark-million-async.cpp
    test/benchmark-million-timers.cpp
    test/benchmark-multi-accept.cpp
    test/benchmark-ping-pongs.cpp
    test/benchmark-ping-udp.cpp
    test/benchmark-pound.cpp
    test/benchmark-pump.cpp
    test/benchmark-sizes.cpp
    test/benchmark-spawn.cpp
    test/benchmark-tcp-write-batch.cpp
    test/benchmark-thread.cpp
    test/benchmark-udp-pummel.cpp
    test/blackhole-server.cpp
    test/dns-server.cpp
    test/echo-server.cpp
    test/run-benchmarks.cpp
    test/runner.cpp)
  target_compile_definitions(uv_run_benchmarks_a PRIVATE ${uv_defines})
  target_compile_options(uv_run_benchmarks_a PRIVATE ${uv_cflags})
  target_link_libraries(uv_run_benchmarks_a uv_a ${uv_test_libraries})

  list(APPEND uv_test_sources
       test/blackhole-server.cpp
       test/echo-server.cpp
       test/run-tests.cpp
       test/runner.cpp
       test/test-active.cpp
       test/test-async-null-cb.cpp
       test/test-async.cpp
       test/test-barrier.cpp
       test/test-callback-order.cpp
       test/test-callback-stack.cpp
       test/test-close-fd.cpp
       test/test-close-order.cpp
       test/test-condvar.cpp
       test/test-connect-unspecified.cpp
       test/test-connection-fail.cpp
       test/test-cwd-and-chdir.cpp
       test/test-default-loop-close.cpp
       test/test-delayed-accept.cpp
       test/test-dlerror.cpp
       test/test-eintr-handling.cpp
       test/test-embed.cpp
       test/test-emfile.cpp
       test/test-env-vars.cpp
       test/test-error.cpp
       test/test-fail-always.cpp
       test/test-fork.cpp
       test/test-fs-copyfile.cpp
       test/test-fs-event.cpp
       test/test-fs-poll.cpp
       test/test-fs.cpp
       test/test-fs-readdir.cpp
       test/test-fs-fd-hash.cpp
       test/test-fs-open-flags.cpp
       test/test-get-currentexe.cpp
       test/test-get-loadavg.cpp
       test/test-get-memory.cpp
       test/test-get-passwd.cpp
       test/test-getaddrinfo.cpp
       test/test-gethostname.cpp
       test/test-getnameinfo.cpp
       test/test-getsockname.cpp
       test/test-getters-setters.cpp
       test/test-gettimeofday.cpp
       test/test-handle-fileno.cpp
       test/test-homedir.cpp
       test/test-hrtime.cpp
       test/test-idle.cpp
       test/test-idna.cpp
       test/test-ip4-addr.cpp
       test/test-ip6-addr.cpp
       test/test-ipc-heavy-traffic-deadlock-bug.cpp
       test/test-ipc-send-recv.cpp
       test/test-ipc.cpp
       test/test-loop-alive.cpp
       test/test-loop-close.cpp
       test/test-loop-configure.cpp
       test/test-loop-handles.cpp
       test/test-loop-stop.cpp
       test/test-loop-time.cpp
       test/test-multiple-listen.cpp
       test/test-mutexes.cpp
       test/test-osx-select.cpp
       test/test-pass-always.cpp
       test/test-ping-pong.cpp
       test/test-pipe-bind-error.cpp
       test/test-pipe-close-stdout-read-stdin.cpp
       test/test-pipe-connect-error.cpp
       test/test-pipe-connect-multiple.cpp
       test/test-pipe-connect-prepare.cpp
       test/test-pipe-getsockname.cpp
       test/test-pipe-pending-instances.cpp
       test/test-pipe-sendmsg.cpp
       test/test-pipe-server-close.cpp
       test/test-pipe-set-fchmod.cpp
       test/test-pipe-set-non-blocking.cpp
       test/test-platform-output.cpp
       test/test-poll-close-doesnt-corrupt-stack.cpp
       test/test-poll-close.cpp
       test/test-poll-closesocket.cpp
       test/test-poll-oob.cpp
       test/test-poll.cpp
       test/test-process-priority.cpp
       test/test-process-title-threadsafe.cpp
       test/test-process-title.cpp
       test/test-queue-foreach-delete.cpp
       test/test-random.cpp
       test/test-ref.cpp
       test/test-run-nowait.cpp
       test/test-run-once.cpp
       test/test-semaphore.cpp
       test/test-shutdown-close.cpp
       test/test-shutdown-eof.cpp
       test/test-shutdown-twice.cpp
       test/test-signal-multiple-loops.cpp
       test/test-signal-pending-on-close.cpp
       test/test-signal.cpp
       test/test-socket-buffer-size.cpp
       test/test-spawn.cpp
       test/test-stdio-over-pipes.cpp
       test/test-strscpy.cpp
       test/test-tcp-alloc-cb-fail.cpp
       test/test-tcp-bind-error.cpp
       test/test-tcp-bind6-error.cpp
       test/test-tcp-close-accept.cpp
       test/test-tcp-close-while-connecting.cpp
       test/test-tcp-close.cpp
       test/test-tcp-close-reset.cpp
       test/test-tcp-connect-error-after-write.cpp
       test/test-tcp-connect-error.cpp
       test/test-tcp-connect-timeout.cpp
       test/test-tcp-connect6-error.cpp
       test/test-tcp-create-socket-early.cpp
       test/test-tcp-flags.cpp
       test/test-tcp-oob.cpp
       test/test-tcp-open.cpp
       test/test-tcp-read-stop.cpp
       test/test-tcp-shutdown-after-write.cpp
       test/test-tcp-try-write.cpp
       test/test-tcp-try-write-error.cpp
       test/test-tcp-unexpected-read.cpp
       test/test-tcp-write-after-connect.cpp
       test/test-tcp-write-fail.cpp
       test/test-tcp-write-queue-order.cpp
       test/test-tcp-write-to-half-open-connection.cpp
       test/test-tcp-writealot.cpp
       test/test-thread-equal.cpp
       test/test-thread.cpp
       test/test-threadpool-cancel.cpp
       test/test-threadpool.cpp
       test/test-timer-again.cpp
       test/test-timer-from-check.cpp
       test/test-timer.cpp
       test/test-tmpdir.cpp
       test/test-tty-duplicate-key.cpp
       test/test-tty-escape-sequence-processing.cpp
       test/test-tty.cpp
       test/test-udp-alloc-cb-fail.cpp
       test/test-udp-bind.cpp
       test/test-udp-connect.cpp
       test/test-udp-create-socket-early.cpp
       test/test-udp-dgram-too-big.cpp
       test/test-udp-ipv6.cpp
       test/test-udp-multicast-interface.cpp
       test/test-udp-multicast-interface6.cpp
       test/test-udp-multicast-join.cpp
       test/test-udp-multicast-join6.cpp
       test/test-udp-multicast-ttl.cpp
       test/test-udp-open.cpp
       test/test-udp-options.cpp
       test/test-udp-send-and-recv.cpp
       test/test-udp-send-hang-loop.cpp
       test/test-udp-send-immediate.cpp
       test/test-udp-send-unreachable.cpp
       test/test-udp-try-send.cpp
       test/test-uname.cpp
       test/test-walk-handles.cpp
       test/test-watcher-cross-stop.cpp)

  add_executable(uv_run_tests ${uv_test_sources})
  target_compile_definitions(uv_run_tests
                             PRIVATE ${uv_defines} USING_UV_SHARED=1)
  target_compile_options(uv_run_tests PRIVATE ${uv_cflags})
  target_link_libraries(uv_run_tests uv ${uv_test_libraries})
  add_test(NAME uv_test
           COMMAND uv_run_tests
           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  if(CMAKE_SYSTEM_NAME STREQUAL "OS390")
    set_tests_properties(uv_test PROPERTIES ENVIRONMENT
                         "LIBPATH=${CMAKE_BINARY_DIR}:$ENV{LIBPATH}")
  endif()
  add_executable(uv_run_tests_a ${uv_test_sources})
  target_compile_definitions(uv_run_tests_a PRIVATE ${uv_defines})
  target_compile_options(uv_run_tests_a PRIVATE ${uv_cflags})
  target_link_libraries(uv_run_tests_a uv_a ${uv_test_libraries})
  add_test(NAME uv_test_a
           COMMAND uv_run_tests_a
           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

if(UNIX)
  # Now for some gibbering horrors from beyond the stars...
  foreach(lib IN LISTS uv_libraries)
    list(APPEND LIBS "-l${lib}")
  endforeach()
  string(REPLACE ";" " " LIBS "${LIBS}")
  # Consider setting project version via project() call?
  file(STRINGS configure.ac configure_ac REGEX ^AC_INIT)
  string(REGEX MATCH "([0-9]+)[.][0-9]+[.][0-9]+" PACKAGE_VERSION "${configure_ac}")
  set(UV_VERSION_MAJOR "${CMAKE_MATCH_1}")
  # The version in the filename is mirroring the behaviour of autotools.
  set_target_properties(uv PROPERTIES
    VERSION ${UV_VERSION_MAJOR}.0.0
    SOVERSION ${UV_VERSION_MAJOR})
  set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
  set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
  set(prefix ${CMAKE_INSTALL_PREFIX})
  configure_file(libuv.pc.in libuv.pc @ONLY)

  install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
  install(FILES ${PROJECT_BINARY_DIR}/libuv.pc
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
  install(TARGETS uv LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(TARGETS uv_a ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if(WIN32)
  install(DIRECTORY include/ DESTINATION include)
  install(FILES LICENSE DESTINATION .)
  install(TARGETS uv uv_a
          RUNTIME DESTINATION lib/$<CONFIG>
          ARCHIVE DESTINATION lib/$<CONFIG>)
endif()
