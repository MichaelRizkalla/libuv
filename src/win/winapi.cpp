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


/* Ntdll function pointers */
sRtlGetVersion pRtlGetVersion;
sRtlNtStatusToDosError pRtlNtStatusToDosError;
sNtDeviceIoControlFile pNtDeviceIoControlFile;
sNtQueryInformationFile pNtQueryInformationFile;
sNtSetInformationFile pNtSetInformationFile;
sNtQueryVolumeInformationFile pNtQueryVolumeInformationFile;
sNtQueryDirectoryFile pNtQueryDirectoryFile;
sNtQuerySystemInformation pNtQuerySystemInformation;
sNtQueryInformationProcess pNtQueryInformationProcess;

/* Kernel32 function pointers */
sGetQueuedCompletionStatusEx pGetQueuedCompletionStatusEx;

/* Powrprof.dll function pointer */
sPowerRegisterSuspendResumeNotification pPowerRegisterSuspendResumeNotification;

/* User32.dll function pointer */
sSetWinEventHook pSetWinEventHook;


void uv_winapi_init() {
  HMODULE ntdll_module;
  HMODULE powrprof_module;
  HMODULE user32_module;
  HMODULE kernel32_module;

  ntdll_module = GetModuleHandleA("ntdll.dll");
  if (ntdll_module == nullptr) {
    uv_fatal_error(GetLastError(), "GetModuleHandleA");
  }

  pRtlGetVersion = reinterpret_cast<sRtlGetVersion>(GetProcAddress(ntdll_module,
                                                   "RtlGetVersion"));

  pRtlNtStatusToDosError = reinterpret_cast<sRtlNtStatusToDosError>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "RtlNtStatusToDosError"));
  if (pRtlNtStatusToDosError == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtDeviceIoControlFile = reinterpret_cast<sNtDeviceIoControlFile>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "NtDeviceIoControlFile"));
  if (pNtDeviceIoControlFile == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtQueryInformationFile = reinterpret_cast<sNtQueryInformationFile>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "NtQueryInformationFile"));
  if (pNtQueryInformationFile == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtSetInformationFile = reinterpret_cast<sNtSetInformationFile>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "NtSetInformationFile"));
  if (pNtSetInformationFile == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtQueryVolumeInformationFile = reinterpret_cast<sNtQueryVolumeInformationFile>
      (GetProcAddress(ntdll_module, "NtQueryVolumeInformationFile"));
  if (pNtQueryVolumeInformationFile == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtQueryDirectoryFile = reinterpret_cast<sNtQueryDirectoryFile>
      (GetProcAddress(ntdll_module, "NtQueryDirectoryFile"));
  if (pNtQueryVolumeInformationFile == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtQuerySystemInformation = reinterpret_cast<sNtQuerySystemInformation>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "NtQuerySystemInformation"));
  if (pNtQuerySystemInformation == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  pNtQueryInformationProcess = reinterpret_cast<sNtQueryInformationProcess>(GetProcAddress(
                                                                        ntdll_module,
                                                                        "NtQueryInformationProcess"));
  if (pNtQueryInformationProcess == nullptr) {
    uv_fatal_error(GetLastError(), "GetProcAddress");
  }

  kernel32_module = GetModuleHandleA("kernel32.dll");
  if (kernel32_module == nullptr) {
    uv_fatal_error(GetLastError(), "GetModuleHandleA");
  }

  pGetQueuedCompletionStatusEx = reinterpret_cast<sGetQueuedCompletionStatusEx>(GetProcAddress(
                                                                        kernel32_module,
                                                                        "GetQueuedCompletionStatusEx"));

  powrprof_module = LoadLibraryA("powrprof.dll");
  if (powrprof_module != nullptr) {
    pPowerRegisterSuspendResumeNotification = reinterpret_cast<sPowerRegisterSuspendResumeNotification>
      (GetProcAddress(powrprof_module, "PowerRegisterSuspendResumeNotification"));
  }

  user32_module = LoadLibraryA("user32.dll");
  if (user32_module != nullptr) {
    pSetWinEventHook = reinterpret_cast<sSetWinEventHook>
      (GetProcAddress(user32_module, "SetWinEventHook"));
  }
}
