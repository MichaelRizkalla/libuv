#include "uv.h"
#include "internal.h"
#include "winapi.h"

static void uv__register_system_resume_callback();

void uv__init_detect_system_wakeup() {
  /* Try registering system power event callback. This is the cleanest
   * method, but it will only work on Win8 and above.
   */
  uv__register_system_resume_callback();
}

static ULONG CALLBACK uv__system_resume_callback(PVOID Context,
                                                 ULONG Type,
                                                 PVOID Setting) {
  (void) Context, Setting;
  if (Type == PBT_APMRESUMESUSPEND || Type == PBT_APMRESUMEAUTOMATIC)
    uv__wake_all_loops();

  return 0;
}

static void uv__register_system_resume_callback() {
  if (pPowerRegisterSuspendResumeNotification == nullptr)
    return;

  auto recipient = _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS{};
  auto registration_handle = _HPOWERNOTIFY{};

  recipient.Callback = uv__system_resume_callback;
  recipient.Context = nullptr;
  (*pPowerRegisterSuspendResumeNotification)(DEVICE_NOTIFY_CALLBACK,
                                             &recipient,
                                             &registration_handle);
}
