// Minimum AETHER power HAL stub (AIDL).
//
// Registers no IPower implementation. SystemUI falls back to defaults for
// power-state queries. Doesn't block boot.

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

int main(int /*argc*/, char** /*argv*/) {
    LOG(INFO) << "aether.power@5-service: AETHER stub";
    ABinderProcess_setThreadPoolMaxThreadCount(1);
    ABinderProcess_startThreadPool();
    ABinderProcess_joinThreadPool();
    return 0;
}
