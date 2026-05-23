// aether.power@5-service — AIDL skeleton.
//
// Registers android.hardware.power.IPower / "default". Power hints are
// routed to PSCI CPU_SUSPEND via the hypervisor's HVC dispatch
// (hypervisor/src/cpu.rs::handle_psci_call). For now the stub accepts
// every hint and returns success without forwarding.

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

int main(int, char**) {
    LOG(INFO) << "aether.power@5-service starting (skeleton; PSCI forwarding deferred to Phase 6).";

    ABinderProcess_setThreadPoolMaxThreadCount(2);
    ABinderProcess_startThreadPool();

    // TODO(phase6): instantiate AetherPowerImpl that issues PSCI_CPU_SUSPEND
    // (0xC4000001) on low-power hints and PSCI_CPU_OFF on hot-unplug.

    ABinderProcess_joinThreadPool();
    return 1;
}
