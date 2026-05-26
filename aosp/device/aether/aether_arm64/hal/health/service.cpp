// Minimum AETHER health HAL stub.
//
// First-pass: no IHealth registration; SystemUI shows whatever defaults the
// framework gives when no health HAL responds. Full implementation reports
// fixed-100% battery (host battery is invisible to the guest per CLAUDE.md
// Host Opaqueness invariant) and a synthetic "discharging" status.

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

int main(int /*argc*/, char** /*argv*/) {
    LOG(INFO) << "aether.health@2.1-service: AETHER stub "
              << "(framework defaults will surface a placeholder battery)";
    configureRpcThreadpool(1, true);
    joinRpcThreadpool();
    return 0;
}
