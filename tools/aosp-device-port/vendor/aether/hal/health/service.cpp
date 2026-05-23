// aether.health@2.1-service — skeleton.
//
// AETHER has no battery (it runs on AC); this HAL reports
// "AC powered, 100% battery, GOOD status" so Android UI does not show a
// flat-battery indicator. Phone Bridge mode (Phase 6) may replace this
// with real battery telemetry forwarded from the USB-attached phone.

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;

int main(int, char**) {
    LOG(INFO) << "aether.health@2.1-service starting (skeleton; reports AC powered, 100%).";
    configureRpcThreadpool(1, true);

    // TODO(phase6): instantiate AetherHealthImpl that returns:
    //   batteryStatus = CHARGING; batteryHealth = GOOD;
    //   batteryLevel = 100; chargerAcOnline = true;
    //   chargerUsbOnline = false; chargerWirelessOnline = false.

    joinRpcThreadpool();
    return 1;
}
