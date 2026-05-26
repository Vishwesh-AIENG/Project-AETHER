// Minimum AETHER sensors HAL service stub.
//
// First-pass implementation: register no concrete sensor and idle. Apps that
// query the sensor service via SensorManager will see "no sensors available".
// This is enough to satisfy Soong, satisfy the VINTF declaration, and let
// Android boot. Full VirtualSensorSuite (BMI160 accel/gyro, BMM150 mag) gets
// wired in once the AT integration plan's translator coverage broadens enough
// to safely run guest userspace.
//
// See hypervisor/src/paravirt.rs::VirtualSensorSuite for the spec the real
// implementation must honour (Gaussian noise via Irwin-Hall CLT n=12, gyro
// bias drift, etc.).

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

#include <chrono>
#include <thread>

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

int main(int /*argc*/, char** /*argv*/) {
    LOG(INFO) << "aether.sensors@2.1-service: AETHER stub starting "
              << "(no concrete sensors registered in this build)";
    configureRpcThreadpool(1, true /*callerWillJoin*/);
    joinRpcThreadpool();
    return 0;
}
