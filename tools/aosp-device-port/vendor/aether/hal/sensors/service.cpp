// aether.sensors@2.1-service — skeleton.
//
// Registers as android.hardware.sensors@2.1::ISensors / "default" so the
// Treble HAL manifest is satisfied and SensorService can attach. Returns an
// empty sensor list for now.
//
// Phase 6 wires this to the AETHER HVC sensor ABI defined in
// hypervisor/src/virtual_sensors_modem.rs (HVC 0x86000004,
// HvcSensorId 0=Accel / 1=Gyro / 2=Mag / 3=Prox) which surfaces
// VirtualSensorSuite (Gaussian-noise Irwin-Hall CLT samples).

#include <android-base/logging.h>
#include <android/hardware/sensors/2.1/ISensors.h>
#include <hidl/HidlTransportSupport.h>

using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;
using ::android::hardware::sensors::V2_1::ISensors;

int main(int, char**) {
    LOG(INFO) << "aether.sensors@2.1-service starting (skeleton; HVC wiring deferred to Phase 6).";
    configureRpcThreadpool(1, true /* willJoin */);

    // TODO(phase6): instantiate AetherSensorsImpl that issues HVC 0x86000004
    // to read live VirtualSensorSuite samples from EL2. For now the service
    // simply does not register an implementation — SensorService treats this
    // as "no sensors" without crashing.

    joinRpcThreadpool();
    return 1;  // joinRpcThreadpool should never return; non-zero on exit.
}
