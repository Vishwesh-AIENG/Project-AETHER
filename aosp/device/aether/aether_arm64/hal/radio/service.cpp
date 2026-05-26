// Minimum AETHER radio HAL service stub.
//
// First-pass implementation: register no concrete RIL. AOSP boot reaches the
// home screen without telephony — TelephonyManager simply reports "no
// service". The full VirtualModem (paravirt shared page at AETHER_MODEM_IPA,
// AT command set, "SIM NOT INSERTED" responses) wires in alongside the AT
// integration translator coverage.
//
// See hypervisor/src/paravirt.rs::VirtualModem for the spec.

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

int main(int /*argc*/, char** /*argv*/) {
    LOG(INFO) << "aether.radio@2.0-service: AETHER stub starting "
              << "(telephony will report 'no service' until VirtualModem lands)";
    configureRpcThreadpool(1, true);
    joinRpcThreadpool();
    return 0;
}
