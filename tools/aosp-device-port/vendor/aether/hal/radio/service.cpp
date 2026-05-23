// aether.radio@2.0-service — skeleton.
//
// Registers as android.hardware.radio@2.0::IRadio / "default" so the Treble
// manifest is satisfied. Default behaviour: report "No SIM" (matches
// VirtualModem default state in hypervisor/src/paravirt.rs::VirtualModem::
// reg_state = NotRegistered).
//
// Phase 6 wires this to the AETHER paravirt modem shared page at
// AETHER_MODEM_IPA=0x0B000000 (cmd_buf / resp_buf), polled via the WFI
// exit hook in EL2.

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;

int main(int, char**) {
    LOG(INFO) << "aether.radio@2.0-service starting (skeleton; modem shared-page wiring deferred to Phase 6).";
    configureRpcThreadpool(2, true);

    // TODO(phase6): map /dev/aether/modem (4 KiB shared page), implement the
    // AT-command transport on top of it, and register IRadio::default.
    // Default response set: AT+CPIN? -> "SIM NOT INSERTED"; AT+CIMI -> ERROR.

    joinRpcThreadpool();
    return 1;
}
