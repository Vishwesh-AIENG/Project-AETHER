// aether.camera@2.7-service — skeleton ("no camera available").
//
// Registers an empty ICameraProvider so apps that check for camera presence
// receive an honest "no cameras" response. Phase 6 may wire this to a Phone
// Bridge passthrough that forwards frames from a USB-attached Android phone.

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;

int main(int, char**) {
    LOG(INFO) << "aether.camera@2.7-service starting (skeleton; no cameras exposed).";
    configureRpcThreadpool(1, true);

    // TODO(phase6 optional): if Phone Bridge is active, register a
    // passthrough ICameraProvider that surfaces the bridged phone's camera.

    joinRpcThreadpool();
    return 1;
}
