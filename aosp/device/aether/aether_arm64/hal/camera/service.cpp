// Minimum AETHER camera HAL stub.
//
// Reports zero cameras via Provider getCameraIdList(). Apps that request
// android.permission.CAMERA still get the grant, but enumeration returns
// empty. This matches ch21's design — AETHER doesn't proxy the host camera
// (host opaqueness per CLAUDE.md No-Boundary Principle).

#include <android-base/logging.h>
#include <hidl/HidlTransportSupport.h>

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

int main(int /*argc*/, char** /*argv*/) {
    LOG(INFO) << "aether.camera@2.7-service: AETHER stub (no cameras)";
    configureRpcThreadpool(1, true);
    joinRpcThreadpool();
    return 0;
}
