// Minimum AETHER gralloc.aether stub.
//
// Compile-only placeholder. Loaded as a shared library by Android's allocator
// service. With no exported entry symbols of the IAllocator V2 ABI, the
// loader will fall back to AOSP's default gralloc-mapper passthrough.
//
// Full implementation routes allocations through the Adreno KMS driver
// (/dev/dri/renderD128 via Mesa freedreno) and uses the system DMA-BUF heap
// (/dev/dma_heap/system) per ch46 invariants. See
// hypervisor/src/adreno_render.rs::GrallocHalConfig for the spec.

#include <android-base/logging.h>

extern "C" __attribute__((visibility("default")))
const char* aether_gralloc_version() {
    return "aether-gralloc stub (no concrete IAllocator export)";
}
