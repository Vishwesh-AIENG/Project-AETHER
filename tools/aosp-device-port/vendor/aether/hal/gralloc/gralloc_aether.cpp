// gralloc.aether — Gralloc 4 allocator skeleton.
//
// Loaded as same-process HAL (vendor/lib64/hw/gralloc.aether.so). Allocates
// buffers via /dev/dma_heap/system (CONFIG_DMABUF_HEAPS_SYSTEM) and exposes
// them via DMA-BUF fds to SurfaceFlinger and Mesa freedreno.
//
// Required SELinux rules (already in sepolicy/hal_graphics_allocator_aether.te):
//   allow gralloc_default dma_heap_device:chr_file { open read write ioctl };
//   allow gralloc_default gpu_device:chr_file       { read write ioctl open };
//   allow gralloc_default dri_device:chr_file       { read write ioctl open };
//
// Phase 6 fleshes out the BufferDescriptor handling; this skeleton just
// registers the module and exposes a stub allocate() that returns
// NO_RESOURCES so callers fail loudly rather than silently using a
// software-rendered surface.

#include <hardware/gralloc.h>
#include <hardware/hardware.h>
#include <android-base/logging.h>

static int aether_gralloc_open(const struct hw_module_t* module,
                               const char* /*id*/,
                               struct hw_device_t** device) {
    LOG(INFO) << "gralloc.aether::open (skeleton).";
    *device = nullptr;
    return -ENODEV;  // Phase 6 wires real device handle.
}

static struct hw_module_methods_t aether_gralloc_methods = {
    .open = aether_gralloc_open,
};

extern "C" struct hw_module_t HAL_MODULE_INFO_SYM = {
    .tag           = HARDWARE_MODULE_TAG,
    .module_api_version = GRALLOC_MODULE_API_VERSION_1_0,
    .hal_api_version    = HARDWARE_HAL_API_VERSION,
    .id            = GRALLOC_HARDWARE_MODULE_ID,
    .name          = "AETHER gralloc skeleton",
    .author        = "AETHER",
    .methods       = &aether_gralloc_methods,
    .dso           = nullptr,
    .reserved      = {0},
};
