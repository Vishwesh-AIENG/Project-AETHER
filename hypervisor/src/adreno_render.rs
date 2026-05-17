// ch46: Adreno GPU — Rendering
//
// Integrates Mesa freedreno (Turnip Vulkan + freedreno OpenGL ES) into the
// AOSP vendor partition and wires the Gralloc and HWC HALs so the Adreno VF
// assigned in ch39 actually renders to the display.
//
// ── What This Module Does ─────────────────────────────────────────────────────
//
// ch39 (gpu_sriov.rs) enabled SR-IOV on the Adreno GPU Physical Function and
// mapped the Android VF's BARs + SMMU STEs.  That is necessary but not
// sufficient for rendering: Android userspace still needs a DRM kernel driver
// that binds to the VF, a Gralloc HAL that allocates GPU-visible buffers, a
// HWC HAL that drives the display controller, and a Vulkan ICD that exposes the
// GPU to apps.
//
// This module captures the complete rendering-stack configuration — driver
// selection, HAL wiring, kernel config entries, SELinux policy entries, and
// AOSP build variables — and provides a gate that verifies the three observable
// outcomes.
//
// ── Gate ──────────────────────────────────────────────────────────────────────
//
// AdrenoRenderGate { vulkan_shows_adreno, glmark2_es2_runs, youtube_1080p_plays }
//   vulkan_shows_adreno  = `vulkaninfo` inside Android shows Vendor 0x17CB
//   glmark2_es2_runs     = `glmark2-es2` completes with score > 0
//   youtube_1080p_plays  = YouTube plays a 1080p video with HW video decode active
//
// ── Phase Machine ─────────────────────────────────────────────────────────────
//
// AdrenoRenderPhase:
//   NotStarted
//   → DrmDriverBound       (msm DRM driver binds to Adreno VF in Android kernel)
//   → GrallocReady         (Gralloc HAL opens /dev/dri/renderD128; GEM alloc works)
//   → HwcReady             (drm_hwcomposer binds DRM device; atomic commits work)
//   → VulkanReady          (Mesa Turnip ICD registered; vulkaninfo sees device)
//   → RenderingActive      (SurfaceFlinger compositing via GPU; no software fallback)
//   → GatePassed           (all three gate criteria satisfied)
//
// ── Silent Failure Modes ──────────────────────────────────────────────────────
//
// 70% of rendering bring-up failures are silent — the system appears to boot
// but uses software rendering with no visible error.  The five most common:
//
//   1. CONFIG_DRM_MSM not set
//      /dev/dri/card0 and /dev/dri/renderD128 are absent.  drm_hwcomposer
//      initialization silently fails and SurfaceFlinger falls back to the
//      software GLES renderer.  logcat shows "hwcomposer: open failed" once
//      at boot and then nothing — GPU is never used.
//
//   2. CONFIG_SYNC_FILE not set
//      Android SurfaceFlinger uses explicit sync fences (android.hardware.
//      graphics.sync) for GPU/display synchronisation.  Without SYNC_FILE, the
//      fence fd from Gralloc is -1.  SurfaceFlinger treats -1 as "already
//      signalled" and presents frames before GPU work completes → display
//      shows garbage or black.  No error in logcat; performance appears normal.
//
//   3. CONFIG_DMABUF_HEAPS / CONFIG_DMA_SHARED_BUFFER not set
//      Android 12+ Gralloc uses /dev/dma_heap/system for buffer allocation.
//      Without the heap, Gralloc 4 returns INVALID_OPERATION for all
//      AHARDWAREBUFFER_USAGE_GPU_* allocations.  It falls back to software
//      buffers.  Apps run; GPU is idle; no errors in logcat by default.
//
//   4. SELinux gralloc_default denial on gpu_device
//      /dev/dri/renderD128 requires `allow gralloc_default gpu_device`.
//      Without it, Gralloc's open() succeeds (node exists) but ioctl() returns
//      -EACCES.  Mesa treats this as "no render device" and silently falls back
//      to llvmpipe software renderer.  `vulkaninfo` may still succeed on the
//      software ICD, hiding the failure entirely.
//
//   5. Vulkan ICD JSON path wrong
//      Mesa Turnip's ICD JSON must be at exactly
//      /vendor/etc/vulkan/icd.d/freedreno.json.  The Android Vulkan loader
//      (libvulkan.so) scans this directory at startup.  If the JSON is absent
//      or malformed, `vulkaninfo` reports "0 Vulkan hardware devices" and exits
//      0 (success) — completely silent.
//
// ── AOSP Build Variables ──────────────────────────────────────────────────────
//
// BoardConfig.mk additions:
//   BOARD_GPU_DRIVERS := adreno
//   BOARD_USES_DRM_HWCOMPOSER := true
//   TARGET_USES_GRALLOC4 := true
//   TARGET_USES_HWC2 := true
//   BOARD_USES_OPENGL_RENDERER := true
//
// device.mk additions (PRODUCT_PACKAGES):
//   android.hardware.graphics.allocator-V2-service
//   android.hardware.graphics.mapper@4.0-impl
//   android.hardware.graphics.composer@2.4-service
//   libEGL_mesa
//   libGLESv2_mesa
//   vulkan.freedreno     ← Mesa Turnip Vulkan ICD
//   libvulkan_freedreno  ← Mesa Turnip .so
//
// ── References ────────────────────────────────────────────────────────────────
//
//   Freedreno: gitlab.freedesktop.org/mesa/mesa src/freedreno/
//   Mesa Turnip: gitlab.freedesktop.org/mesa/mesa src/freedreno/vulkan/
//   drm_hwcomposer: gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer
//   Android HAL: source.android.com/docs/core/graphics
//   DRM/MSM driver: linux-ref/drivers/gpu/drm/msm/
//   Qualcomm Vendor ID 0x17CB: PCI-SIG allocation

use crate::kernel_defconfig::{DefconfigEntry, DefconfigValue};

// ─────────────────────────────────────────────────────────────────────────────
// Driver selection
// ─────────────────────────────────────────────────────────────────────────────

/// GPU userspace driver source for the Android vendor partition.
///
/// AETHER ships Mesa freedreno by default.  Qualcomm's proprietary stack
/// requires an NDA and cannot be redistributed; it is listed here for
/// documentation only — `AdrenoRenderConfig::validate()` rejects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuDriverSource {
    /// Mesa freedreno — open source (MIT/X11).
    ///
    /// - OpenGL ES: freedreno gallium backend (`src/gallium/drivers/freedreno/`)
    /// - Vulkan:    Mesa Turnip (`src/freedreno/vulkan/`)
    /// - Build:     `m freedom` inside AOSP Mesa integration
    /// - ICD path:  `/vendor/etc/vulkan/icd.d/freedreno.json`
    ///
    /// Supports Adreno 600+, including the Adreno 740 on Snapdragon X Elite.
    MesaFreedrenoOpen,

    /// Qualcomm proprietary Adreno driver.
    ///
    /// Requires Qualcomm NDA.  Cannot be redistributed in an open-source
    /// build.  `validate()` returns `ProprietaryDriverNotRedistributable`
    /// if this variant is selected.
    QualcommProprietary,
}

// ─────────────────────────────────────────────────────────────────────────────
// Gralloc HAL configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Gralloc HAL version.
///
/// Android 14 (API 34) requires AIDL Gralloc 2; HIDL 4 is the legacy path.
/// AETHER targets Android 14, so `Aidl2` is the production default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrallocVersion {
    /// HIDL android.hardware.graphics.mapper@4.0 — legacy, pre-Android 14.
    Hidl4,
    /// AIDL android.hardware.graphics.allocator-V2 — Android 14+.
    Aidl2,
}

/// Gralloc HAL wiring configuration.
///
/// Gralloc allocates GPU-visible buffers (AHardwareBuffers) for SurfaceFlinger,
/// the camera HAL, and app-level drawing.  For Adreno, allocation goes through
/// the DRM render node.
#[derive(Debug, Clone, Copy)]
pub struct GrallocHalConfig {
    /// AIDL or HIDL Gralloc version.  AETHER uses `Aidl2`.
    pub version: GrallocVersion,

    /// DRM render node path inside Android.
    ///
    /// The Adreno VF appears as `/dev/dri/renderD128` (second DRM device;
    /// renderD129 if a virtual display adapter occupies renderD128).
    /// Gralloc opens this node for every GEM buffer allocation.
    ///
    /// SELinux note: `gralloc_default` domain must have `gpu_device:chr_file
    /// { read write ioctl }` — see `ADRENO_SELINUX_RULES`.
    pub render_node_path: &'static str,

    /// DMA-BUF heap path for system-memory allocations.
    ///
    /// Android 12+ Gralloc 4 allocates via `/dev/dma_heap/system` instead of
    /// ION.  Requires `CONFIG_DMABUF_HEAPS=y` + `CONFIG_DMABUF_HEAPS_SYSTEM=y`.
    pub dma_heap_path: &'static str,
}

impl GrallocHalConfig {
    /// Default AETHER Gralloc configuration for the Adreno VF.
    pub const fn aether_defaults() -> Self {
        Self {
            version: GrallocVersion::Aidl2,
            render_node_path: "/dev/dri/renderD128",
            dma_heap_path: "/dev/dma_heap/system",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HWC (Hardware Composer) HAL
// ─────────────────────────────────────────────────────────────────────────────

/// Hardware Composer HAL implementation selection.
///
/// HWC drives the display controller — it composites SurfaceFlinger layers via
/// DRM atomic modesetting and presents the final frame to the display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwcImplementation {
    /// Open-source `drm_hwcomposer` — HWC2/HWC3 implementation using DRM/KMS.
    ///
    /// Supports any DRM/KMS driver including freedreno.  Uses DRM atomic
    /// modesetting for tear-free display and explicit sync fences.
    /// Build: integrated into AOSP via `hardware/drm_hwcomposer`.
    DrmHwcomposer,

    /// Qualcomm proprietary `hwcomposer.adreno.so`.
    ///
    /// Higher performance on real Qualcomm hardware but not redistributable.
    /// Rejected by `validate()` for the same reason as proprietary driver.
    QualcommProprietary,

    /// Software fallback via GLES renderer.
    ///
    /// Used only for bring-up debugging — the GPU is bypassed entirely and
    /// all composition is done in software.  `validate()` rejects this in
    /// production configs because it defeats the purpose of ch46.
    SoftwareFallback,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vulkan ICD configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Vulkan Installable Client Driver (ICD) registration.
///
/// The Android Vulkan loader (`libvulkan.so`) scans `/vendor/etc/vulkan/icd.d/`
/// at startup for JSON manifests.  Each JSON points to a `.so` that implements
/// the VK_KHR_get_physical_device_properties2 and related entry points.
///
/// For AETHER, Mesa Turnip provides a Vulkan 1.3 driver for Adreno 6xx/7xx.
/// The ICD JSON and `.so` must be installed in the vendor partition image.
#[derive(Debug, Clone, Copy)]
pub struct VulkanIcdConfig {
    /// Absolute path to the ICD JSON inside the Android vendor partition.
    ///
    /// The Android Vulkan loader scans `/vendor/etc/vulkan/icd.d/` exactly.
    /// Any other path → `vulkaninfo` reports 0 GPU devices (silent failure #5).
    pub icd_json_path: &'static str,

    /// Absolute path to the Vulkan ICD shared library.
    ///
    /// Referenced inside the ICD JSON as `"library_path"`.
    /// AETHER installs Mesa Turnip at `/vendor/lib64/hw/vulkan.freedreno.so`.
    pub library_path: &'static str,

    /// Vulkan API version supported by this ICD.
    ///
    /// Encoded as (major, minor, patch).  Mesa Turnip on Adreno 740 supports
    /// Vulkan 1.3.  Android 14 apps may require 1.1+.
    pub api_version: (u8, u8, u8),
}

impl VulkanIcdConfig {
    /// Default AETHER Vulkan ICD configuration for Mesa Turnip on Adreno 740.
    pub const fn aether_defaults() -> Self {
        Self {
            icd_json_path: "/vendor/etc/vulkan/icd.d/freedreno.json",
            library_path: "/vendor/lib64/hw/vulkan.freedreno.so",
            api_version: (1, 3, 0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Display output pipeline selection.
///
/// In production AETHER hardware boots, the Adreno VF drives the physical
/// display via DRM KMS.  During QEMU testing, virtio-gpu provides a virtual
/// framebuffer (no Adreno hardware needed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPipeline {
    /// DRM kernel modesetting — required for production Adreno rendering.
    ///
    /// Requires `CONFIG_DRM_MSM=y`.  drm_hwcomposer opens `/dev/dri/card0`
    /// and performs atomic commits to drive the display.
    KernelModeSetting,

    /// VirtIO-GPU for QEMU testing.
    ///
    /// No Adreno hardware needed.  QEMU exposes a virtual display via
    /// `virtio-gpu-pci`.  The Android guest uses `virtio_gpu` DRM driver.
    /// Cannot test Adreno rendering performance, but validates the rest of
    /// the userspace boot sequence.
    VirtioGpuQemu,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering-specific kernel defconfig entries
// ─────────────────────────────────────────────────────────────────────────────

/// A kernel defconfig entry required for Adreno GPU rendering, with a
/// description of the silent failure that occurs if it is omitted.
#[derive(Debug, Clone, Copy)]
pub struct AdrenoKernelEntry {
    /// The kernel CONFIG_ entry.
    pub entry: DefconfigEntry,
    /// One-line description of the silent failure if this entry is missing.
    pub silent_failure: &'static str,
}

impl AdrenoKernelEntry {
    const fn required(name: &'static [u8], silent_failure: &'static str) -> Self {
        Self {
            entry: DefconfigEntry { name, value: DefconfigValue::Enabled },
            silent_failure,
        }
    }

    const fn forbidden(name: &'static [u8], silent_failure: &'static str) -> Self {
        Self {
            entry: DefconfigEntry { name, value: DefconfigValue::Disabled },
            silent_failure,
        }
    }
}

/// Kernel defconfig entries required for Adreno GPU rendering on AETHER.
///
/// These supplement `AETHER_GKI_DEFCONFIG` (ch44).  Every entry here is
/// specific to the GPU/display/media stack; generic Android entries are in ch44.
///
/// Silent failures are listed per entry — omitting a single entry can cause
/// the GPU to be silently bypassed with no visible error in logcat.
pub const ADRENO_RENDER_DEFCONFIG: &[AdrenoKernelEntry] = &[
    // ── DRM core ─────────────────────────────────────────────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_DRM",
        "No DRM subsystem: /dev/dri/ absent; drm_hwcomposer init fails; \
         SurfaceFlinger silently uses software renderer.",
    ),

    AdrenoKernelEntry::required(
        b"CONFIG_DRM_KMS_HELPER",
        "drm_hwcomposer uses DRM atomic modesetting KMS helpers; \
         without this it falls back to legacy fbdev silently.",
    ),

    // ── Adreno MSM DRM driver ─────────────────────────────────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_DRM_MSM",
        "Adreno MSM/freedreno DRM driver absent: Adreno VF has no DRM bind; \
         /dev/dri/renderD128 never created; Gralloc silently falls back to \
         software buffers.",
    ),

    // ── Sync fences (explicit fencing) ────────────────────────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_SYNC_FILE",
        "SurfaceFlinger explicit sync fences disabled: fence fd returns -1; \
         SurfaceFlinger treats all fences as immediately signalled; frames are \
         presented before GPU completes → display shows garbage or black screen. \
         No error in logcat.",
    ),

    // ── DMA-BUF (Gralloc buffer allocation) ──────────────────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_DMA_SHARED_BUFFER",
        "AHardwareBuffer (Gralloc 4) uses DMA-BUF for cross-process sharing; \
         without this, GPU buffer allocation fails silently with INVALID_OPERATION.",
    ),

    AdrenoKernelEntry::required(
        b"CONFIG_DMABUF_HEAPS",
        "Android 12+ Gralloc uses /dev/dma_heap/system; without heap allocator \
         the device node is absent; Gralloc silently allocates software-only buffers.",
    ),

    AdrenoKernelEntry::required(
        b"CONFIG_DMABUF_HEAPS_SYSTEM",
        "System DMA-BUF heap at /dev/dma_heap/system required for GPU-visible \
         system-memory allocations; absent → Gralloc falls back to software.",
    ),

    // ── Display connector ─────────────────────────────────────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_DRM_DISPLAY_CONNECTOR",
        "Display connector abstraction required by drm_hwcomposer for virtual \
         and physical display output; absent → HWC cannot enumerate displays.",
    ),

    // ── Media (hardware video decode for YouTube 1080p) ───────────────────────

    AdrenoKernelEntry::required(
        b"CONFIG_MEDIA_SUPPORT",
        "Android media framework requires CONFIG_MEDIA_SUPPORT; absent → \
         MediaCodec hardware decode unavailable; YouTube falls back to software \
         decode (stutters at 1080p).",
    ),

    AdrenoKernelEntry::required(
        b"CONFIG_VIDEO_DEV",
        "V4L2 video device support required for hardware video decoder; \
         absent → YouTube 1080p uses CPU software decode and overloads the system.",
    ),

    AdrenoKernelEntry::required(
        b"CONFIG_MEDIA_CONTROLLER",
        "V4L2 media controller required by Qualcomm video decoder (venus); \
         absent → /dev/media0 missing; HW decode pipeline fails to init.",
    ),

    // ── Disable legacy framebuffer (prevent silent GPU bypass) ────────────────

    AdrenoKernelEntry::forbidden(
        b"CONFIG_FB",
        "Legacy fbdev enabled: drm_hwcomposer may fall back to /dev/fb0 instead \
         of DRM atomic modesetting; GPU compositing path is bypassed silently. \
         Disable fbdev to force the correct DRM path.",
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// SELinux policy entries
// ─────────────────────────────────────────────────────────────────────────────

/// A single SELinux TE rule required for GPU rendering.
///
/// Each entry maps to one line in a `.te` policy file under
/// `device/aether/aether_arm64/sepolicy/`.
#[derive(Debug, Clone, Copy)]
pub struct GpuSelinuxRule {
    /// SELinux source domain (process context).
    pub domain: &'static str,
    /// SELinux object (file/device context).
    pub object: &'static str,
    /// Object class (`chr_file`, `dir`, `file`, etc.).
    pub class: &'static str,
    /// Permissions to allow.
    pub perms: &'static str,
    /// The `.te` source file to add this rule to.
    pub te_file: &'static str,
    /// What silently breaks without this rule.
    pub silent_failure: &'static str,
}

/// SELinux rules required for Adreno GPU rendering in AETHER.
///
/// These rules must be added to the AETHER sepolicy directory alongside
/// the AETHER_SEPOLICY_FIXES table from ch45.
///
/// All rules are for SELinux enforcing mode (`ro.build.type=user`).
/// Missing any one of these causes silent software-rendering fallback.
pub const ADRENO_SELINUX_RULES: &[GpuSelinuxRule] = &[
    GpuSelinuxRule {
        domain: "gralloc_default",
        object: "gpu_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "gralloc_default.te",
        silent_failure: "Gralloc cannot open /dev/dri/renderD128; ioctl returns \
                         -EACCES; Mesa silently falls back to llvmpipe software \
                         renderer; vulkaninfo may still pass on software ICD.",
    },
    GpuSelinuxRule {
        domain: "gralloc_default",
        object: "dri_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "gralloc_default.te",
        silent_failure: "DRI device node (/dev/dri/card0) inaccessible to Gralloc; \
                         modesetting impossible; drm_hwcomposer falls back to fbdev.",
    },
    GpuSelinuxRule {
        domain: "hal_graphics_composer_default",
        object: "gpu_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "hal_graphics_composer_default.te",
        silent_failure: "HWC HAL cannot open render node; compositor falls back \
                         to software GLES path without error.",
    },
    GpuSelinuxRule {
        domain: "hal_graphics_composer_default",
        object: "dri_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "hal_graphics_composer_default.te",
        silent_failure: "HWC HAL cannot open DRM KMS device; atomic commits fail; \
                         display shows black screen.",
    },
    GpuSelinuxRule {
        domain: "system_server",
        object: "gpu_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "system_server.te",
        silent_failure: "SurfaceFlinger (inside system_server) denied GPU access; \
                         falls back to pure CPU rendering; system_server may crash \
                         with SIGSEGV in EGL init.",
    },
    GpuSelinuxRule {
        domain: "untrusted_app",
        object: "gpu_device",
        class: "chr_file",
        perms: "{ read ioctl open }",
        te_file: "untrusted_app.te",
        silent_failure: "Apps cannot access GPU render node; Vulkan and GLES unavailable \
                         for app processes; all 3D rendering falls back to software.",
    },
    GpuSelinuxRule {
        domain: "mediacodec",
        object: "video_device",
        class: "chr_file",
        perms: "{ read write ioctl open }",
        te_file: "mediacodec.te",
        silent_failure: "Hardware video decoder (venus) inaccessible; YouTube falls \
                         back to software decode; 1080p gate fails.",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// AOSP build variables
// ─────────────────────────────────────────────────────────────────────────────

/// AOSP build variable name (BoardConfig.mk or device.mk key).
pub type BuildVarName = &'static str;

/// A single AOSP build variable required for Adreno rendering.
#[derive(Debug, Clone, Copy)]
pub struct AospRenderBuildVar {
    /// Variable name (e.g., `"BOARD_GPU_DRIVERS"`).
    pub name: BuildVarName,
    /// Required value (e.g., `"adreno"`).
    pub value: &'static str,
    /// Which Makefile this goes in.
    pub makefile: &'static str,
}

/// BoardConfig.mk + device.mk variables required for Adreno GPU rendering.
///
/// Add these to `device/aether/aether_arm64/BoardConfig.mk` and
/// `device/aether/aether_arm64/device.mk` respectively.
pub const ADRENO_AOSP_BUILD_VARS: &[AospRenderBuildVar] = &[
    AospRenderBuildVar {
        name: "BOARD_GPU_DRIVERS",
        value: "adreno",
        makefile: "BoardConfig.mk",
    },
    AospRenderBuildVar {
        name: "BOARD_USES_DRM_HWCOMPOSER",
        value: "true",
        makefile: "BoardConfig.mk",
    },
    AospRenderBuildVar {
        name: "TARGET_USES_GRALLOC4",
        value: "true",
        makefile: "BoardConfig.mk",
    },
    AospRenderBuildVar {
        name: "TARGET_USES_HWC2",
        value: "true",
        makefile: "BoardConfig.mk",
    },
    AospRenderBuildVar {
        name: "BOARD_USES_OPENGL_RENDERER",
        value: "true",
        makefile: "BoardConfig.mk",
    },
];

/// PRODUCT_PACKAGES entries required for Adreno GPU rendering.
///
/// Add each of these strings to the `PRODUCT_PACKAGES` list in `device.mk`.
pub const ADRENO_PRODUCT_PACKAGES: &[&str] = &[
    "android.hardware.graphics.allocator-V2-service",
    "android.hardware.graphics.mapper@4.0-impl",
    "android.hardware.graphics.composer@2.4-service",
    "libEGL_mesa",
    "libGLESv1_CM_mesa",
    "libGLESv2_mesa",
    "vulkan.freedreno",
    "libvulkan_freedreno",
];

// ─────────────────────────────────────────────────────────────────────────────
// Rendering phase machine
// ─────────────────────────────────────────────────────────────────────────────

/// Phase of the Adreno rendering bring-up sequence.
///
/// Phases are reported by the Android side via UART diagnostics (UART_PA
/// at 0x0900_0000) using the signatures in `RENDER_UART_SIGNATURES`.
/// AETHER's hypervisor monitors the UART stream to track progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdrenoRenderPhase {
    /// ch46 pipeline not yet started.
    NotStarted,
    /// msm DRM driver bound to Adreno VF; `/dev/dri/card0` and
    /// `/dev/dri/renderD128` exist inside Android.
    DrmDriverBound,
    /// Gralloc HAL opened `/dev/dri/renderD128`; GEM buffer allocation works.
    GrallocReady,
    /// `drm_hwcomposer` service started; DRM atomic commits succeeding.
    HwcReady,
    /// Mesa Turnip ICD registered; `vulkaninfo` sees Vendor 0x17CB.
    VulkanReady,
    /// SurfaceFlinger compositing via GPU (no software fallback).
    RenderingActive,
    /// All three gate criteria satisfied.
    GatePassed,
}

// ─────────────────────────────────────────────────────────────────────────────
// UART log signatures for phase detection
// ─────────────────────────────────────────────────────────────────────────────

/// UART log signature indicating msm DRM driver bound to Adreno VF.
/// Emitted by `drivers/gpu/drm/msm/msm_drv.c` at DRM probe.
pub const RENDER_UART_DRM_BOUND: &[u8] = b"msm_drm msm_drm: bound";

/// UART log signature indicating Gralloc HAL opened the render node.
/// Emitted by `hardware/drm_hwcomposer` or Gralloc service at startup.
pub const RENDER_UART_GRALLOC_READY: &[u8] = b"gralloc: opened render node";

/// UART log signature indicating drm_hwcomposer started successfully.
/// Emitted by `hardware/drm_hwcomposer` HAL service init.
pub const RENDER_UART_HWC_READY: &[u8] = b"DrmHwcTwo::Init: success";

/// UART log signature indicating Mesa Turnip Vulkan ICD initialized.
/// Emitted by Mesa Turnip driver during VkInstance creation.
pub const RENDER_UART_VULKAN_READY: &[u8] = b"TU_DEBUG: Turnip initialized";

/// UART log signature indicating SurfaceFlinger GPU compositing is active.
/// Emitted by SurfaceFlinger when it selects GPU as the compositor backend.
pub const RENDER_UART_GPU_COMPOSITING: &[u8] = b"SurfaceFlinger: GPU compositing";

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the Adreno rendering configuration pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdrenoRenderError {
    /// Qualcomm proprietary driver selected — cannot be redistributed in an
    /// open-source AETHER build.  Use `GpuDriverSource::MesaFreedrenoOpen`.
    ProprietaryDriverNotRedistributable,

    /// Qualcomm proprietary HWC selected alongside open-source GPU driver.
    /// These two must match: both open-source or both proprietary.
    HwcIncompatibleWithDriverSource,

    /// `SoftwareFallback` HWC selected in production config.
    /// Software composition defeats the purpose of ch46 (Adreno rendering).
    SoftwareFallbackForbiddenInProduction,

    /// Vulkan API version below the Android 14 minimum of 1.1.0.
    VulkanApiVersionTooOld {
        /// The reported (major, minor, patch) version.
        reported: (u8, u8, u8),
    },

    /// Gralloc render node path is empty.
    GrallocRenderNodePathEmpty,

    /// Gralloc DMA-BUF heap path is empty.
    GrallocDmaHeapPathEmpty,

    /// Vulkan ICD JSON path does not start with `/vendor/etc/vulkan/icd.d/`.
    /// Any other path causes the Android Vulkan loader to silently ignore the ICD.
    VulkanIcdPathNotInVendor,

    /// Vulkan library path does not start with `/vendor/`.
    /// Non-vendor paths are rejected by the Android dynamic linker namespace.
    VulkanLibraryNotInVendor,
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate
// ─────────────────────────────────────────────────────────────────────────────

/// Ch46 gate criterion: Adreno GPU renders in Android.
///
/// All three booleans must be true to pass the gate.
///
/// - `vulkan_shows_adreno`: `vulkaninfo` inside Android shows Vendor ID 0x17CB
///   (Qualcomm).  The Mesa Turnip Vulkan ICD must be correctly registered and
///   the Adreno VF must be bound by the msm DRM driver.
///
/// - `glmark2_es2_runs`: `glmark2-es2` completes its benchmark suite with a
///   final score > 0 and exits without crashing.  Exercises the full OpenGL ES
///   rendering pipeline: EGL context creation → vertex/fragment shaders →
///   texture sampling → framebuffer presentation.
///
/// - `youtube_1080p_plays`: The YouTube app streams a 1080p video with hardware
///   video decode active.  Verifies the V4L2 video decoder (venus), the media
///   codec HAL, DMA-BUF import from the decoder to Gralloc, and final frame
///   compositing via drm_hwcomposer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdrenoRenderGate {
    /// `vulkaninfo` shows Qualcomm Vendor ID 0x17CB.
    pub vulkan_shows_adreno: bool,
    /// `glmark2-es2` runs and produces a non-zero score.
    pub glmark2_es2_runs: bool,
    /// YouTube plays 1080p with hardware video decode.
    pub youtube_1080p_plays: bool,
}

impl AdrenoRenderGate {
    /// Initial state before any pipeline step.
    pub const fn not_started() -> Self {
        Self {
            vulkan_shows_adreno: false,
            glmark2_es2_runs: false,
            youtube_1080p_plays: false,
        }
    }

    /// Returns `true` when all three gate criteria are satisfied.
    pub const fn passes(&self) -> bool {
        self.vulkan_shows_adreno && self.glmark2_es2_runs && self.youtube_1080p_plays
    }

    /// Returns `true` if the minimum rendering criterion is met.
    ///
    /// `vulkan_shows_adreno` is the prerequisite for the other two — if Vulkan
    /// does not see the GPU, glmark2 and YouTube cannot use hardware rendering.
    pub const fn gpu_visible(&self) -> bool {
        self.vulkan_shows_adreno
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Complete Adreno rendering configuration for ch46.
///
/// Aggregates driver selection, Gralloc wiring, HWC selection, Vulkan ICD
/// path, and display pipeline.  `validate()` enforces production invariants
/// before any AOSP build or boot sequence relies on this configuration.
#[derive(Clone, Copy, Debug)]
pub struct AdrenoRenderConfig {
    /// GPU userspace driver source.  Must be `MesaFreedrenoOpen` for production.
    pub driver_source: GpuDriverSource,
    /// Gralloc HAL wiring configuration.
    pub gralloc: GrallocHalConfig,
    /// Hardware Composer implementation.  Must be `DrmHwcomposer` for production.
    pub hwc: HwcImplementation,
    /// Vulkan ICD registration.
    pub vulkan: VulkanIcdConfig,
    /// Display output pipeline.
    pub display: DisplayPipeline,
}

impl AdrenoRenderConfig {
    /// Production AETHER default: Mesa freedreno + drm_hwcomposer + Vulkan 1.3.
    ///
    /// This configuration passes `validate()` and is used as the basis for
    /// the AOSP build variables in `ADRENO_AOSP_BUILD_VARS`.
    pub const fn aether_defaults() -> Self {
        Self {
            driver_source: GpuDriverSource::MesaFreedrenoOpen,
            gralloc: GrallocHalConfig::aether_defaults(),
            hwc: HwcImplementation::DrmHwcomposer,
            vulkan: VulkanIcdConfig::aether_defaults(),
            display: DisplayPipeline::KernelModeSetting,
        }
    }

    /// Validate production invariants.
    ///
    /// Catches the configuration mistakes that produce silent rendering failures:
    /// - Proprietary driver (not redistributable)
    /// - Mismatched driver/HWC sources
    /// - Software HWC fallback in production
    /// - Vulkan API version below Android 14 minimum
    /// - Empty or wrong-prefix paths (silent ICD loader failures)
    pub fn validate(&self) -> Result<(), AdrenoRenderError> {
        // Proprietary driver cannot be redistributed.
        if self.driver_source == GpuDriverSource::QualcommProprietary {
            return Err(AdrenoRenderError::ProprietaryDriverNotRedistributable);
        }

        // HWC source must match the GPU driver source.
        // Open-source driver + proprietary HWC is unsupported.
        if self.driver_source == GpuDriverSource::MesaFreedrenoOpen
            && self.hwc == HwcImplementation::QualcommProprietary
        {
            return Err(AdrenoRenderError::HwcIncompatibleWithDriverSource);
        }

        // Software HWC fallback defeats the purpose of ch46.
        if self.hwc == HwcImplementation::SoftwareFallback {
            return Err(AdrenoRenderError::SoftwareFallbackForbiddenInProduction);
        }

        // Vulkan 1.0 is too old for Android 14 apps.
        // Require at least 1.1.0.
        let (major, minor, _patch) = self.vulkan.api_version;
        if major < 1 || (major == 1 && minor < 1) {
            return Err(AdrenoRenderError::VulkanApiVersionTooOld {
                reported: self.vulkan.api_version,
            });
        }

        // Gralloc render node path must not be empty.
        if self.gralloc.render_node_path.is_empty() {
            return Err(AdrenoRenderError::GrallocRenderNodePathEmpty);
        }

        // Gralloc DMA-BUF heap path must not be empty.
        if self.gralloc.dma_heap_path.is_empty() {
            return Err(AdrenoRenderError::GrallocDmaHeapPathEmpty);
        }

        // Vulkan ICD JSON must be under /vendor/etc/vulkan/icd.d/ — the only
        // path the Android Vulkan loader scans.  Any other path = silent failure.
        if !self.vulkan.icd_json_path.starts_with("/vendor/etc/vulkan/icd.d/") {
            return Err(AdrenoRenderError::VulkanIcdPathNotInVendor);
        }

        // Vulkan library must be in /vendor/ — non-vendor paths are rejected by
        // the Android linker namespace for vendor HALs.
        if !self.vulkan.library_path.starts_with("/vendor/") {
            return Err(AdrenoRenderError::VulkanLibraryNotInVendor);
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline state
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime state for the ch46 Adreno rendering bring-up pipeline.
///
/// Tracks which phase the Android rendering stack has reached and records
/// the gate criteria as they are observed via UART log scanning.
#[derive(Debug, Clone, Copy)]
pub struct AdrenoRenderState {
    /// Current phase in the rendering bring-up sequence.
    pub phase: AdrenoRenderPhase,
    /// Gate criteria observed so far.
    pub gate: AdrenoRenderGate,
}

impl AdrenoRenderState {
    /// Construct initial state before pipeline starts.
    pub const fn new() -> Self {
        Self {
            phase: AdrenoRenderPhase::NotStarted,
            gate: AdrenoRenderGate::not_started(),
        }
    }

    /// Process one UART log line and advance phase / gate state.
    ///
    /// Called by the EL2 UART monitor loop for each byte line received.
    /// `line` is a byte slice containing one UART log line (no newline).
    ///
    /// # Safety
    /// No heap; no system calls.  Safe at EL2 in `no_std` context.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, RENDER_UART_DRM_BOUND)
            && self.phase < AdrenoRenderPhase::DrmDriverBound
        {
            self.phase = AdrenoRenderPhase::DrmDriverBound;
        }

        if contains_bytes(line, RENDER_UART_GRALLOC_READY)
            && self.phase < AdrenoRenderPhase::GrallocReady
        {
            self.phase = AdrenoRenderPhase::GrallocReady;
        }

        if contains_bytes(line, RENDER_UART_HWC_READY)
            && self.phase < AdrenoRenderPhase::HwcReady
        {
            self.phase = AdrenoRenderPhase::HwcReady;
        }

        if contains_bytes(line, RENDER_UART_VULKAN_READY) {
            self.gate.vulkan_shows_adreno = true;
            if self.phase < AdrenoRenderPhase::VulkanReady {
                self.phase = AdrenoRenderPhase::VulkanReady;
            }
        }

        if contains_bytes(line, RENDER_UART_GPU_COMPOSITING)
            && self.phase < AdrenoRenderPhase::RenderingActive
        {
            self.phase = AdrenoRenderPhase::RenderingActive;
        }

        if self.gate.passes() && self.phase < AdrenoRenderPhase::GatePassed {
            self.phase = AdrenoRenderPhase::GatePassed;
        }
    }

    /// Returns the current gate state.
    pub const fn gate(&self) -> &AdrenoRenderGate {
        &self.gate
    }
}

impl Default for AdrenoRenderState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline initialiser
// ─────────────────────────────────────────────────────────────────────────────

/// Validate the Adreno rendering configuration and return the initial pipeline
/// state.
///
/// Call this during AETHER hypervisor boot after `assign_gpu_vfs()` (ch39)
/// completes.  The returned `AdrenoRenderState` is passed to the UART monitor
/// loop which calls `state.process_line()` for each boot log line.
///
/// # Errors
///
/// Returns `AdrenoRenderError` if the configuration is invalid.  Errors here
/// indicate a misconfiguration in the AOSP build or SELinux policy that will
/// cause silent GPU bypass.  Treat as fatal — abort the boot sequence and
/// report the error via UART before the Android guest starts.
pub fn init_adreno_render_pipeline(
    config: &AdrenoRenderConfig,
) -> Result<AdrenoRenderState, AdrenoRenderError> {
    config.validate()?;
    Ok(AdrenoRenderState::new())
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-pattern scan (no heap, no regex — safe at EL2)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `haystack` contains `needle` as a sub-slice.
///
/// O(n × m) window scan.  No allocation, no unsafe.
/// Same implementation as `contains_bytes` in ch45 (userspace_boot.rs).
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AdrenoRenderGate ──────────────────────────────────────────────────────

    #[test]
    fn gate_not_started_all_false() {
        let g = AdrenoRenderGate::not_started();
        assert!(!g.vulkan_shows_adreno);
        assert!(!g.glmark2_es2_runs);
        assert!(!g.youtube_1080p_plays);
    }

    #[test]
    fn gate_not_started_does_not_pass() {
        assert!(!AdrenoRenderGate::not_started().passes());
    }

    #[test]
    fn gate_vulkan_only_does_not_pass() {
        let g = AdrenoRenderGate {
            vulkan_shows_adreno: true,
            glmark2_es2_runs: false,
            youtube_1080p_plays: false,
        };
        assert!(!g.passes());
        assert!(g.gpu_visible());
    }

    #[test]
    fn gate_two_of_three_does_not_pass() {
        let g = AdrenoRenderGate {
            vulkan_shows_adreno: true,
            glmark2_es2_runs: true,
            youtube_1080p_plays: false,
        };
        assert!(!g.passes());
    }

    #[test]
    fn gate_all_true_passes() {
        let g = AdrenoRenderGate {
            vulkan_shows_adreno: true,
            glmark2_es2_runs: true,
            youtube_1080p_plays: true,
        };
        assert!(g.passes());
    }

    #[test]
    fn gate_gpu_visible_requires_vulkan() {
        let g = AdrenoRenderGate {
            vulkan_shows_adreno: false,
            glmark2_es2_runs: true,
            youtube_1080p_plays: true,
        };
        assert!(!g.gpu_visible());
        assert!(!g.passes());
    }

    // ── AdrenoRenderConfig::validate ─────────────────────────────────────────

    #[test]
    fn aether_defaults_validates_ok() {
        assert!(AdrenoRenderConfig::aether_defaults().validate().is_ok());
    }

    #[test]
    fn proprietary_driver_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.driver_source = GpuDriverSource::QualcommProprietary;
        assert_eq!(
            cfg.validate(),
            Err(AdrenoRenderError::ProprietaryDriverNotRedistributable)
        );
    }

    #[test]
    fn proprietary_hwc_with_open_driver_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.hwc = HwcImplementation::QualcommProprietary;
        assert_eq!(
            cfg.validate(),
            Err(AdrenoRenderError::HwcIncompatibleWithDriverSource)
        );
    }

    #[test]
    fn software_fallback_hwc_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.hwc = HwcImplementation::SoftwareFallback;
        assert_eq!(
            cfg.validate(),
            Err(AdrenoRenderError::SoftwareFallbackForbiddenInProduction)
        );
    }

    #[test]
    fn vulkan_api_1_0_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.api_version = (1, 0, 0);
        assert_eq!(
            cfg.validate(),
            Err(AdrenoRenderError::VulkanApiVersionTooOld { reported: (1, 0, 0) })
        );
    }

    #[test]
    fn vulkan_api_1_1_accepted() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.api_version = (1, 1, 0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn vulkan_api_0_x_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.api_version = (0, 9, 0);
        assert!(matches!(
            cfg.validate(),
            Err(AdrenoRenderError::VulkanApiVersionTooOld { .. })
        ));
    }

    #[test]
    fn empty_render_node_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.gralloc.render_node_path = "";
        assert_eq!(cfg.validate(), Err(AdrenoRenderError::GrallocRenderNodePathEmpty));
    }

    #[test]
    fn empty_dma_heap_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.gralloc.dma_heap_path = "";
        assert_eq!(cfg.validate(), Err(AdrenoRenderError::GrallocDmaHeapPathEmpty));
    }

    #[test]
    fn icd_json_not_in_vendor_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.icd_json_path = "/system/etc/vulkan/icd.d/freedreno.json";
        assert_eq!(cfg.validate(), Err(AdrenoRenderError::VulkanIcdPathNotInVendor));
    }

    #[test]
    fn icd_json_in_vendor_accepted() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.icd_json_path = "/vendor/etc/vulkan/icd.d/freedreno.json";
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn vulkan_library_not_in_vendor_rejected() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.vulkan.library_path = "/system/lib64/hw/vulkan.freedreno.so";
        assert_eq!(cfg.validate(), Err(AdrenoRenderError::VulkanLibraryNotInVendor));
    }

    // ── VulkanIcdConfig defaults ──────────────────────────────────────────────

    #[test]
    fn vulkan_defaults_icd_path() {
        let icd = VulkanIcdConfig::aether_defaults();
        assert_eq!(icd.icd_json_path, "/vendor/etc/vulkan/icd.d/freedreno.json");
    }

    #[test]
    fn vulkan_defaults_library_path() {
        let icd = VulkanIcdConfig::aether_defaults();
        assert_eq!(icd.library_path, "/vendor/lib64/hw/vulkan.freedreno.so");
    }

    #[test]
    fn vulkan_defaults_version_is_1_3() {
        let icd = VulkanIcdConfig::aether_defaults();
        assert_eq!(icd.api_version, (1, 3, 0));
    }

    // ── GrallocHalConfig defaults ─────────────────────────────────────────────

    #[test]
    fn gralloc_defaults_render_node() {
        let g = GrallocHalConfig::aether_defaults();
        assert_eq!(g.render_node_path, "/dev/dri/renderD128");
    }

    #[test]
    fn gralloc_defaults_dma_heap() {
        let g = GrallocHalConfig::aether_defaults();
        assert_eq!(g.dma_heap_path, "/dev/dma_heap/system");
    }

    #[test]
    fn gralloc_defaults_version_aidl2() {
        let g = GrallocHalConfig::aether_defaults();
        assert_eq!(g.version, GrallocVersion::Aidl2);
    }

    // ── AdrenoRenderPhase ordering ────────────────────────────────────────────

    #[test]
    fn phase_ordering_monotone() {
        assert!(AdrenoRenderPhase::NotStarted < AdrenoRenderPhase::DrmDriverBound);
        assert!(AdrenoRenderPhase::DrmDriverBound < AdrenoRenderPhase::GrallocReady);
        assert!(AdrenoRenderPhase::GrallocReady < AdrenoRenderPhase::HwcReady);
        assert!(AdrenoRenderPhase::HwcReady < AdrenoRenderPhase::VulkanReady);
        assert!(AdrenoRenderPhase::VulkanReady < AdrenoRenderPhase::RenderingActive);
        assert!(AdrenoRenderPhase::RenderingActive < AdrenoRenderPhase::GatePassed);
    }

    // ── AdrenoRenderState::process_line ──────────────────────────────────────

    #[test]
    fn process_drm_bound_advances_phase() {
        let mut s = AdrenoRenderState::new();
        s.process_line(b"[   1.234] msm_drm msm_drm: bound 0000:01:00.0 (ops msm_ops)");
        assert_eq!(s.phase, AdrenoRenderPhase::DrmDriverBound);
    }

    #[test]
    fn process_gralloc_ready_advances_phase() {
        let mut s = AdrenoRenderState::new();
        s.phase = AdrenoRenderPhase::DrmDriverBound;
        s.process_line(b"gralloc: opened render node /dev/dri/renderD128");
        assert_eq!(s.phase, AdrenoRenderPhase::GrallocReady);
    }

    #[test]
    fn process_hwc_ready_advances_phase() {
        let mut s = AdrenoRenderState::new();
        s.phase = AdrenoRenderPhase::GrallocReady;
        s.process_line(b"DrmHwcTwo::Init: success");
        assert_eq!(s.phase, AdrenoRenderPhase::HwcReady);
    }

    #[test]
    fn process_vulkan_ready_sets_gate_flag() {
        let mut s = AdrenoRenderState::new();
        s.process_line(b"TU_DEBUG: Turnip initialized on Adreno 740");
        assert!(s.gate.vulkan_shows_adreno);
        assert_eq!(s.phase, AdrenoRenderPhase::VulkanReady);
    }

    #[test]
    fn process_gpu_compositing_advances_to_rendering_active() {
        let mut s = AdrenoRenderState::new();
        s.phase = AdrenoRenderPhase::VulkanReady;
        s.process_line(b"SurfaceFlinger: GPU compositing enabled");
        assert_eq!(s.phase, AdrenoRenderPhase::RenderingActive);
    }

    #[test]
    fn process_gate_passed_when_all_criteria_met() {
        let mut s = AdrenoRenderState::new();
        s.phase = AdrenoRenderPhase::RenderingActive;
        s.gate.vulkan_shows_adreno = true;
        s.gate.glmark2_es2_runs = true;
        s.gate.youtube_1080p_plays = true;
        // Trigger gate check via any line
        s.process_line(b"irrelevant");
        assert_eq!(s.phase, AdrenoRenderPhase::GatePassed);
    }

    #[test]
    fn process_unknown_line_does_not_advance_phase() {
        let mut s = AdrenoRenderState::new();
        s.process_line(b"some unrelated log line");
        assert_eq!(s.phase, AdrenoRenderPhase::NotStarted);
    }

    // ── contains_bytes ────────────────────────────────────────────────────────

    #[test]
    fn contains_bytes_exact_match() {
        assert!(contains_bytes(b"hello world", b"hello world"));
    }

    #[test]
    fn contains_bytes_substring() {
        assert!(contains_bytes(b"hello world", b"world"));
    }

    #[test]
    fn contains_bytes_prefix() {
        assert!(contains_bytes(b"hello world", b"hello"));
    }

    #[test]
    fn contains_bytes_not_found() {
        assert!(!contains_bytes(b"hello world", b"xyz"));
    }

    #[test]
    fn contains_bytes_empty_needle() {
        assert!(contains_bytes(b"anything", b""));
    }

    #[test]
    fn contains_bytes_empty_haystack_nonempty_needle() {
        assert!(!contains_bytes(b"", b"x"));
    }

    #[test]
    fn contains_bytes_needle_longer_than_haystack() {
        assert!(!contains_bytes(b"hi", b"hello"));
    }

    // ── ADRENO_RENDER_DEFCONFIG ───────────────────────────────────────────────

    #[test]
    fn defconfig_has_drm_msm_required() {
        let has = ADRENO_RENDER_DEFCONFIG
            .iter()
            .any(|e| e.entry.name == b"CONFIG_DRM_MSM"
                && e.entry.value == DefconfigValue::Enabled);
        assert!(has, "CONFIG_DRM_MSM=y must be in ADRENO_RENDER_DEFCONFIG");
    }

    #[test]
    fn defconfig_has_sync_file_required() {
        let has = ADRENO_RENDER_DEFCONFIG
            .iter()
            .any(|e| e.entry.name == b"CONFIG_SYNC_FILE"
                && e.entry.value == DefconfigValue::Enabled);
        assert!(has, "CONFIG_SYNC_FILE=y must be in ADRENO_RENDER_DEFCONFIG");
    }

    #[test]
    fn defconfig_has_dmabuf_heaps_required() {
        let has = ADRENO_RENDER_DEFCONFIG
            .iter()
            .any(|e| e.entry.name == b"CONFIG_DMABUF_HEAPS"
                && e.entry.value == DefconfigValue::Enabled);
        assert!(has, "CONFIG_DMABUF_HEAPS=y must be in ADRENO_RENDER_DEFCONFIG");
    }

    #[test]
    fn defconfig_fb_is_disabled() {
        let has = ADRENO_RENDER_DEFCONFIG
            .iter()
            .any(|e| e.entry.name == b"CONFIG_FB"
                && e.entry.value == DefconfigValue::Disabled);
        assert!(has, "CONFIG_FB must be disabled in ADRENO_RENDER_DEFCONFIG");
    }

    #[test]
    fn defconfig_no_empty_silent_failures() {
        for entry in ADRENO_RENDER_DEFCONFIG {
            assert!(
                !entry.silent_failure.is_empty(),
                "Every defconfig entry must document its silent failure mode"
            );
        }
    }

    // ── ADRENO_SELINUX_RULES ──────────────────────────────────────────────────

    #[test]
    fn selinux_has_gralloc_default_gpu_device() {
        let has = ADRENO_SELINUX_RULES
            .iter()
            .any(|r| r.domain == "gralloc_default" && r.object == "gpu_device");
        assert!(has, "gralloc_default gpu_device rule must be present");
    }

    #[test]
    fn selinux_all_rules_have_silent_failure() {
        for rule in ADRENO_SELINUX_RULES {
            assert!(
                !rule.silent_failure.is_empty(),
                "Every SELinux rule must document its silent failure"
            );
        }
    }

    // ── ADRENO_AOSP_BUILD_VARS ────────────────────────────────────────────────

    #[test]
    fn aosp_build_vars_has_board_gpu_drivers() {
        let has = ADRENO_AOSP_BUILD_VARS
            .iter()
            .any(|v| v.name == "BOARD_GPU_DRIVERS" && v.value == "adreno");
        assert!(has, "BOARD_GPU_DRIVERS := adreno must be in ADRENO_AOSP_BUILD_VARS");
    }

    #[test]
    fn aosp_build_vars_has_drm_hwcomposer() {
        let has = ADRENO_AOSP_BUILD_VARS
            .iter()
            .any(|v| v.name == "BOARD_USES_DRM_HWCOMPOSER" && v.value == "true");
        assert!(has);
    }

    #[test]
    fn aosp_product_packages_has_vulkan_freedreno() {
        let has = ADRENO_PRODUCT_PACKAGES.iter().any(|&p| p == "vulkan.freedreno");
        assert!(has, "vulkan.freedreno must be in ADRENO_PRODUCT_PACKAGES");
    }

    #[test]
    fn aosp_product_packages_has_gralloc_v2_service() {
        let has = ADRENO_PRODUCT_PACKAGES
            .iter()
            .any(|&p| p.contains("graphics.allocator"));
        assert!(has, "Gralloc allocator service must be in ADRENO_PRODUCT_PACKAGES");
    }

    // ── init_adreno_render_pipeline ───────────────────────────────────────────

    #[test]
    fn init_pipeline_defaults_ok() {
        let cfg = AdrenoRenderConfig::aether_defaults();
        let result = init_adreno_render_pipeline(&cfg);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.phase, AdrenoRenderPhase::NotStarted);
        assert!(!state.gate.passes());
    }

    #[test]
    fn init_pipeline_invalid_config_errors() {
        let mut cfg = AdrenoRenderConfig::aether_defaults();
        cfg.driver_source = GpuDriverSource::QualcommProprietary;
        let result = init_adreno_render_pipeline(&cfg);
        assert!(result.is_err());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::size_of;

    // Gate must be small enough for stack use in no_std early boot.
    assert!(size_of::<AdrenoRenderGate>() <= 8, "AdrenoRenderGate must be ≤ 8 bytes");

    // Config must be stack-allocable in early boot (no heap).
    assert!(
        size_of::<AdrenoRenderConfig>() <= 512,
        "AdrenoRenderConfig must be ≤ 512 bytes"
    );

    // Vulkan 1.3 API version must be (1, 3, 0) — encoded as three u8s.
    let (major, minor, patch) = VulkanIcdConfig::aether_defaults().api_version;
    assert!(major == 1, "Mesa Turnip major version must be 1");
    assert!(minor == 3, "Mesa Turnip minor version must be 3 (Vulkan 1.3)");
    assert!(patch == 0, "Mesa Turnip patch version must be 0");

    // Default render node path must reference renderD128 (Adreno VF DRM node).
    let render_node = GrallocHalConfig::aether_defaults().render_node_path;
    // Cannot use starts_with in const context; verify first char is '/'
    assert!(render_node.as_bytes()[0] == b'/', "render_node_path must be absolute");

    // Defconfig table must be non-empty.
    assert!(
        !ADRENO_RENDER_DEFCONFIG.is_empty(),
        "ADRENO_RENDER_DEFCONFIG must not be empty"
    );

    // SELinux rules table must be non-empty.
    assert!(
        !ADRENO_SELINUX_RULES.is_empty(),
        "ADRENO_SELINUX_RULES must not be empty"
    );

    // AOSP build vars table must be non-empty.
    assert!(
        !ADRENO_AOSP_BUILD_VARS.is_empty(),
        "ADRENO_AOSP_BUILD_VARS must not be empty"
    );

    // Product packages list must be non-empty.
    assert!(
        !ADRENO_PRODUCT_PACKAGES.is_empty(),
        "ADRENO_PRODUCT_PACKAGES must not be empty"
    );
};
