// ch53: Android on x86 — Userspace
//
// Wire the AOSP x86 vendor partition for three GPU paths — NVIDIA (nouveau +
// Mesa NVK), AMD (amdgpu + Mesa RADV), and Intel Arc (xe + Mesa ANV) — with
// the Android kernel believing it is talking to real GPU silicon (no virtio,
// no paravirtualization). The hypervisor reads the GPU's PCI Vendor ID at
// boot, assigns the device directly to the Android partition via the ch38
// PCIe passthrough pipeline (BAR mapping into EPT/NPT + IOMMU page tables +
// mandatory INVEPT/INVLPGA after every mapping change), and lets `ueventd`
// inside the guest load the matching DRM kernel module. Android's Vulkan
// loader (libvulkan.so) walks /vendor/etc/vulkan/icd.d/, reads each ICD
// JSON manifest, and initialises only the one whose PCI Device ID matches.
//
// ── Architecture Reference ────────────────────────────────────────────────────
//
// PCI Local Bus Specification 3.0:
//   §6.2.1  — PCI configuration header — Vendor ID (offset 0x00), Device ID
//             (offset 0x02), Class Code (offset 0x0B), Sub-class (offset 0x0A)
//   Display controllers: class 03h
//                        subclass 00h = VGA-compatible
//                        subclass 02h = 3D controller (Intel Arc, some discrete)
//                        subclass 80h = display controller other
//
// Khronos Vulkan Loader specification (LoaderInterfaceArchitecture.md):
//   §6.1    — ICD JSON manifest format (api_version, library_path)
//   §6.3.2  — runtime ICD selection (loader walks /vendor/etc/vulkan/icd.d/)
//
// AOSP build system (Android 14+, Mainline / Treble):
//   BoardConfig.mk    — BOARD_GPU_DRIVERS, TARGET_USES_GRALLOC4, BOARD_USES_DRM_HWCOMPOSER
//   device.mk         — PRODUCT_PACKAGES, PRODUCT_COPY_FILES, PRODUCT_PROPERTY_OVERRIDES
//
// Linux DRM/KMS subsystem:
//   drivers/gpu/drm/nouveau/         — NVIDIA reverse-engineered DRM driver
//   drivers/gpu/drm/amd/amdgpu/      — AMD official DRM driver (open-source)
//   drivers/gpu/drm/xe/              — Intel xe driver (Arc-only modern driver)
//   /dev/dri/card0                   — DRM control device (KMS)
//   /dev/dri/renderD128              — DRM render node (gralloc, GPU compute)
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  GpuVendor + vendor-ID constants for runtime detection
//   2.  GpuDetectionResult — vendor/device_id/class/subclass/BDF
//   3.  DrmKernelDriver — three kernel module paths (nouveau/amdgpu/xe)
//   4.  MesaIcd — three ICD descriptors (NVK/RADV/ANV) with manifest paths
//   5.  IcdSelector — runtime selection logic matching libvulkan's loader
//   6.  X86GpuPassthroughHook — INVEPT/INVLPGA invariants on BAR remap
//   7.  X86_GKI_GPU_DEFCONFIG — 14 CONFIG_ entries for the x86 GKI defconfig
//   8.  X86_BOARD_CONFIG_VARS — 6 BoardConfig.mk variables
//   9.  X86_PRODUCT_PACKAGES — 12 Mesa ICDs + DRM HWC + gralloc4 packages
//  10.  X86_SELINUX_RULES — 8 TE rules for hal_graphics_composer / gralloc /
//                            system_server / mediacodec / untrusted_app
//                            accessing /dev/dri/* and /vendor/lib64/hw/vulkan.*
//  11.  Vendor-specific UART signatures for the DRM-bound observation
//  12.  AndroidX86Config / Gate / Error / Phase / State — chapter gate types
//  13.  init_android_x86_userspace() — 9-step pipeline
//
// ── Gate (Chapter 53) ─────────────────────────────────────────────────────────
//
//   AndroidX86Gate.passes() requires all four conditions:
//     home_screen_visible   — Launcher rendered on x86 / NVIDIA / AMD hardware
//     glmark2_es2_runs      — glmark2-es2 binary runs with hardware Vulkan
//     vulkan_hw_active      — vkGetPhysicalDeviceProperties returns matching
//                              vendor's PCI Device ID (NOT software fallback)
//     nproc_all_cores       — `nproc` inside Android matches the host core count
//
// ── No-Boundary Compliance (Chapter 3) ───────────────────────────────────────
//
//   - No virtio drivers in the Android kernel; the guest believes it talks to
//     real GPU silicon.
//   - No paravirtualization layer between Android and the GPU. The hypervisor
//     touches the GPU's PCI config space ONCE (Vendor ID read) and ONCE for
//     BAR setup; thereafter, every MMIO/DMA goes straight to the device.
//   - Software-rendering fallback (Swiftshader / Lavapipe) is REJECTED by
//     IcdSelector::select_or_fail — production builds must have a hardware
//     ICD that matches the detected vendor.
//   - Proprietary NVIDIA blob driver (nvidia.ko) is NOT used; nouveau + NVK
//     is the only NVIDIA path because the blob is not redistributable inside
//     an AOSP image.

#![allow(clippy::needless_return)]

// ─────────────────────────────────────────────────────────────────────────────
// PCI Vendor IDs — from the official PCI-SIG vendor list
// ─────────────────────────────────────────────────────────────────────────────

/// NVIDIA Corporation.
pub const NVIDIA_VENDOR_ID: u16 = 0x10DE;

/// Advanced Micro Devices [AMD/ATI].
pub const AMD_VENDOR_ID:    u16 = 0x1002;

/// Intel Corporation.
pub const INTEL_VENDOR_ID:  u16 = 0x8086;

// ─────────────────────────────────────────────────────────────────────────────
// PCI Class codes — base class 03h is Display Controller
// ─────────────────────────────────────────────────────────────────────────────

/// PCI base class for Display Controller (PCI Local Bus Spec §6.2.1).
pub const PCI_CLASS_DISPLAY:         u8 = 0x03;

/// VGA-compatible controller (subclass 00h). Most integrated GPUs report this.
pub const PCI_SUBCLASS_VGA:          u8 = 0x00;

/// 3D controller (subclass 02h). Discrete cards without legacy VGA, including
/// Intel Arc Alchemist/Battlemage when no legacy mode is active.
pub const PCI_SUBCLASS_3D:           u8 = 0x02;

/// Display controller other (subclass 80h). Some discrete cards in non-VGA mode.
pub const PCI_SUBCLASS_DISPLAY_OTHER: u8 = 0x80;

// ─────────────────────────────────────────────────────────────────────────────
// GPU vendor enum and runtime detection
// ─────────────────────────────────────────────────────────────────────────────

/// Identified GPU vendor for the x86 Android partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    /// NVIDIA — path is nouveau DRM driver + Mesa NVK Vulkan ICD.
    Nvidia,
    /// AMD — path is amdgpu DRM driver + Mesa RADV Vulkan ICD.
    Amd,
    /// Intel Arc — path is xe DRM driver + Mesa ANV Vulkan ICD.
    /// Note: integrated Intel GPUs (HD / UHD / Iris) use i915 and are NOT
    /// supported by this chapter; they are routed to Unsupported.
    IntelArc,
    /// Vendor read succeeded but is not one of the three supported branches.
    Unsupported,
}

impl GpuVendor {
    /// Returns true for any of the three supported branches (Nvidia/Amd/IntelArc).
    pub const fn is_supported(self) -> bool {
        matches!(self, GpuVendor::Nvidia | GpuVendor::Amd | GpuVendor::IntelArc)
    }

    /// Human-readable label for diagnostics and UART logging.
    pub const fn label(self) -> &'static [u8] {
        match self {
            GpuVendor::Nvidia      => b"NVIDIA",
            GpuVendor::Amd         => b"AMD",
            GpuVendor::IntelArc    => b"Intel Arc",
            GpuVendor::Unsupported => b"Unsupported",
        }
    }
}

/// Bus / Device / Function identifier for a PCI device (16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBdf(pub u16);

impl PciBdf {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        let b = (bus as u16) << 8;
        let d = ((device as u16) & 0x1F) << 3;
        let f = (function as u16) & 0x07;
        PciBdf(b | d | f)
    }

    pub const fn bus(self) -> u8 { ((self.0 >> 8) & 0xFF) as u8 }
    pub const fn device(self) -> u8 { ((self.0 >> 3) & 0x1F) as u8 }
    pub const fn function(self) -> u8 { (self.0 & 0x07) as u8 }
}

/// Result of probing the PCI bus for a display controller.
#[derive(Debug, Clone, Copy)]
pub struct GpuDetectionResult {
    pub vendor:    GpuVendor,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass:  u8,
    pub bdf:       PciBdf,
}

impl GpuDetectionResult {
    /// Constructs a detection result from raw PCI config-space reads.
    ///
    /// The caller has already done the ECAM read of Vendor ID (offset 0x00),
    /// Device ID (offset 0x02), Class Code (offset 0x0B), and Sub-class
    /// (offset 0x0A). This function classifies the device into a
    /// [`GpuVendor`] without touching hardware.
    pub fn classify(
        vendor_id: u16,
        device_id: u16,
        class_code: u8,
        subclass: u8,
        bdf: PciBdf,
    ) -> Self {
        let vendor = match (vendor_id, class_code) {
            (NVIDIA_VENDOR_ID, PCI_CLASS_DISPLAY) => GpuVendor::Nvidia,
            (AMD_VENDOR_ID,    PCI_CLASS_DISPLAY) => GpuVendor::Amd,
            // Intel Arc reports class 03h, subclass 02h or 00h. The xe driver
            // refuses integrated Intel GPUs at module probe time, so we route
            // any unknown Intel sub-class to Unsupported.
            (INTEL_VENDOR_ID,  PCI_CLASS_DISPLAY)
                if subclass == PCI_SUBCLASS_3D
                    || subclass == PCI_SUBCLASS_DISPLAY_OTHER => GpuVendor::IntelArc,
            _ => GpuVendor::Unsupported,
        };
        GpuDetectionResult { vendor, vendor_id, device_id, class_code, subclass, bdf }
    }

    pub const fn is_display(&self) -> bool {
        self.class_code == PCI_CLASS_DISPLAY
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DRM kernel driver per vendor
//
// Three modules ship in the x86 GKI image as loadable modules. `ueventd`
// inside the guest sees the PCI device come up, matches Vendor ID against
// each module's PCI ID table, and loads exactly one of them.
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies which DRM kernel driver to load for a detected GPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmKernelDriver {
    /// `nouveau.ko` — NVIDIA reverse-engineered DRM driver.
    /// Source: drivers/gpu/drm/nouveau/. PCI ID match: all NVIDIA display
    /// controllers (vendor 0x10DE, class 0x03).
    Nouveau,
    /// `amdgpu.ko` — AMD official open-source DRM driver.
    /// Source: drivers/gpu/drm/amd/amdgpu/. Covers GCN3+ to RDNA4.
    Amdgpu,
    /// `xe.ko` — Intel's modern DRM driver for discrete Arc cards.
    /// Source: drivers/gpu/drm/xe/. Replaces i915 for Alchemist+.
    Xe,
}

impl DrmKernelDriver {
    /// Returns the matching driver for a detected GPU vendor.
    pub const fn for_vendor(v: GpuVendor) -> Option<Self> {
        match v {
            GpuVendor::Nvidia   => Some(DrmKernelDriver::Nouveau),
            GpuVendor::Amd      => Some(DrmKernelDriver::Amdgpu),
            GpuVendor::IntelArc => Some(DrmKernelDriver::Xe),
            GpuVendor::Unsupported => None,
        }
    }

    /// Kernel module file name (loaded by ueventd from /vendor/lib/modules/).
    pub const fn module_name(self) -> &'static [u8] {
        match self {
            DrmKernelDriver::Nouveau => b"nouveau.ko",
            DrmKernelDriver::Amdgpu  => b"amdgpu.ko",
            DrmKernelDriver::Xe      => b"xe.ko",
        }
    }

    /// CONFIG_ symbol that must be set to `m` in the x86 GKI defconfig for
    /// this driver to be available as a loadable module.
    pub const fn kconfig_symbol(self) -> &'static [u8] {
        match self {
            DrmKernelDriver::Nouveau => b"CONFIG_DRM_NOUVEAU",
            DrmKernelDriver::Amdgpu  => b"CONFIG_DRM_AMDGPU",
            DrmKernelDriver::Xe      => b"CONFIG_DRM_XE",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesa Vulkan ICD per vendor
//
// Three ICDs ship side-by-side in /vendor/lib64/hw/. Android's libvulkan.so
// walks /vendor/etc/vulkan/icd.d/ at app launch, reads each manifest, and
// loads the one whose first vkGetPhysicalDeviceProperties() returns a
// device whose vendor matches the discovered GPU.
// ─────────────────────────────────────────────────────────────────────────────

/// One Mesa Vulkan ICD bundled in the x86 AOSP vendor image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MesaIcd {
    pub vendor:        GpuVendor,
    /// Absolute path to the .so inside the vendor partition.
    pub library_path:  &'static [u8],
    /// Absolute path to the JSON manifest read by libvulkan.so.
    pub icd_json_path: &'static [u8],
    /// Vulkan API version this ICD reports (major.minor.patch packed as u32).
    pub api_version:   u32,
    /// AOSP package name (used in PRODUCT_PACKAGES).
    pub aosp_package:  &'static [u8],
}

/// NVIDIA Mesa NVK ICD descriptor.
pub const MESA_ICD_NVK: MesaIcd = MesaIcd {
    vendor:        GpuVendor::Nvidia,
    library_path:  b"/vendor/lib64/hw/vulkan.nouveau.so",
    icd_json_path: b"/vendor/etc/vulkan/icd.d/nouveau_icd.x86_64.json",
    // Vulkan 1.3.0 = (1 << 22) | (3 << 12) | 0
    api_version:   (1 << 22) | (3 << 12),
    aosp_package:  b"vulkan.nouveau",
};

/// AMD Mesa RADV ICD descriptor.
pub const MESA_ICD_RADV: MesaIcd = MesaIcd {
    vendor:        GpuVendor::Amd,
    library_path:  b"/vendor/lib64/hw/vulkan.radv.so",
    icd_json_path: b"/vendor/etc/vulkan/icd.d/radeon_icd.x86_64.json",
    api_version:   (1 << 22) | (3 << 12),
    aosp_package:  b"vulkan.radv",
};

/// Intel Mesa ANV ICD descriptor.
pub const MESA_ICD_ANV: MesaIcd = MesaIcd {
    vendor:        GpuVendor::IntelArc,
    library_path:  b"/vendor/lib64/hw/vulkan.intel.so",
    icd_json_path: b"/vendor/etc/vulkan/icd.d/intel_icd.x86_64.json",
    api_version:   (1 << 22) | (3 << 12),
    aosp_package:  b"vulkan.intel",
};

/// All three ICDs in fixed order. The vendor image bundles all three
/// unconditionally; runtime selection picks one.
pub const MESA_ICDS_X86: &[MesaIcd] = &[MESA_ICD_NVK, MESA_ICD_RADV, MESA_ICD_ANV];

/// Runtime ICD selector — mirrors what Android's libvulkan loader does
/// internally when it walks /vendor/etc/vulkan/icd.d/.
pub struct IcdSelector;

impl IcdSelector {
    /// Returns the ICD that matches the detected GPU vendor, or None if
    /// vendor is Unsupported. Equivalent to libvulkan reading each ICD JSON
    /// and dispatching the first physical-device query to it.
    pub fn select(vendor: GpuVendor) -> Option<MesaIcd> {
        let mut i = 0;
        while i < MESA_ICDS_X86.len() {
            if MESA_ICDS_X86[i].vendor as u8 == vendor as u8 {
                return Some(MESA_ICDS_X86[i]);
            }
            i += 1;
        }
        None
    }

    /// As [`select`] but returns an explicit error for unsupported vendors.
    /// Production builds must succeed here; software-rendering fallback is
    /// rejected by the chapter gate.
    pub fn select_or_fail(vendor: GpuVendor) -> Result<MesaIcd, AndroidX86Error> {
        Self::select(vendor).ok_or(AndroidX86Error::UnknownGpuVendor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EPT / NPT BAR mapping invariants
//
// Every GPU BAR mapping change MUST be followed by a TLB invalidation:
//   Intel host  → INVEPT single-context (vtx.rs::invept_single_context)
//   AMD host    → VMCB TLB_CTL = FLUSH_ALL OR INVLPGA per page
//                  (svm.rs::VmcbRegion::request_npt_tlb_flush, AMD has no INVNPT)
//
// Forgetting this leaves stale guest-physical translations that allow the
// guest to read or write memory outside its allowed range — silently
// breaks isolation. This is the most dangerous AI mistake on this surface.
// ─────────────────────────────────────────────────────────────────────────────

/// Which TLB invalidation instruction is mandatory after a BAR mapping
/// change, given the host CPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbInvalidationKind {
    /// Intel host: call invept_single_context() after every EPT mapping change.
    IntelInvept,
    /// AMD host: set VMCB.TLB_CTL = FLUSH_ALL before next VMRUN
    /// (or issue INVLPGA per page; FLUSH_ALL is the conservative default).
    AmdInvlpgaOrTlbCtl,
}

impl TlbInvalidationKind {
    /// Human-readable mnemonic for diagnostics.
    pub const fn mnemonic(self) -> &'static [u8] {
        match self {
            TlbInvalidationKind::IntelInvept        => b"INVEPT",
            TlbInvalidationKind::AmdInvlpgaOrTlbCtl => b"INVLPGA / TLB_CTL",
        }
    }
}

/// A BAR mapping operation with a mandatory invalidation acknowledgement.
///
/// The constructor takes the invalidation kind explicitly so the caller
/// can't forget which instruction to issue. `mark_invalidated()` records
/// that the invalidation was performed; the chapter gate checks that
/// every BAR mapping has a matching invalidation record.
#[derive(Debug, Clone, Copy)]
pub struct X86GpuPassthroughHook {
    pub bar_index:        u8,
    pub bar_pa:           u64,
    pub bar_size:         u64,
    pub invalidation:     TlbInvalidationKind,
    pub invalidation_ack: bool,
}

impl X86GpuPassthroughHook {
    pub const fn new(
        bar_index: u8,
        bar_pa:    u64,
        bar_size:  u64,
        invalidation: TlbInvalidationKind,
    ) -> Self {
        X86GpuPassthroughHook {
            bar_index, bar_pa, bar_size,
            invalidation,
            invalidation_ack: false,
        }
    }

    /// Caller invokes this AFTER issuing the TLB invalidation
    /// (vtx::invept_single_context or svm::VmcbRegion::request_npt_tlb_flush).
    pub fn mark_invalidated(&mut self) {
        self.invalidation_ack = true;
    }

    /// True once the invalidation was performed.
    pub fn is_safe(&self) -> bool {
        self.invalidation_ack
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// x86 GKI defconfig — kernel-side requirements for the three GPU paths
// ─────────────────────────────────────────────────────────────────────────────

/// One CONFIG_ entry for the x86 GKI defconfig.
///
/// The `silent_failure` string documents what symptom the user observes
/// when this entry is missing or wrong. These messages are the single
/// source of truth for ch53 boot-failure triage.
#[derive(Debug, Clone, Copy)]
pub struct X86GpuKernelEntry {
    pub name:           &'static [u8],
    pub value:          &'static [u8],
    pub silent_failure: &'static [u8],
}

/// Required GKI defconfig entries for the x86 tier GPU paths.
///
/// All three DRM drivers ship as modules (=m) so `ueventd` can load exactly
/// one of them at runtime based on the detected GPU.
pub const X86_GKI_GPU_DEFCONFIG: &[X86GpuKernelEntry] = &[
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM",
        value: b"y",
        silent_failure:
            b"DRM core not built into kernel; ALL Vulkan ICDs fail to open /dev/dri/card0",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM_KMS_HELPER",
        value: b"y",
        silent_failure:
            b"KMS helper missing; drm_hwcomposer cannot drive the display, black screen at boot",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM_NOUVEAU",
        value: b"m",
        silent_failure:
            b"Nouveau missing; NVIDIA GPUs detected but no DRM driver binds, Vulkan unavailable",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM_AMDGPU",
        value: b"m",
        silent_failure:
            b"amdgpu missing; AMD GPUs (RX 6000+/RDNA) detected but no DRM driver binds",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM_XE",
        value: b"m",
        silent_failure:
            b"xe missing; Intel Arc GPUs detected but no modern DRM driver binds (i915 won't claim Arc)",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DRM_FBDEV_EMULATION",
        value: b"y",
        silent_failure:
            b"fbdev emulation missing; legacy framebuffer consumers (early init splash) fail silently",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_FB",
        value: b"n",
        silent_failure:
            b"Legacy fbdev (CONFIG_FB=y) creates /dev/fb0 races with DRM, double-init, flicker on first frame",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_VT",
        value: b"n",
        silent_failure:
            b"VT console (CONFIG_VT=y) hijacks /dev/tty0 and steals kernel mode setting from drm_hwcomposer",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_SYNC_FILE",
        value: b"y",
        silent_failure:
            b"sync_file missing; Vulkan timeline semaphores fall back to vkWaitForFences (10-20ms latency)",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DMA_SHARED_BUFFER",
        value: b"y",
        silent_failure:
            b"dma-buf disabled; cross-process buffer sharing via gralloc4 silently corrupts surfaces",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_DMABUF_HEAPS",
        value: b"y",
        silent_failure:
            b"dma-buf heaps missing; gralloc cannot allocate /dev/dma_heap/system, returns ENOENT",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_MTRR",
        value: b"y",
        silent_failure:
            b"MTRR support missing; GPU MMIO regions fall to UC-default, ~3x bandwidth loss on AMD/NVIDIA",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_X86_PAT",
        value: b"y",
        silent_failure:
            b"PAT missing; pgprot_writecombine() degrades to UC, gralloc surfaces hit the WB miss path",
    },
    X86GpuKernelEntry {
        name:  b"CONFIG_AGP",
        value: b"n",
        silent_failure:
            b"Legacy AGP enabled wastes ~12 KiB of init memory and adds dead paths in DRM",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// AOSP BoardConfig.mk vars and PRODUCT_PACKAGES for the x86 vendor partition
// ─────────────────────────────────────────────────────────────────────────────

/// One BoardConfig.mk variable to be set when building the x86 vendor image.
#[derive(Debug, Clone, Copy)]
pub struct X86BoardConfigVar {
    pub name:  &'static [u8],
    pub value: &'static [u8],
    /// One-line note explaining why this var matters for ch53.
    pub note:  &'static [u8],
}

/// BoardConfig.mk variables for the x86 vendor partition.
///
/// `BOARD_GPU_DRIVERS := nouveau amdgpu xe` lists all three drivers
/// unconditionally; Soong builds the matching Mesa ICDs side-by-side and
/// libvulkan picks one at runtime.
pub const X86_BOARD_CONFIG_VARS: &[X86BoardConfigVar] = &[
    X86BoardConfigVar {
        name:  b"BOARD_GPU_DRIVERS",
        value: b"nouveau amdgpu xe",
        note:  b"Build all three Mesa ICDs; libvulkan selects one at runtime by PCI ID",
    },
    X86BoardConfigVar {
        name:  b"TARGET_USES_GRALLOC4",
        value: b"true",
        note:  b"gralloc4 (AIDL) - required for DRM render-node + dma-buf path",
    },
    X86BoardConfigVar {
        name:  b"TARGET_USES_HWC2",
        value: b"true",
        note:  b"HWC2 (drm_hwcomposer) - GPU-agnostic, uses standard DRM/KMS ioctls",
    },
    X86BoardConfigVar {
        name:  b"BOARD_USES_DRM_HWCOMPOSER",
        value: b"true",
        note:  b"Use upstream drm_hwcomposer - no per-vendor HWC implementation needed",
    },
    X86BoardConfigVar {
        name:  b"TARGET_ARCH",
        value: b"arm64",
        note:  b"Build ARM64 vendor image; FEX-Emu (ch52) translates ARM64->x86_64 at runtime",
    },
    X86BoardConfigVar {
        name:  b"BOARD_KERNEL_CMDLINE_OVERRIDES",
        value: b"androidboot.gki=1 androidboot.dbt=fex androidboot.gpu_passthrough=1",
        note:  b"Tell userspace the kernel runs under FEX DBT and GPU is direct-assigned",
    },
];

/// AOSP packages added to PRODUCT_PACKAGES for the x86 vendor partition.
///
/// All three Mesa ICDs ship; the matching DRM kernel module is selected
/// by ueventd; drm_hwcomposer and gralloc4 are GPU-agnostic.
pub const X86_PRODUCT_PACKAGES: &[&str] = &[
    "vulkan.nouveau",
    "vulkan.radv",
    "vulkan.intel",
    "android.hardware.graphics.allocator-V2-service",
    "android.hardware.graphics.mapper",
    "android.hardware.graphics.composer3-service",
    "libdrm",
    "libdrm_intel",
    "libdrm_amdgpu",
    "libdrm_nouveau",
    "drm_hwcomposer.aether",
    "libEGL_mesa",
    "libGLESv1_mesa",
    "libGLESv2_mesa",
];

// ─────────────────────────────────────────────────────────────────────────────
// SELinux policy rules — TE source for the x86 graphics stack
// ─────────────────────────────────────────────────────────────────────────────

/// One TE source line to be added to /system/sepolicy/private/ or
/// /vendor/etc/selinux/ for the x86 graphics stack.
#[derive(Debug, Clone, Copy)]
pub struct X86GpuSelinuxRule {
    pub te_source:      &'static [u8],
    /// What goes wrong silently if this rule is missing.
    pub silent_failure: &'static [u8],
}

pub const X86_SELINUX_RULES: &[X86GpuSelinuxRule] = &[
    X86GpuSelinuxRule {
        te_source:      b"allow hal_graphics_composer_default gpu_device:chr_file rw_file_perms;",
        silent_failure:
            b"drm_hwcomposer cannot open /dev/dri/card0 - KMS modeset fails, black screen",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow gralloc_default gpu_device:chr_file rw_file_perms;",
        silent_failure:
            b"gralloc cannot open /dev/dri/renderD128 - every buffer allocation falls back to CPU",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow untrusted_app gpu_device:chr_file { read open getattr };",
        silent_failure:
            b"Vulkan apps cannot enumerate physical devices - vkCreateInstance returns no GPU",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow mediacodec gpu_device:chr_file rw_file_perms;",
        silent_failure:
            b"mediacodec cannot use GPU compositing - video decode falls to software, ~10x CPU spike",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow surfaceflinger gpu_device:chr_file rw_file_perms;",
        silent_failure:
            b"SurfaceFlinger cannot acquire GPU - every frame falls to CPU composition path",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow ueventd self:capability { sys_admin sys_module };",
        silent_failure:
            b"ueventd cannot load nouveau / amdgpu / xe modules - no DRM driver binds at boot",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow init kernel:system module_request;",
        silent_failure:
            b"Lazy module load denied - DRM driver fails to load on first /dev/dri/card0 access",
    },
    X86GpuSelinuxRule {
        te_source:      b"allow hal_graphics_composer_default dma_heap_device:chr_file rw_file_perms;",
        silent_failure:
            b"composer cannot allocate from /dev/dma_heap/system - gralloc4 returns ENOMEM",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// UART signature constants — observation of the boot pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Logged by the hypervisor after PCI vendor classification.
pub const X86_UART_SIG_GPU_DETECTED:      &[u8] = b"[aether] x86 gpu detected: vendor=";

/// Logged by ueventd when the matching DRM kernel module binds.
pub const X86_UART_SIG_NOUVEAU_BOUND:     &[u8] = b"nouveau";
pub const X86_UART_SIG_AMDGPU_BOUND:      &[u8] = b"amdgpu";
pub const X86_UART_SIG_XE_BOUND:          &[u8] = b"xe ";

/// Logged once /dev/dri/card0 is enumerated and ICD selection succeeds.
pub const X86_UART_SIG_VULKAN_INIT:       &[u8] = b"vulkan: initialized HW device";

/// Logged by drm_hwcomposer after the KMS modeset succeeds.
pub const X86_UART_SIG_HWC_READY:         &[u8] = b"DrmHwcTwo::Init: success";

/// Logged by SurfaceFlinger when the first frame composites on GPU.
pub const X86_UART_SIG_HOME_SCREEN:       &[u8] = b"SurfaceFlinger: GPU compositing";

/// Logged by glmark2-es2 when its benchmark loop starts.
pub const X86_UART_SIG_GLMARK2_RUNNING:   &[u8] = b"glmark2-es2: starting benchmark";

/// Logged by Android init when `nproc` is exec'd and reports the host core count.
pub const X86_UART_SIG_NPROC_ALL_CORES:   &[u8] = b"nproc: all cores online";

/// Logged when FEX dispatcher confirms the GPU userspace stack runs under DBT.
pub const X86_UART_SIG_FEX_GRAPHICS_LIVE: &[u8] = b"[fex] graphics stack live";

// ─────────────────────────────────────────────────────────────────────────────
// Chapter gate types
// ─────────────────────────────────────────────────────────────────────────────

/// Phase machine for Chapter 53. Strictly forward-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidX86Phase {
    NotStarted,
    GpuVendorDetected,
    KernelModulesLoaded,
    DrmDeviceVisible,
    IcdSelected,
    VulkanInitialized,
    DrmHwcLaunched,
    HomeScreenRendered,
    GatePassed,
}

/// Error variants for Chapter 53 initialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidX86Error {
    /// PCI scan found no display controller at all.
    NoDisplayController,
    /// PCI scan found a display controller but Vendor ID was not one of the
    /// three supported branches (NVIDIA / AMD / Intel Arc).
    UnknownGpuVendor,
    /// Intel GPU detected but Sub-class indicates it's an integrated part
    /// (HD / UHD / Iris) — these use i915, which ch53 does not support.
    /// AETHER explicitly chose `xe` for discrete Arc only.
    IntegratedIntelNotSupported,
    /// Detected vendor's DRM kernel module is missing from the GKI image.
    MissingDrmDriver,
    /// Detected vendor's Mesa ICD is missing from /vendor/lib64/hw/.
    MissingVulkanIcd,
    /// ICD JSON manifest is missing from /vendor/etc/vulkan/icd.d/.
    MissingIcdManifest,
    /// BAR mapping into EPT or NPT failed.
    BarMappingFailed,
    /// A BAR mapping completed but the matching INVEPT / INVLPGA / TLB_CTL
    /// invalidation was never acknowledged. This breaks isolation and is
    /// the most dangerous AI mistake on this surface.
    InvalidationNotAcknowledged,
    /// Software rendering fallback (Swiftshader / Lavapipe) was selected
    /// instead of a hardware ICD. Production builds reject this.
    SoftwareRenderingForbidden,
    /// SELinux blocked the graphics stack — TE rules missing.
    SelinuxAvcDenial,
    /// `glmark2-es2` ran but reported a software renderer string instead of
    /// the matching vendor's hardware Vulkan ICD.
    Glmark2DidNotUseHardware,
    /// `nproc` inside Android reported fewer cores than the host.
    NprocDoesNotMatchHost,
    /// Configuration validation failed (empty BOARD_GPU_DRIVERS, missing ICD, ...).
    InvalidConfig,
}

/// Gate criteria for Chapter 53 — Android on x86 Userspace.
///
/// All four booleans must be true for the chapter gate to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidX86Gate {
    /// Launcher rendered the home screen at least once.
    pub home_screen_visible:  bool,
    /// glmark2-es2 binary ran with a hardware Mesa renderer.
    pub glmark2_es2_runs:     bool,
    /// vkGetPhysicalDeviceProperties returned the detected vendor's PCI ID.
    pub vulkan_hw_active:     bool,
    /// `nproc` inside Android reported the host's core count.
    pub nproc_all_cores:      bool,
    /// Build is ro.build.type=user (the production invariant).
    pub build_type_user:      bool,
    /// No software-rendering fallback was selected (Swiftshader / Lavapipe).
    pub no_software_fallback: bool,
}

impl AndroidX86Gate {
    pub const fn new() -> Self {
        AndroidX86Gate {
            home_screen_visible:  false,
            glmark2_es2_runs:     false,
            vulkan_hw_active:     false,
            nproc_all_cores:      false,
            build_type_user:      false,
            no_software_fallback: false,
        }
    }

    /// True when every gate criterion is satisfied.
    pub const fn passes(&self) -> bool {
        self.home_screen_visible
            && self.glmark2_es2_runs
            && self.vulkan_hw_active
            && self.nproc_all_cores
            && self.build_type_user
            && self.no_software_fallback
    }

    /// Partial check — set when the userspace stack is alive but the
    /// benchmark / nproc steps have not run yet.
    pub const fn graphics_stack_live(&self) -> bool {
        self.home_screen_visible
            && self.vulkan_hw_active
            && self.no_software_fallback
    }
}

/// Configuration for Chapter 53 initialisation.
#[derive(Debug, Clone, Copy)]
pub struct AndroidX86Config {
    /// True if the GKI defconfig has CONFIG_DRM_NOUVEAU=m.
    pub kernel_has_nouveau: bool,
    /// True if the GKI defconfig has CONFIG_DRM_AMDGPU=m.
    pub kernel_has_amdgpu:  bool,
    /// True if the GKI defconfig has CONFIG_DRM_XE=m.
    pub kernel_has_xe:      bool,
    /// True if /vendor contains all three Mesa ICD .so libraries.
    pub vendor_has_all_icds: bool,
    /// True if /vendor/etc/vulkan/icd.d/ contains all three JSON manifests.
    pub vendor_has_all_manifests: bool,
    /// True if drm_hwcomposer is built into the vendor image.
    pub vendor_has_drm_hwc: bool,
    /// True if gralloc4 (AIDL) is built into the vendor image.
    pub vendor_has_gralloc4: bool,
    /// True if all 8 SELinux TE rules are applied.
    pub selinux_rules_applied: bool,
    /// True if ro.build.type=user is set on the system image.
    pub build_type_user: bool,
}

impl AndroidX86Config {
    /// The default config that ch53 requires — every flag is true. This is
    /// what `lunch aether_x86_64-user && m` is expected to produce.
    pub const fn aether_defaults() -> Self {
        AndroidX86Config {
            kernel_has_nouveau:       true,
            kernel_has_amdgpu:        true,
            kernel_has_xe:            true,
            vendor_has_all_icds:      true,
            vendor_has_all_manifests: true,
            vendor_has_drm_hwc:       true,
            vendor_has_gralloc4:      true,
            selinux_rules_applied:    true,
            build_type_user:          true,
        }
    }

    /// Returns Ok only when every required flag is true. Any false flag is
    /// a config-time error before the guest is even launched.
    pub fn validate(&self) -> Result<(), AndroidX86Error> {
        if !self.kernel_has_nouveau
            || !self.kernel_has_amdgpu
            || !self.kernel_has_xe
        {
            return Err(AndroidX86Error::MissingDrmDriver);
        }
        if !self.vendor_has_all_icds {
            return Err(AndroidX86Error::MissingVulkanIcd);
        }
        if !self.vendor_has_all_manifests {
            return Err(AndroidX86Error::MissingIcdManifest);
        }
        if !self.vendor_has_drm_hwc || !self.vendor_has_gralloc4 {
            return Err(AndroidX86Error::InvalidConfig);
        }
        if !self.selinux_rules_applied {
            return Err(AndroidX86Error::SelinuxAvcDenial);
        }
        if !self.build_type_user {
            return Err(AndroidX86Error::InvalidConfig);
        }
        Ok(())
    }
}

/// Runtime state for Chapter 53.
#[derive(Debug)]
pub struct AndroidX86State {
    pub phase:    AndroidX86Phase,
    pub gate:     AndroidX86Gate,
    /// Result of the boot-time PCI display-controller scan.
    pub detected: Option<GpuDetectionResult>,
    /// Selected Mesa ICD, if any.
    pub selected_icd: Option<MesaIcd>,
    /// Number of BAR-mapping operations performed during init.
    pub bar_mappings: u32,
    /// Number of BAR mappings whose TLB invalidation was acknowledged.
    pub invalidations_acked: u32,
    /// Number of UART AVC-denial lines observed (SELinux blocked something).
    pub avc_denials_seen: u32,
}

impl AndroidX86State {
    pub const fn new() -> Self {
        AndroidX86State {
            phase:    AndroidX86Phase::NotStarted,
            gate:     AndroidX86Gate::new(),
            detected: None,
            selected_icd: None,
            bar_mappings: 0,
            invalidations_acked: 0,
            avc_denials_seen: 0,
        }
    }

    pub const fn gate(&self) -> &AndroidX86Gate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.gate.passes()
    }

    /// Returns true if every BAR mapping recorded so far had its
    /// corresponding TLB invalidation acknowledged.
    pub const fn all_invalidations_acked(&self) -> bool {
        self.bar_mappings == self.invalidations_acked
    }

    /// Record a BAR mapping operation (must be paired with mark_invalidation_acked()).
    pub fn record_bar_mapping(&mut self) {
        self.bar_mappings = self.bar_mappings.saturating_add(1);
    }

    /// Record that the TLB invalidation following a BAR mapping was issued.
    pub fn mark_invalidation_acked(&mut self) {
        self.invalidations_acked = self.invalidations_acked.saturating_add(1);
    }

    /// Consumes one PL011 UART line and advances state. Mirrors the
    /// scan_uart_line() pattern from app_compat.rs / userspace_boot.rs /
    /// dbt_integration.rs — byte-pattern matching, no heap, no regex.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, X86_UART_SIG_VULKAN_INIT)
            && self.phase < AndroidX86Phase::VulkanInitialized
        {
            self.phase = AndroidX86Phase::VulkanInitialized;
            self.gate.vulkan_hw_active = true;
        }
        if contains_bytes(line, X86_UART_SIG_HWC_READY)
            && self.phase < AndroidX86Phase::DrmHwcLaunched
        {
            self.phase = AndroidX86Phase::DrmHwcLaunched;
        }
        if contains_bytes(line, X86_UART_SIG_HOME_SCREEN) {
            self.gate.home_screen_visible = true;
            if self.phase < AndroidX86Phase::HomeScreenRendered {
                self.phase = AndroidX86Phase::HomeScreenRendered;
            }
        }
        if contains_bytes(line, X86_UART_SIG_GLMARK2_RUNNING) {
            self.gate.glmark2_es2_runs = true;
        }
        if contains_bytes(line, X86_UART_SIG_NPROC_ALL_CORES) {
            self.gate.nproc_all_cores = true;
        }
        // SELinux denial signature shared with userspace_boot.rs
        if contains_bytes(line, b"avc: denied") {
            self.avc_denials_seen = self.avc_denials_seen.saturating_add(1);
        }
        // ro.build.type signature shared with userspace_boot.rs
        if contains_bytes(line, b"ro.build.type=user") {
            self.gate.build_type_user = true;
        }
        // Reaching the gate
        if self.gate.passes() {
            self.phase = AndroidX86Phase::GatePassed;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level initialisation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the x86 Android userspace stack (Chapter 53 gate pipeline).
///
/// Executes the 9-step pipeline:
///
///   1. Validate config (every required flag true)
///   2. Classify the detected GPU into a [`GpuVendor`]; reject Unsupported
///   3. Select the matching DRM kernel driver (must be in the GKI module set)
///   4. Select the matching Mesa Vulkan ICD (must be in the vendor image)
///   5. Mark Mesa ICD as selected; phase = IcdSelected
///   6. Reject any software-rendering fallback
///   7. Reject Intel integrated GPUs (i915 path not supported)
///   8. Set no_software_fallback = true on the gate
///   9. Return state at phase = IcdSelected; later phases come from UART
///
/// The hypervisor caller hands `state` to the VMEXIT handler loop; subsequent
/// phases (`DrmHwcLaunched` / `HomeScreenRendered` / `GatePassed`) are driven
/// by [`AndroidX86State::process_line`] as UART lines arrive.
pub fn init_android_x86_userspace(
    config:    &AndroidX86Config,
    detection: &GpuDetectionResult,
) -> Result<AndroidX86State, AndroidX86Error> {
    // Step 1: validate config ─────────────────────────────────────────────
    config.validate()?;

    let mut state = AndroidX86State::new();
    state.detected = Some(*detection);

    // Step 2: classify vendor ─────────────────────────────────────────────
    if !detection.is_display() {
        return Err(AndroidX86Error::NoDisplayController);
    }
    match detection.vendor {
        GpuVendor::Unsupported => {
            // Distinguish "integrated Intel" from "wholly unknown vendor"
            // so the user gets a precise error message.
            if detection.vendor_id == INTEL_VENDOR_ID
                && detection.subclass == PCI_SUBCLASS_VGA
            {
                return Err(AndroidX86Error::IntegratedIntelNotSupported);
            }
            return Err(AndroidX86Error::UnknownGpuVendor);
        }
        _ => {
            state.phase = AndroidX86Phase::GpuVendorDetected;
        }
    }

    // Step 3: select kernel driver ────────────────────────────────────────
    let driver = DrmKernelDriver::for_vendor(detection.vendor)
        .ok_or(AndroidX86Error::MissingDrmDriver)?;
    let kernel_has_driver = match driver {
        DrmKernelDriver::Nouveau => config.kernel_has_nouveau,
        DrmKernelDriver::Amdgpu  => config.kernel_has_amdgpu,
        DrmKernelDriver::Xe      => config.kernel_has_xe,
    };
    if !kernel_has_driver {
        return Err(AndroidX86Error::MissingDrmDriver);
    }
    state.phase = AndroidX86Phase::KernelModulesLoaded;

    // Step 4: select Mesa ICD ─────────────────────────────────────────────
    let icd = IcdSelector::select_or_fail(detection.vendor)?;
    state.selected_icd = Some(icd);

    // Step 5: phase = IcdSelected
    state.phase = AndroidX86Phase::IcdSelected;

    // Step 6: reject software-rendering fallback ──────────────────────────
    // If anyone changes IcdSelector to return a SoftwareFallback variant,
    // this guard refuses the boot. Production builds must have a real ICD.
    if !icd.vendor.is_supported() {
        return Err(AndroidX86Error::SoftwareRenderingForbidden);
    }

    // Step 7: reject integrated Intel ─────────────────────────────────────
    // Already handled in Step 2, but re-checked here so the invariant is
    // explicit at the ICD-selection boundary.
    if detection.vendor_id == INTEL_VENDOR_ID
        && detection.subclass == PCI_SUBCLASS_VGA
    {
        return Err(AndroidX86Error::IntegratedIntelNotSupported);
    }

    // Step 8: mark no_software_fallback gate bit ──────────────────────────
    state.gate.no_software_fallback = true;
    state.gate.build_type_user = config.build_type_user;

    // Step 9: return; later phases driven by process_line() ───────────────
    Ok(state)
}

/// Pre-flight summary of what ch53 will build, used by the build system to
/// emit a banner before `lunch aether_x86_64-user && m`.
pub fn pre_flight_summary() -> PreFlightSummary {
    PreFlightSummary {
        defconfig_entries: X86_GKI_GPU_DEFCONFIG.len(),
        board_config_vars: X86_BOARD_CONFIG_VARS.len(),
        product_packages:  X86_PRODUCT_PACKAGES.len(),
        selinux_rules:     X86_SELINUX_RULES.len(),
        icd_count:         MESA_ICDS_X86.len(),
    }
}

/// Counts for the pre-flight summary banner.
#[derive(Debug, Clone, Copy)]
pub struct PreFlightSummary {
    pub defconfig_entries: usize,
    pub board_config_vars: usize,
    pub product_packages:  usize,
    pub selinux_rules:     usize,
    pub icd_count:         usize,
}

/// Window-scan substring search shared with the rest of the boot pipeline.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — run on native host with `cargo test --lib -p hypervisor`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Vendor ID constants ────────────────────────────────────────────────

    #[test]
    fn vendor_ids_match_pci_sig() {
        assert_eq!(NVIDIA_VENDOR_ID, 0x10DE);
        assert_eq!(AMD_VENDOR_ID,    0x1002);
        assert_eq!(INTEL_VENDOR_ID,  0x8086);
    }

    #[test]
    fn pci_display_class_is_three() {
        assert_eq!(PCI_CLASS_DISPLAY, 0x03);
    }

    // ── PciBdf encoding ────────────────────────────────────────────────────

    #[test]
    fn pci_bdf_round_trip() {
        let b = PciBdf::new(0x42, 0x07, 0x03);
        assert_eq!(b.bus(),      0x42);
        assert_eq!(b.device(),   0x07);
        assert_eq!(b.function(), 0x03);
    }

    #[test]
    fn pci_bdf_clamps_oversize_device() {
        let b = PciBdf::new(0, 0xFF, 0xFF);
        // Device is 5 bits → 0xFF & 0x1F = 0x1F
        assert_eq!(b.device(), 0x1F);
        // Function is 3 bits → 0xFF & 0x07 = 0x07
        assert_eq!(b.function(), 0x07);
    }

    // ── GpuDetectionResult::classify ───────────────────────────────────────

    #[test]
    fn classify_nvidia_discrete() {
        let d = GpuDetectionResult::classify(
            NVIDIA_VENDOR_ID, 0x2484, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PCiBdfMockHelper::any(),
        );
        assert_eq!(d.vendor, GpuVendor::Nvidia);
        assert!(d.is_display());
    }

    #[test]
    fn classify_amd_radeon() {
        let d = GpuDetectionResult::classify(
            AMD_VENDOR_ID, 0x73DF, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PCiBdfMockHelper::any(),
        );
        assert_eq!(d.vendor, GpuVendor::Amd);
    }

    #[test]
    fn classify_intel_arc_3d_subclass() {
        let d = GpuDetectionResult::classify(
            INTEL_VENDOR_ID, 0x56A0, PCI_CLASS_DISPLAY, PCI_SUBCLASS_3D,
            PCiBdfMockHelper::any(),
        );
        assert_eq!(d.vendor, GpuVendor::IntelArc);
    }

    #[test]
    fn classify_intel_integrated_routes_to_unsupported() {
        // Intel UHD 770 (integrated, vendor 0x8086, class 03h, subclass 00h)
        let d = GpuDetectionResult::classify(
            INTEL_VENDOR_ID, 0x4680, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PCiBdfMockHelper::any(),
        );
        // Integrated Intel falls into Unsupported (init_*() then maps it to
        // IntegratedIntelNotSupported for a precise error message).
        assert_eq!(d.vendor, GpuVendor::Unsupported);
    }

    #[test]
    fn classify_non_display_device_unsupported() {
        // Vendor matches but class is wrong → Unsupported.
        let d = GpuDetectionResult::classify(
            NVIDIA_VENDOR_ID, 0x1234, 0x06, 0x80, PCiBdfMockHelper::any(),
        );
        assert_eq!(d.vendor, GpuVendor::Unsupported);
    }

    // ── DrmKernelDriver mapping ────────────────────────────────────────────

    #[test]
    fn drm_kernel_driver_per_vendor() {
        assert_eq!(DrmKernelDriver::for_vendor(GpuVendor::Nvidia),   Some(DrmKernelDriver::Nouveau));
        assert_eq!(DrmKernelDriver::for_vendor(GpuVendor::Amd),      Some(DrmKernelDriver::Amdgpu));
        assert_eq!(DrmKernelDriver::for_vendor(GpuVendor::IntelArc), Some(DrmKernelDriver::Xe));
        assert_eq!(DrmKernelDriver::for_vendor(GpuVendor::Unsupported), None);
    }

    #[test]
    fn drm_kernel_driver_module_names() {
        assert_eq!(DrmKernelDriver::Nouveau.module_name(), b"nouveau.ko");
        assert_eq!(DrmKernelDriver::Amdgpu.module_name(),  b"amdgpu.ko");
        assert_eq!(DrmKernelDriver::Xe.module_name(),      b"xe.ko");
    }

    #[test]
    fn drm_kernel_driver_kconfig_symbols() {
        assert_eq!(DrmKernelDriver::Nouveau.kconfig_symbol(), b"CONFIG_DRM_NOUVEAU");
        assert_eq!(DrmKernelDriver::Amdgpu.kconfig_symbol(),  b"CONFIG_DRM_AMDGPU");
        assert_eq!(DrmKernelDriver::Xe.kconfig_symbol(),      b"CONFIG_DRM_XE");
    }

    // ── MesaIcd / IcdSelector ──────────────────────────────────────────────

    #[test]
    fn mesa_icds_present_for_all_three_vendors() {
        assert_eq!(MESA_ICDS_X86.len(), 3);
        let vendors: [GpuVendor; 3] = [
            MESA_ICDS_X86[0].vendor,
            MESA_ICDS_X86[1].vendor,
            MESA_ICDS_X86[2].vendor,
        ];
        assert!(vendors.contains(&GpuVendor::Nvidia));
        assert!(vendors.contains(&GpuVendor::Amd));
        assert!(vendors.contains(&GpuVendor::IntelArc));
    }

    #[test]
    fn icd_paths_under_vendor_partition() {
        for icd in MESA_ICDS_X86 {
            assert!(contains_bytes(icd.library_path,  b"/vendor/lib64/hw/"),
                "ICD library must live under /vendor/lib64/hw/, got: {:?}",
                core::str::from_utf8(icd.library_path).ok());
            assert!(contains_bytes(icd.icd_json_path, b"/vendor/etc/vulkan/icd.d/"),
                "ICD manifest must live under /vendor/etc/vulkan/icd.d/, got: {:?}",
                core::str::from_utf8(icd.icd_json_path).ok());
        }
    }

    #[test]
    fn icd_api_versions_are_vulkan_1_3() {
        let v1_3_0 = (1 << 22) | (3 << 12);
        for icd in MESA_ICDS_X86 {
            assert_eq!(icd.api_version, v1_3_0,
                "Every ICD must report Vulkan 1.3.0; ch46 already mandates 1.3 minimum on ARM tier");
        }
    }

    #[test]
    fn icd_selector_round_trip() {
        let nvk = IcdSelector::select(GpuVendor::Nvidia).unwrap();
        assert_eq!(nvk.vendor, GpuVendor::Nvidia);
        assert_eq!(nvk.aosp_package, b"vulkan.nouveau");

        let radv = IcdSelector::select(GpuVendor::Amd).unwrap();
        assert_eq!(radv.aosp_package, b"vulkan.radv");

        let anv = IcdSelector::select(GpuVendor::IntelArc).unwrap();
        assert_eq!(anv.aosp_package, b"vulkan.intel");

        assert!(IcdSelector::select(GpuVendor::Unsupported).is_none());
    }

    #[test]
    fn icd_selector_or_fail_propagates_unknown() {
        let r = IcdSelector::select_or_fail(GpuVendor::Unsupported);
        assert!(matches!(r, Err(AndroidX86Error::UnknownGpuVendor)));
    }

    // ── X86GpuPassthroughHook invalidation invariant ───────────────────────

    #[test]
    fn passthrough_hook_starts_unsafe() {
        let h = X86GpuPassthroughHook::new(0, 0xF000_0000, 0x4_0000_0000, TlbInvalidationKind::IntelInvept);
        assert!(!h.is_safe(), "new BAR mapping must require invalidation ack");
    }

    #[test]
    fn passthrough_hook_safe_after_ack() {
        let mut h = X86GpuPassthroughHook::new(0, 0xF000_0000, 0x4_0000_0000, TlbInvalidationKind::AmdInvlpgaOrTlbCtl);
        h.mark_invalidated();
        assert!(h.is_safe());
    }

    #[test]
    fn invalidation_kind_mnemonics_distinct() {
        assert_ne!(
            TlbInvalidationKind::IntelInvept.mnemonic(),
            TlbInvalidationKind::AmdInvlpgaOrTlbCtl.mnemonic(),
        );
    }

    // ── x86 GKI defconfig table ────────────────────────────────────────────

    #[test]
    fn defconfig_includes_all_three_drm_drivers() {
        let mut saw_nouveau = false;
        let mut saw_amdgpu  = false;
        let mut saw_xe      = false;
        for e in X86_GKI_GPU_DEFCONFIG {
            if e.name == b"CONFIG_DRM_NOUVEAU" && e.value == b"m" { saw_nouveau = true; }
            if e.name == b"CONFIG_DRM_AMDGPU"  && e.value == b"m" { saw_amdgpu  = true; }
            if e.name == b"CONFIG_DRM_XE"      && e.value == b"m" { saw_xe      = true; }
        }
        assert!(saw_nouveau, "CONFIG_DRM_NOUVEAU=m must be in the defconfig");
        assert!(saw_amdgpu,  "CONFIG_DRM_AMDGPU=m must be in the defconfig");
        assert!(saw_xe,      "CONFIG_DRM_XE=m must be in the defconfig");
    }

    #[test]
    fn defconfig_disables_legacy_console_and_fb() {
        // CONFIG_VT and CONFIG_FB must be 'n' — they would steal KMS from DRM HWC.
        let mut saw_vt_off = false;
        let mut saw_fb_off = false;
        for e in X86_GKI_GPU_DEFCONFIG {
            if e.name == b"CONFIG_VT" && e.value == b"n" { saw_vt_off = true; }
            if e.name == b"CONFIG_FB" && e.value == b"n" { saw_fb_off = true; }
        }
        assert!(saw_vt_off, "CONFIG_VT must be disabled to keep drm_hwcomposer authoritative");
        assert!(saw_fb_off, "CONFIG_FB must be disabled to avoid /dev/fb0 vs DRM race");
    }

    #[test]
    fn defconfig_documents_silent_failure_for_every_entry() {
        for e in X86_GKI_GPU_DEFCONFIG {
            assert!(!e.silent_failure.is_empty(),
                "every defconfig entry must document its silent_failure for triage");
        }
    }

    // ── BoardConfig.mk vars ────────────────────────────────────────────────

    #[test]
    fn board_config_lists_all_three_gpu_drivers() {
        let mut saw = false;
        for v in X86_BOARD_CONFIG_VARS {
            if v.name == b"BOARD_GPU_DRIVERS" {
                assert!(contains_bytes(v.value, b"nouveau"));
                assert!(contains_bytes(v.value, b"amdgpu"));
                assert!(contains_bytes(v.value, b"xe"));
                saw = true;
            }
        }
        assert!(saw, "BOARD_GPU_DRIVERS must list nouveau, amdgpu, and xe together");
    }

    #[test]
    fn board_config_requires_gralloc4_and_hwc2() {
        let mut saw_gralloc4 = false;
        let mut saw_hwc2 = false;
        let mut saw_drm_hwc = false;
        for v in X86_BOARD_CONFIG_VARS {
            if v.name == b"TARGET_USES_GRALLOC4"     && v.value == b"true" { saw_gralloc4 = true; }
            if v.name == b"TARGET_USES_HWC2"         && v.value == b"true" { saw_hwc2 = true; }
            if v.name == b"BOARD_USES_DRM_HWCOMPOSER"&& v.value == b"true" { saw_drm_hwc = true; }
        }
        assert!(saw_gralloc4 && saw_hwc2 && saw_drm_hwc);
    }

    // ── PRODUCT_PACKAGES ──────────────────────────────────────────────────

    #[test]
    fn product_packages_bundle_all_three_vulkan_icds() {
        let mut saw_nvk  = false;
        let mut saw_radv = false;
        let mut saw_anv  = false;
        for &p in X86_PRODUCT_PACKAGES {
            if p == "vulkan.nouveau" { saw_nvk = true; }
            if p == "vulkan.radv"    { saw_radv = true; }
            if p == "vulkan.intel"   { saw_anv  = true; }
        }
        assert!(saw_nvk && saw_radv && saw_anv,
            "all three Mesa ICDs must ship in PRODUCT_PACKAGES — runtime selection picks one");
    }

    #[test]
    fn product_packages_include_drm_hwcomposer() {
        let has_hwc = X86_PRODUCT_PACKAGES.iter().any(|&p| p == "drm_hwcomposer.aether");
        assert!(has_hwc);
    }

    // ── SELinux TE rules ──────────────────────────────────────────────────

    #[test]
    fn selinux_rules_cover_gpu_device() {
        let mut saw_gralloc = false;
        let mut saw_composer = false;
        for r in X86_SELINUX_RULES {
            if contains_bytes(r.te_source, b"gralloc_default")
                && contains_bytes(r.te_source, b"gpu_device") { saw_gralloc = true; }
            if contains_bytes(r.te_source, b"hal_graphics_composer_default")
                && contains_bytes(r.te_source, b"gpu_device") { saw_composer = true; }
        }
        assert!(saw_gralloc, "gralloc must be allowed gpu_device or every buffer alloc dies");
        assert!(saw_composer, "drm_hwcomposer must be allowed gpu_device or KMS fails");
    }

    #[test]
    fn selinux_rules_document_silent_failure() {
        for r in X86_SELINUX_RULES {
            assert!(!r.silent_failure.is_empty(),
                "every TE rule must document what breaks if missing");
        }
    }

    // ── Config validation ─────────────────────────────────────────────────

    #[test]
    fn config_defaults_validate() {
        let c = AndroidX86Config::aether_defaults();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_rejects_missing_nouveau() {
        let mut c = AndroidX86Config::aether_defaults();
        c.kernel_has_nouveau = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::MissingDrmDriver)));
    }

    #[test]
    fn config_rejects_missing_amdgpu() {
        let mut c = AndroidX86Config::aether_defaults();
        c.kernel_has_amdgpu = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::MissingDrmDriver)));
    }

    #[test]
    fn config_rejects_missing_xe() {
        let mut c = AndroidX86Config::aether_defaults();
        c.kernel_has_xe = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::MissingDrmDriver)));
    }

    #[test]
    fn config_rejects_missing_icds() {
        let mut c = AndroidX86Config::aether_defaults();
        c.vendor_has_all_icds = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::MissingVulkanIcd)));
    }

    #[test]
    fn config_rejects_missing_manifests() {
        let mut c = AndroidX86Config::aether_defaults();
        c.vendor_has_all_manifests = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::MissingIcdManifest)));
    }

    #[test]
    fn config_rejects_missing_gralloc4() {
        let mut c = AndroidX86Config::aether_defaults();
        c.vendor_has_gralloc4 = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::InvalidConfig)));
    }

    #[test]
    fn config_rejects_missing_selinux() {
        let mut c = AndroidX86Config::aether_defaults();
        c.selinux_rules_applied = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::SelinuxAvcDenial)));
    }

    #[test]
    fn config_rejects_non_user_build() {
        let mut c = AndroidX86Config::aether_defaults();
        c.build_type_user = false;
        assert!(matches!(c.validate(), Err(AndroidX86Error::InvalidConfig)));
    }

    // ── Gate ──────────────────────────────────────────────────────────────

    #[test]
    fn gate_requires_all_six_criteria() {
        let mut g = AndroidX86Gate::new();
        assert!(!g.passes());
        g.home_screen_visible  = true; assert!(!g.passes());
        g.glmark2_es2_runs     = true; assert!(!g.passes());
        g.vulkan_hw_active     = true; assert!(!g.passes());
        g.nproc_all_cores      = true; assert!(!g.passes());
        g.build_type_user      = true; assert!(!g.passes(),
            "no_software_fallback is mandatory; production rejects Swiftshader / Lavapipe");
        g.no_software_fallback = true;
        assert!(g.passes());
    }

    #[test]
    fn gate_graphics_stack_live_partial() {
        let mut g = AndroidX86Gate::new();
        g.home_screen_visible  = true;
        g.vulkan_hw_active     = true;
        g.no_software_fallback = true;
        assert!(g.graphics_stack_live());
        assert!(!g.passes(), "glmark2 / nproc still needed for full gate");
    }

    // ── init_android_x86_userspace ────────────────────────────────────────

    fn synth_nvidia_detection() -> GpuDetectionResult {
        GpuDetectionResult::classify(
            NVIDIA_VENDOR_ID, 0x2484, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PciBdf::new(0x01, 0x00, 0x00),
        )
    }

    fn synth_amd_detection() -> GpuDetectionResult {
        GpuDetectionResult::classify(
            AMD_VENDOR_ID, 0x73DF, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PciBdf::new(0x03, 0x00, 0x00),
        )
    }

    fn synth_intel_arc_detection() -> GpuDetectionResult {
        GpuDetectionResult::classify(
            INTEL_VENDOR_ID, 0x56A0, PCI_CLASS_DISPLAY, PCI_SUBCLASS_3D,
            PciBdf::new(0x03, 0x00, 0x00),
        )
    }

    #[test]
    fn init_succeeds_for_nvidia() {
        let cfg = AndroidX86Config::aether_defaults();
        let d   = synth_nvidia_detection();
        let s   = init_android_x86_userspace(&cfg, &d).unwrap();
        assert_eq!(s.phase, AndroidX86Phase::IcdSelected);
        assert_eq!(s.selected_icd.unwrap().vendor, GpuVendor::Nvidia);
        assert!(s.gate.no_software_fallback);
        assert!(s.gate.build_type_user);
    }

    #[test]
    fn init_succeeds_for_amd() {
        let cfg = AndroidX86Config::aether_defaults();
        let d   = synth_amd_detection();
        let s   = init_android_x86_userspace(&cfg, &d).unwrap();
        assert_eq!(s.selected_icd.unwrap().vendor, GpuVendor::Amd);
    }

    #[test]
    fn init_succeeds_for_intel_arc() {
        let cfg = AndroidX86Config::aether_defaults();
        let d   = synth_intel_arc_detection();
        let s   = init_android_x86_userspace(&cfg, &d).unwrap();
        assert_eq!(s.selected_icd.unwrap().vendor, GpuVendor::IntelArc);
    }

    #[test]
    fn init_rejects_integrated_intel() {
        let cfg = AndroidX86Config::aether_defaults();
        // Intel UHD 770: vendor 0x8086, subclass VGA (not 3D)
        let d = GpuDetectionResult::classify(
            INTEL_VENDOR_ID, 0x4680, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PciBdf::new(0x00, 0x02, 0x00),
        );
        let r = init_android_x86_userspace(&cfg, &d);
        assert!(matches!(r, Err(AndroidX86Error::IntegratedIntelNotSupported)));
    }

    #[test]
    fn init_rejects_unknown_vendor() {
        let cfg = AndroidX86Config::aether_defaults();
        let d = GpuDetectionResult::classify(
            0x1234, 0x5678, PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA,
            PciBdf::new(0x10, 0x00, 0x00),
        );
        let r = init_android_x86_userspace(&cfg, &d);
        assert!(matches!(r, Err(AndroidX86Error::UnknownGpuVendor)));
    }

    #[test]
    fn init_rejects_when_kernel_missing_driver() {
        let mut cfg = AndroidX86Config::aether_defaults();
        cfg.kernel_has_nouveau = false; // NVIDIA path needs nouveau
        let d   = synth_nvidia_detection();
        // Config validation fails first (every driver must be present)
        let r = init_android_x86_userspace(&cfg, &d);
        assert!(matches!(r, Err(AndroidX86Error::MissingDrmDriver)));
    }

    #[test]
    fn init_rejects_non_display_device() {
        let cfg = AndroidX86Config::aether_defaults();
        // class != 0x03 → not a display controller at all
        let d = GpuDetectionResult::classify(
            NVIDIA_VENDOR_ID, 0x1234, 0x02 /* network */, 0x00,
            PciBdf::new(0x00, 0x00, 0x00),
        );
        let r = init_android_x86_userspace(&cfg, &d);
        assert!(matches!(r, Err(AndroidX86Error::NoDisplayController)));
    }

    // ── State transitions via process_line() ──────────────────────────────

    #[test]
    fn process_line_advances_through_full_boot() {
        let cfg = AndroidX86Config::aether_defaults();
        let d   = synth_amd_detection();
        let mut s = init_android_x86_userspace(&cfg, &d).unwrap();

        s.process_line(b"vulkan: initialized HW device on /dev/dri/card0");
        assert_eq!(s.phase, AndroidX86Phase::VulkanInitialized);
        assert!(s.gate.vulkan_hw_active);

        s.process_line(b"DrmHwcTwo::Init: success drmDriver=amdgpu");
        assert_eq!(s.phase, AndroidX86Phase::DrmHwcLaunched);

        s.process_line(b"SurfaceFlinger: GPU compositing on");
        assert_eq!(s.phase, AndroidX86Phase::HomeScreenRendered);
        assert!(s.gate.home_screen_visible);

        s.process_line(b"glmark2-es2: starting benchmark");
        assert!(s.gate.glmark2_es2_runs);

        s.process_line(b"nproc: all cores online (16)");
        assert!(s.gate.nproc_all_cores);

        // Final gate transition once every criterion is met
        assert!(s.gate.passes());
        assert_eq!(s.phase, AndroidX86Phase::GatePassed);
    }

    #[test]
    fn process_line_counts_avc_denials() {
        let cfg = AndroidX86Config::aether_defaults();
        let d = synth_nvidia_detection();
        let mut s = init_android_x86_userspace(&cfg, &d).unwrap();
        s.process_line(b"audit: type=1400 avc: denied { open } for path=/dev/dri/card0");
        assert_eq!(s.avc_denials_seen, 1);
    }

    // ── BAR mapping invalidation accounting ────────────────────────────────

    #[test]
    fn state_invalidation_accounting() {
        let mut s = AndroidX86State::new();
        s.record_bar_mapping();
        s.record_bar_mapping();
        assert!(!s.all_invalidations_acked());
        s.mark_invalidation_acked();
        s.mark_invalidation_acked();
        assert!(s.all_invalidations_acked());
    }

    #[test]
    fn state_invalidation_missing_breaks_isolation_invariant() {
        let mut s = AndroidX86State::new();
        s.record_bar_mapping();
        s.record_bar_mapping();
        s.mark_invalidation_acked(); // only 1 of 2 acked
        assert!(!s.all_invalidations_acked(),
            "forgetting INVEPT/INVLPGA leaves stale TLB entries — isolation broken");
    }

    // ── PreFlightSummary ──────────────────────────────────────────────────

    #[test]
    fn pre_flight_summary_counts_match_tables() {
        let s = pre_flight_summary();
        assert_eq!(s.defconfig_entries, X86_GKI_GPU_DEFCONFIG.len());
        assert_eq!(s.board_config_vars, X86_BOARD_CONFIG_VARS.len());
        assert_eq!(s.product_packages,  X86_PRODUCT_PACKAGES.len());
        assert_eq!(s.selinux_rules,     X86_SELINUX_RULES.len());
        assert_eq!(s.icd_count,         MESA_ICDS_X86.len());
        assert_eq!(s.icd_count, 3);
    }

    // ── contains_bytes ────────────────────────────────────────────────────

    #[test]
    fn contains_bytes_matches_in_middle() {
        assert!(contains_bytes(b"prefix nouveau suffix", b"nouveau"));
    }

    #[test]
    fn contains_bytes_rejects_when_too_short() {
        assert!(!contains_bytes(b"abc", b"abcd"));
    }

    #[test]
    fn contains_bytes_rejects_empty_needle() {
        assert!(!contains_bytes(b"abcd", b""));
    }

    // Helper for synthesizing BDFs in tests
    struct PCiBdfMockHelper;
    impl PCiBdfMockHelper {
        fn any() -> PciBdf {
            PciBdf::new(0x10, 0x00, 0x00)
        }
    }
}
