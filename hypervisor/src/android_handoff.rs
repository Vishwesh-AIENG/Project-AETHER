// android_handoff.rs — x86-tier Android boot.img handoff preparation.
//
// Phase 4 deliverable. Glues:
//
//   * `android_boot::scan_for_boot_image` (Phase 3 / Ch19+) — finds the ARM64
//     GKI Image inside a staged Android boot.img.
//   * `kernel::build_android_dtb` — emits the Linux FDT the kernel reads at
//     boot.
//   * `DbtInitialRegs` — ARM64 register file the FEX dispatcher (Phase 5)
//     consults when it picks up translation at the kernel entry.
//
// QEMU staging contract:
//   The launcher loads `boot.img` at `STAGED_BOOT_IMG_PA` via
//   `-device loader,file=boot.img,addr=0x80000000,force-raw=on`. UEFI's
//   identity map keeps those bytes accessible to the hypervisor; we don't
//   need an extra UEFI AllocatePages call.
//
// On production hardware the same constants apply; the AETHER bootloader
// `BootImageHeader::parse` pipeline reads `boot_a` off NVMe into the same
// physical address before invoking the hypervisor. Phase 6 wires that path.
//
// Read-only — populates a `DbtInitialRegs` value and an `AndroidHandoff`
// summary. Does no MMIO, no Stage 2 / EPT / NPT manipulation; that lives
// in the platform-specific paging code.

#![allow(dead_code)]

use crate::android_boot::{scan_for_boot_image, AndroidBootError, AndroidBootLayout};
use crate::kernel::{build_android_dtb, AndroidDtbConfig, KernelError,
                    MAX_ANDROID_CPUS, MAX_KERNEL_CMDLINE_LEN};

// ─────────────────────────────────────────────────────────────────────────────
// Memory map constants for the x86 Android handoff
// ─────────────────────────────────────────────────────────────────────────────

/// Physical address where QEMU's `-device loader,file=boot.img,addr=…` stages
/// the Android boot image, and where the AETHER bootloader copies `boot_a`
/// from NVMe in production.
///
/// 0x8000_0000 = 2 GiB. Safely above the hypervisor's BSS in OVMF builds and
/// outside any normal UEFI-claimed range.
pub const STAGED_BOOT_IMG_PA: u64 = 0x8000_0000;

/// Maximum size of the staged boot.img. AOSP `BOOT_BYTES` is 64 MiB; we map
/// the same window for EPT/NPT identity coverage.
pub const STAGED_BOOT_IMG_SIZE: u64 = 64 * 1024 * 1024;

/// Physical address where the hypervisor writes the guest DTB blob.
/// Placed 16 MiB above the boot.img window so the EPT/NPT 2-MiB map can
/// cover both with a single contiguous range.
pub const GUEST_DTB_PA: u64 = STAGED_BOOT_IMG_PA + STAGED_BOOT_IMG_SIZE;

/// Maximum bytes the DTB blob may occupy. `build_android_dtb` typically
/// emits ~4 KiB; we reserve a full 2 MiB so the EPT/NPT identity-map can
/// cover the DTB with a single 2-MiB PDE leaf entry (Intel SDM Vol. 3C
/// Table 28-2 / AMD APM Vol 2 §15.25.7).
pub const GUEST_DTB_SIZE: u64 = 2 * 1024 * 1024;

/// Kernel working RAM extending past boot.img + DTB. Linux init, page
/// allocations, ramdisk extraction, and early userspace all live here.
/// The total mapped guest RAM (HANDOFF_REGION_SIZE) is what the DTB
/// `/memory` node advertises to the kernel. 1 GiB is the minimum that
/// reaches Android home screen without OOM (Zygote + system_server alone
/// reserve ~600 MiB).
pub const KERNEL_WORKING_RAM_SIZE: u64 = 1024 * 1024 * 1024
    - STAGED_BOOT_IMG_SIZE
    - GUEST_DTB_SIZE;

/// Total contiguous host PA span the EPT/NPT identity map must cover for
/// the Android handoff: boot.img window + DTB region + kernel working RAM.
/// Fits in a single 1-GiB PDPT entry (512 × 2-MiB PDE leaves = 1 GiB),
/// which is also the upper bound for `build_ept_2mib_range` (one PD table).
pub const HANDOFF_REGION_SIZE: u64 =
    STAGED_BOOT_IMG_SIZE + GUEST_DTB_SIZE + KERNEL_WORKING_RAM_SIZE;

// ─────────────────────────────────────────────────────────────────────────────
// DbtInitialRegs — ARM64 GPR file at kernel entry
// ─────────────────────────────────────────────────────────────────────────────

/// ARM64 boot-protocol register state at kernel entry.
///
/// Per `linux/Documentation/arm64/booting.rst` §4:
///   * `x0` = physical address of FDT blob
///   * `x1`, `x2`, `x3` = 0   (reserved for future use; kernel checks)
///   * All other GPRs = 0
///   * PC = kernel entry (KERNEL_LOAD_PA + text_offset)
///   * SP = unspecified (kernel sets up its own stack)
///
/// Phase 5's FEX dispatcher reads this struct to seed the ARM64 register
/// file before translating the first basic block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct DbtInitialRegs {
    pub x:  [u64; 31],   // x0..x30
    pub sp: u64,
    pub pc: u64,
}

impl DbtInitialRegs {
    pub const fn zero() -> Self {
        Self { x: [0; 31], sp: 0, pc: 0 }
    }

    /// Construct the ARM64 GPR file required by `linux/Documentation/arm64/
    /// booting.rst`. `kernel_pc` is the kernel entry PA; `dtb_pa` is the
    /// FDT blob PA.
    pub const fn for_kernel_entry(kernel_pc: u64, dtb_pa: u64) -> Self {
        let mut r = Self::zero();
        r.x[0] = dtb_pa;
        // x1..x3 stay zero by virtue of `zero()`.
        r.pc = kernel_pc;
        r
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidHandoff — full summary the boot path needs from this module
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the x86 boot path needs to know to launch Android via FEX.
#[derive(Debug, Clone, Copy)]
pub struct AndroidHandoff {
    /// Layout of the boot.img discovered at `STAGED_BOOT_IMG_PA`.
    pub layout:     AndroidBootLayout,
    /// PA of the DTB blob the kernel reads via x0.
    pub dtb_pa:     u64,
    /// Length of the DTB blob actually written.
    pub dtb_len:    usize,
    /// ARM64 GPR file Phase 5 hands to FEX before dispatching.
    pub dbt_regs:   DbtInitialRegs,
    /// PA of the kernel entry (== `layout.kernel_pa` for text_offset=0 GKI).
    pub kernel_pc:  u64,
    /// Base + size of the contiguous host PA range the EPT/NPT must map.
    pub region_pa:   u64,
    pub region_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// No `ANDROID!` magic in the staged region — boot.img not loaded.
    BootImgNotFound,
    /// boot.img header parse failed.
    InvalidHeader,
    /// Kernel image declared a size larger than the staged window.
    KernelOutOfRange,
    /// DTB emission failed.
    DtbBuild(KernelError),
    /// DTB emission produced more bytes than `GUEST_DTB_SIZE`.
    DtbTooLarge,
}

impl From<AndroidBootError> for HandoffError {
    fn from(e: AndroidBootError) -> Self {
        match e {
            AndroidBootError::NotFound         => Self::BootImgNotFound,
            AndroidBootError::InvalidHeader    => Self::InvalidHeader,
            AndroidBootError::KernelOutOfRange => Self::KernelOutOfRange,
            AndroidBootError::RegionTooSmall   => Self::KernelOutOfRange,
        }
    }
}

impl From<KernelError> for HandoffError {
    fn from(e: KernelError) -> Self { Self::DtbBuild(e) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Android DTB config used at Phase-4 handoff time
// ─────────────────────────────────────────────────────────────────────────────

/// Build the default `AndroidDtbConfig` for an x86 Android partition.
///
/// Values mirror QEMU virt-machine numbers (re-used because FEX translates
/// to the same ABI an ARM Android image expects). Phase 6 personalises this
/// per real-hardware tier.
pub fn default_dtb_config() -> AndroidDtbConfig {
    let mut cfg = AndroidDtbConfig {
        cpu_count: 1,
        cpu_mpidr: [0u64; MAX_ANDROID_CPUS],
        // memory_base MUST match STAGED_BOOT_IMG_PA — that is where the EPT/NPT
        // identity-map starts. Old QEMU-virt default (0x4000_0000) would leave
        // the kernel accessing unmapped guest physical addresses on every load.
        memory_base: STAGED_BOOT_IMG_PA,
        // memory_size MUST equal what the EPT/NPT actually covers. Anything
        // the kernel tries beyond this range produces an EPT/NPT violation.
        memory_size: HANDOFF_REGION_SIZE,
        gicd_base: 0x0800_0000,
        gicd_size: 0x10000,
        gicr_base: 0x080A_0000,
        gicr_size: 0x20000,
        uart_base: 0x0900_0000,
        uart_irq_spi: 33,
        cmdline:    [0u8; MAX_KERNEL_CMDLINE_LEN],
        cmdline_len: 0,
    };
    // Default kernel cmdline — same string AETHER's BoardConfig.mk emits.
    let cmd = b"earlyprintk console=ttyAMA0,115200 androidboot.hardware=aether \
                androidboot.selinux=enforcing androidboot.verifiedbootstate=green";
    let n = if cmd.len() < MAX_KERNEL_CMDLINE_LEN { cmd.len() } else { MAX_KERNEL_CMDLINE_LEN };
    cfg.cmdline[..n].copy_from_slice(&cmd[..n]);
    cfg.cmdline_len = n;
    cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// prepare_android_handoff — top-level entry
// ─────────────────────────────────────────────────────────────────────────────

/// Discover the staged boot.img, build the DTB, and synthesise the ARM64
/// register file FEX will read at dispatch.
///
/// # Safety
/// * `STAGED_BOOT_IMG_PA..STAGED_BOOT_IMG_PA+STAGED_BOOT_IMG_SIZE` and
///   `GUEST_DTB_PA..GUEST_DTB_PA+GUEST_DTB_SIZE` must be mapped readable +
///   writable in the host page tables (UEFI identity map satisfies this on
///   OVMF; production hardware satisfies it because the hypervisor owns
///   the early CR3 directly).
/// * Concurrent calls are forbidden — this writes the DTB blob in place.
pub unsafe fn prepare_android_handoff() -> Result<AndroidHandoff, HandoffError> {
    // SAFETY: caller guarantees mapping; we cast the PA window to a `&[u8]`.
    let region: &[u8] = unsafe {
        core::slice::from_raw_parts(
            STAGED_BOOT_IMG_PA as *const u8,
            STAGED_BOOT_IMG_SIZE as usize,
        )
    };

    let layout = scan_for_boot_image(region, STAGED_BOOT_IMG_PA)?;

    // Emit the DTB into the dedicated guest region.
    let dtb_cfg = default_dtb_config();
    let dtb_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            GUEST_DTB_PA as *mut u8,
            GUEST_DTB_SIZE as usize,
        )
    };
    let dtb_len = build_android_dtb(&dtb_cfg, dtb_buf)?;
    if dtb_len as u64 > GUEST_DTB_SIZE {
        return Err(HandoffError::DtbTooLarge);
    }

    let dbt_regs = DbtInitialRegs::for_kernel_entry(layout.kernel_pa, GUEST_DTB_PA);

    Ok(AndroidHandoff {
        layout,
        dtb_pa:  GUEST_DTB_PA,
        dtb_len,
        dbt_regs,
        kernel_pc: layout.kernel_pa,
        region_pa:   STAGED_BOOT_IMG_PA,
        region_size: HANDOFF_REGION_SIZE,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_2mib_aligned() {
        // 2-MiB alignment lets the EPT/NPT identity-map use PDE leaf entries.
        assert_eq!(STAGED_BOOT_IMG_PA & 0x1F_FFFF, 0);
        assert_eq!(GUEST_DTB_PA       & 0x1F_FFFF, 0);
        assert_eq!(STAGED_BOOT_IMG_SIZE & 0x1F_FFFF, 0);
        assert_eq!(GUEST_DTB_SIZE       & 0x1F_FFFF, 0);
    }

    #[test]
    fn handoff_region_is_contiguous() {
        // DTB sits immediately above the boot.img window.
        assert_eq!(GUEST_DTB_PA, STAGED_BOOT_IMG_PA + STAGED_BOOT_IMG_SIZE);
        // HANDOFF_REGION_SIZE = boot.img + DTB + kernel working RAM.
        assert_eq!(
            HANDOFF_REGION_SIZE,
            STAGED_BOOT_IMG_SIZE + GUEST_DTB_SIZE + KERNEL_WORKING_RAM_SIZE
        );
        // Must fit in a single 1 GiB PDPT entry (the EPT/NPT 2-MiB-leaf
        // helper assumes one PD table covering ≤ 1 GiB).
        assert!(HANDOFF_REGION_SIZE <= 1024 * 1024 * 1024);
        // 2-MiB aligned for PDE leaves.
        assert_eq!(HANDOFF_REGION_SIZE & 0x1F_FFFF, 0);
    }

    #[test]
    fn dtb_memory_matches_mapped_region() {
        // The DTB MUST advertise exactly the region we EPT/NPT-identity-map,
        // otherwise the kernel hits unmapped GPAs on early allocations.
        let cfg = default_dtb_config();
        assert_eq!(cfg.memory_base, STAGED_BOOT_IMG_PA);
        assert_eq!(cfg.memory_size, HANDOFF_REGION_SIZE);
    }

    #[test]
    fn fex_initial_regs_match_arm64_boot_protocol() {
        let r = DbtInitialRegs::for_kernel_entry(0x4080_0000, 0x4400_0000);
        assert_eq!(r.x[0], 0x4400_0000);          // x0 = DTB PA
        assert_eq!(r.x[1], 0);                    // x1 = 0
        assert_eq!(r.x[2], 0);                    // x2 = 0
        assert_eq!(r.x[3], 0);                    // x3 = 0
        for i in 4..31 { assert_eq!(r.x[i], 0); }  // x4..x30 = 0
        assert_eq!(r.sp, 0);
        assert_eq!(r.pc, 0x4080_0000);
    }

    #[test]
    fn handoff_error_conversion_covers_all_android_errors() {
        let mapping = [
            (AndroidBootError::NotFound,         HandoffError::BootImgNotFound),
            (AndroidBootError::InvalidHeader,    HandoffError::InvalidHeader),
            (AndroidBootError::KernelOutOfRange, HandoffError::KernelOutOfRange),
            (AndroidBootError::RegionTooSmall,   HandoffError::KernelOutOfRange),
        ];
        for (input, expected) in mapping {
            assert_eq!(HandoffError::from(input), expected);
        }
    }

    #[test]
    fn default_dtb_config_validates() {
        // Should round-trip through the existing kernel.rs validator.
        let cfg = default_dtb_config();
        assert!(cfg.validate().is_ok());
        assert!(cfg.cmdline_len > 10);
    }

    #[test]
    fn default_dtb_config_builds() {
        let cfg = default_dtb_config();
        let mut out = [0u8; 8192];
        let n = build_android_dtb(&cfg, &mut out).expect("DTB build");
        assert!(n > 0);
        assert!(n < out.len());
        // FDT magic at offset 0.
        assert_eq!(&out[..4], &[0xD0, 0x0D, 0xFE, 0xED]);
    }

    #[test]
    fn default_dtb_fits_in_guest_dtb_size() {
        let cfg = default_dtb_config();
        let mut buf = vec![0u8; GUEST_DTB_SIZE as usize];
        let n = build_android_dtb(&cfg, &mut buf).expect("DTB build");
        assert!((n as u64) < GUEST_DTB_SIZE,
                "DTB {} bytes exceeded GUEST_DTB_SIZE {}", n, GUEST_DTB_SIZE);
    }
}
