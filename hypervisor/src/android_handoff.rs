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
/// `/memory` node advertises to the kernel.
///
/// Phase-F: keep this at 1 GiB to maximise what the kernel can see; the
/// runtime probe (`probe_handoff_writable_extent` in boot_x86.rs)
/// truncates DOWN to the actually-writable extent reported by UEFI.
/// With the full HANDOFF_REGION_SIZE UEFI allocation (Phase-F change in
/// boot_x86.rs) the writable extent IS the full 1 GiB, but kernel
/// behaviour shifts: a much larger code surface gets translated which
/// triggers more JIT bump arena pressure AND surfaces a register-spill
/// UD2 in paging_init's map_mem path (block at 0xffffffc008041834,
/// inside create_kpti_ng_temp_pgd). Phase F+G need this lower_int
/// spill fix to land first; until then a smaller advertised range
/// (256 MiB) avoids the over-pressured block while we wait.
pub const KERNEL_WORKING_RAM_SIZE: u64 = 1024 * 1024 * 1024
    - STAGED_BOOT_IMG_SIZE
    - GUEST_DTB_SIZE;

/// Total contiguous host PA span the EPT/NPT identity map must cover for
/// the Android handoff: boot.img window + DTB region + kernel working RAM.
/// Fits in a single 1-GiB PDPT entry (512 × 2-MiB PDE leaves = 1 GiB),
/// which is also the upper bound for `build_ept_2mib_range` (one PD table).
pub const HANDOFF_REGION_SIZE: u64 =
    STAGED_BOOT_IMG_SIZE + GUEST_DTB_SIZE + KERNEL_WORKING_RAM_SIZE;

// ── Phase 3 PIVOT: PMEM-backed AOSP system image (x86 tier) ──────────────────
//
// The GKI kernel has no virtio-blk driver but has CONFIG_OF_PMEM=y, so the AOSP
// `system.raw` image is staged into a FIXED high-RAM region by QEMU's generic
// loader (`-device loader,file=system.raw,addr=PMEM_SYSTEM_PA`) and exposed to
// the guest as a `compatible="pmem-region"` DT node → /dev/pmem0 → /system.
//
// PA chosen at 12 GiB: above the low-4-GiB hypervisor heap/staging/PCI-hole AND
// clear of the translator JIT cache + bump arena (which occupy PDPT slot 8 at
// 0x2_0000_0000). PML4[0]'s existing PDPT has free 1-GiB slots [12..15] so the
// host CR3 maps the region with three 1-GiB leaf entries (no new page-table page
// needed). With QEMU -m 16G the high-RAM band is [4 GiB, ~17.25 GiB), so
// [12 GiB, 15 GiB) is backed. Mirrored in `qemu/run-x86-auto.py` (loader addr)
// — keep the two in sync.
/// Base PA of the PMEM `/system` region (12 GiB).
pub const PMEM_SYSTEM_PA: u64 = 0x3_0000_0000;
/// Size of the PMEM `/system` region (3 GiB == `qemu/images/system.raw`).
pub const PMEM_SYSTEM_SIZE: u64 = 0xC000_0000;

/// Boot the AOSP `system.raw` directly as root (`root=/dev/pmem0`) instead of
/// running the boot.img ramdisk's first-stage init. The image is a system-as-root
/// layout (`/init` -> `/system/bin/init`), so this bypasses the ramdisk
/// switch_root that fails in the DBT. See `prepare_android_handoff`.
pub const BOOT_SYSTEM_AS_ROOT: bool = true;

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
    /// `true` if the boot.img kernel was gzip-compressed and inflated into a
    /// dedicated region (so `kernel_pc` is the decompressed entry, not the
    /// in-place compressed payload).
    pub kernel_decompressed: bool,
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
    /// Kernel payload is gzip-compressed but inflation failed (corrupt stream,
    /// or it decompresses to more than the destination region holds).
    KernelDecompressFailed,
    /// Kernel payload uses a compression format AETHER does not implement
    /// (e.g. lz4 / xz). Only raw `Image` and gzip `Image.gz` are supported.
    KernelCompressionUnsupported,
    /// No room above the DTB in the mapped region for the decompressed kernel.
    KernelDecompressNoRoom,
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
        // Default: no initrd. prepare_android_handoff_at populates these from
        // the boot.img scan's ramdisk_pa/ramdisk_size when a ramdisk exists.
        initrd_start: 0,
        initrd_end:   0,
        // Phase 3 PIVOT: expose the QEMU-loader-staged system.raw as a PMEM
        // block device (/dev/pmem0) — the kernel has no virtio-blk driver.
        pmem_base: PMEM_SYSTEM_PA,
        pmem_size: PMEM_SYSTEM_SIZE,
    };
    // Default kernel cmdline — same string AETHER's BoardConfig.mk emits.
    // `earlycon=pl011,mmio32,0x9000000` enables Linux's earlycon PL011 driver
    // BEFORE the regular console init — without it, kernel printk accumulates
    // in a buffer until the late console driver loads (after IRQ/timer init),
    // so any pre-IRQ panic prints nothing to PL011/COM1 and looks silent.
    // Pairs with mmio_emu::PL011_UART_BASE = 0x0900_0000 → pl011_emit → dual_puts.
    // `androidboot.slot_suffix=_a` gives fs_mgr a slot context: this AOSP build
    // is A/B (the ramdisk fstab.aether marks system/vendor/product `slotselect`),
    // so first-stage init's `fs_mgr_update_for_slotselect` aborts with "Error
    // updating for slotselect" if no suffix is available — even though our DT
    // fstab uses direct, non-slotselect `/dev/block/vda` (which therefore keeps
    // its name; the suffix only appends to entries that actually set slotselect).
    // `root=/dev/pmem0 rootwait ro`: boot the system.raw PMEM device as root
    // (system-as-root). `androidboot.force_normal_boot=1`: skip recovery and do a
    // normal boot even though there is no boot/recovery ramdisk distinction.
    // `rootwait` blocks until of_pmem has created /dev/pmem0. (See BOOT_SYSTEM_AS_ROOT.)
    // `initcall_debug ignore_loglevel`: DIAGNOSTIC — print every initcall as it
    // runs ("calling X+0x0/0x0 @ 1" before, "initcall X returned … after N usecs"
    // after). The last `calling …` with no matching `returned` names the hanging
    // initcall. `ignore_loglevel` forces the KERN_DEBUG initcall lines to the
    // console (default loglevel filters them). Remove once the hang is found.
    // `initcall_blacklist=init_kprobe_trace`: the kprobe-tracing initcall HANGS
    // under the DBT — it blocks on a wait (RCU grace period / kprobe instruction
    // patching sync) that never completes (hot PCs are all idle/scheduler/RCU).
    // Kprobe/ftrace tracing is a debug feature not needed for boot or production,
    // so blacklist it. (Multiple names comma-separated if more tracing initcalls
    // hang.) initcall_blacklist is parsed by init/main.c, always available.
    // `init=/system/bin/init`: with system-as-root and NO initramfs, the kernel
    // never sets ramdisk_execute_command (=/init), so kernel_init falls through its
    // default list /sbin/init → /etc/init → /bin/init → /bin/sh. On an AOSP image
    // /etc → /system/etc and /etc/init is a DIRECTORY → execve EACCES (-13); only
    // /bin/init (→/system/bin/init) eventually runs. Pointing `init=` straight at
    // /system/bin/init runs Android's real init immediately and skips the two
    // failed candidate execs (no ambiguity, no -13 noise).
    let cmd = b"earlycon=pl011,mmio32,0x9000000 console=ttyAMA0,115200 \
                root=/dev/pmem0 rootwait ro androidboot.force_normal_boot=1 \
                init=/system/bin/init \
                androidboot.hardware=aether androidboot.selinux=enforcing \
                androidboot.verifiedbootstate=green androidboot.slot_suffix=_a \
                initcall_debug ignore_loglevel initcall_blacklist=init_kprobe_trace";
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
    unsafe {
        prepare_android_handoff_at(
            STAGED_BOOT_IMG_PA,
            STAGED_BOOT_IMG_SIZE,
            GUEST_DTB_PA,
            GUEST_DTB_SIZE,
            HANDOFF_REGION_SIZE,
        )
    }
}

/// Same as `prepare_android_handoff` but accepts caller-supplied PAs for the
/// staged boot.img window and the DTB destination. Used when the UEFI ESP
/// reader allocated the staging buffer at runtime (audit §2a fix) so the
/// scan looks at the actual UEFI-allocated PA instead of the legacy
/// hardcoded `0x8000_0000` constant. The fallback path still calls the
/// constants-based form above for backward compatibility.
///
/// # Safety
/// Same contract as [`prepare_android_handoff`]; in addition, both
/// `(stage_pa, stage_size)` and `(dtb_pa, dtb_size)` must point at host RAM
/// the hypervisor exclusively owns.
pub unsafe fn prepare_android_handoff_at(
    stage_pa:        u64,
    stage_size:      u64,
    dtb_pa:          u64,
    dtb_size:        u64,
    region_size_out: u64,
) -> Result<AndroidHandoff, HandoffError> {
    // SAFETY: caller guarantees mapping; we cast the PA window to a `&[u8]`.
    let region: &[u8] = unsafe {
        core::slice::from_raw_parts(stage_pa as *const u8, stage_size as usize)
    };

    let mut layout = scan_for_boot_image(region, stage_pa)?;

    // Emit the DTB into the dedicated guest region. Re-target memory_base /
    // memory_size at the caller-supplied region so the guest DTB matches
    // what the NPT actually maps.
    let mut dtb_cfg = default_dtb_config();
    dtb_cfg.memory_base = stage_pa;
    dtb_cfg.memory_size = region_size_out;
    // A.3: wire the boot.img-staged ramdisk into /chosen so the kernel's
    // populate_rootfs() finds and unpacks the cpio. layout.ramdisk_pa points
    // INSIDE the boot.img window (header_pa + 4 KiB + page_round_up(kernel_size)),
    // which is part of [stage_pa, stage_pa+region_size_out) — the same span the
    // EPT/NPT identity-maps and the DTB advertises as /memory — so the kernel
    // sees these PAs as plain conventional RAM and can read the ramdisk in
    // place (no copy needed). When the kernel was gzip-decompressed above the
    // DTB, layout.kernel_pa moves but ramdisk_pa stays in the boot.img window;
    // we deliberately do NOT re-derive ramdisk position from the new kernel_pa.
    // BOOT_SYSTEM_AS_ROOT: the staged AOSP system.raw is a system-as-root image
    // (root has /init -> /system/bin/init, /system/, and the standard mount-point
    // dirs). Booting it directly as root via `root=/dev/pmem0` (cmdline) skips the
    // boot.img ramdisk's first-stage init + switch_root entirely — switch_root was
    // failing in the DBT (getmntent returned an empty mnt_dir -> mount("",..)=EINVAL
    // -> init exit 127 -> panic). When this is true we do NOT advertise the initrd,
    // so the kernel mounts root= instead of running the ramdisk's /init.
    if !BOOT_SYSTEM_AS_ROOT && layout.ramdisk_size > 0 {
        dtb_cfg.initrd_start = layout.ramdisk_pa;
        dtb_cfg.initrd_end   = layout.ramdisk_pa + layout.ramdisk_size as u64;
    }
    let dtb_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(dtb_pa as *mut u8, dtb_size as usize)
    };
    let dtb_len = build_android_dtb(&dtb_cfg, dtb_buf)?;
    if dtb_len as u64 > dtb_size {
        return Err(HandoffError::DtbTooLarge);
    }

    // ── Decompress the kernel if it is gzip-compressed ────────────────────
    //
    // The discovered kernel runs IN PLACE inside the boot.img window
    // (`kernel_pa == header_pa + 4096`). Android boot.img kernels are almost
    // always gzip-compressed (`Image.gz` / `Image.gz-dtb`); the DBT dispatcher
    // fetches the entry as raw bytes, so a compressed payload makes the very
    // first translated block lift the gzip magic `1f 8b 08 00` instead of ARM64
    // code (observed on the first real-hardware boot: TranslateFail at
    // pc == kernel_pa == 0xac401000, word == 0x00088b1f, kind=lift).
    //
    // AETHER is the bootloader (No-Boundary, Ch. 3) and arm64 has no
    // self-extracting kernel, so we inflate here into a dedicated 2-MiB-aligned
    // destination immediately above the DTB. The destination lives inside the
    // EPT/NPT-mapped handoff region (which the design already treats as
    // guest-owned conventional RAM — the guest writes there during boot), is
    // disjoint from the compressed source in the boot.img window, and is what
    // the dispatch loop's MMU window + identity reader cover. We then repoint
    // `kernel_pa` (and the DbtInitialRegs PC) at the decompressed entry.
    let kernel_off = (layout.kernel_pa - stage_pa) as usize;
    let kernel_size = layout.kernel_size as usize;
    if kernel_off + kernel_size > region.len() {
        return Err(HandoffError::KernelOutOfRange);
    }
    let kernel_src = &region[kernel_off..kernel_off + kernel_size];

    let kernel_decompressed = if crate::inflate::is_gzip(kernel_src) {
        // 2-MiB-aligned destination just above the DTB region.
        let dest_pa = (dtb_pa + dtb_size + 0x1F_FFFF) & !0x1F_FFFF;
        let region_end = stage_pa + region_size_out;
        if dest_pa >= region_end {
            return Err(HandoffError::KernelDecompressNoRoom);
        }
        let dest_cap = (region_end - dest_pa) as usize;
        // SAFETY: the caller guarantees [stage_pa, stage_pa+region_size_out) is
        // hypervisor-owned, host-identity-mapped RAM. `dest_pa..region_end` is a
        // subrange of it that is disjoint from the boot.img window holding
        // `kernel_src` (dest_pa >= dtb_pa+dtb_size, and the boot.img window ends
        // at stage_pa+STAGED_BOOT_IMG_SIZE <= dtb_pa).
        let dest: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(dest_pa as *mut u8, dest_cap)
        };
        let n = crate::inflate::gunzip(kernel_src, dest)
            .map_err(|_| HandoffError::KernelDecompressFailed)?;
        // Repoint the entry at the decompressed image. Leave ramdisk_pa
        // pointing at the original in-place ramdisk in the boot.img window.
        layout.kernel_pa = dest_pa;
        layout.kernel_size = n as u32;
        true
    } else if is_unsupported_kernel_compression(kernel_src) {
        return Err(HandoffError::KernelCompressionUnsupported);
    } else {
        // Uncompressed `Image`. The arm64 boot protocol REQUIRES a 2-MiB-aligned
        // load address (Documentation/arm64/booting.rst §"Call the kernel image").
        // Running in place at `header_pa + 4096` (only 4-KiB-aligned) makes the
        // kernel's self-relocated VA base 0x1000 off a 16-KiB (THREAD_SIZE)
        // boundary, so every thread stack lands non-THREAD_SIZE-aligned. The
        // VMAP_STACK overflow detector (`tbnz sp, #THREAD_SHIFT`) then falsely
        // trips on the FIRST exception taken on such a stack (e.g. the first timer
        // IRQ) → handle_bad_stack → "kernel stack overflow" panic. Copy the image
        // to the same 2-MiB-aligned destination the gzip path uses.
        let dest_pa = (dtb_pa + dtb_size + 0x1F_FFFF) & !0x1F_FFFF;
        let region_end = stage_pa + region_size_out;
        if dest_pa >= region_end {
            return Err(HandoffError::KernelDecompressNoRoom);
        }
        let dest_cap = (region_end - dest_pa) as usize;
        if kernel_size > dest_cap {
            return Err(HandoffError::KernelDecompressNoRoom);
        }
        // SAFETY: identical to the gzip branch — `dest_pa..region_end` is
        // hypervisor-owned, host-identity-mapped RAM, disjoint from the boot.img
        // window holding `kernel_src` (dest_pa >= dtb_pa+dtb_size; the boot.img
        // window ends at stage_pa+STAGED_BOOT_IMG_SIZE <= dtb_pa).
        let dest: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(dest_pa as *mut u8, dest_cap)
        };
        dest[..kernel_size].copy_from_slice(kernel_src);
        layout.kernel_pa = dest_pa;
        false
    };

    let dbt_regs = DbtInitialRegs::for_kernel_entry(layout.kernel_pa, dtb_pa);

    Ok(AndroidHandoff {
        layout,
        dtb_pa,
        dtb_len,
        dbt_regs,
        kernel_pc: layout.kernel_pa,
        region_pa:   stage_pa,
        region_size: region_size_out,
        kernel_decompressed,
    })
}

/// Detect compressed-kernel formats AETHER does NOT implement, so the boot
/// path can fail-loud with a clear diagnostic instead of feeding the bytes to
/// the DBT (which would TranslateFail on the compression magic).
fn is_unsupported_kernel_compression(k: &[u8]) -> bool {
    if k.len() < 4 {
        return false;
    }
    let h = [k[0], k[1], k[2], k[3]];
    const LZ4_FRAME: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];
    const LZ4_LEGACY: [u8; 4] = [0x02, 0x21, 0x4C, 0x18];
    const XZ: [u8; 4] = [0xFD, b'7', b'z', b'X']; // \xFD 7 z X (Z)
    const LZMA_ALONE: [u8; 3] = [0x5D, 0x00, 0x00];
    const ZSTD: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
    h == LZ4_FRAME
        || h == LZ4_LEGACY
        || h == XZ
        || h == ZSTD
        || k[..3] == LZMA_ALONE
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
    fn dump_dtb_for_inspection() {
        let cfg = default_dtb_config();
        let mut out = vec![0u8; 8192];
        let n = build_android_dtb(&cfg, &mut out).expect("DTB build");
        std::fs::write("D:/AETHER/qemu/test.dtb", &out[..n]).unwrap();
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
