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
/// RELOCATION: guest DRAM moved to the 4 GiB window [4 GiB, 8 GiB)
/// (aether_translator::runtime::mmu::GUEST_PA_BASE/SIZE) — raw, hole-free
/// `-m 16G` high-RAM, so the runtime hole-probe is SKIPPED and the FULL window
/// is advertised. Sized at 4 GiB total so the kernel sees the design-target RAM
/// (zygote / system_server / graphics need ≥1-2 GiB to reach SurfaceFlinger;
/// the old ~562 MiB cap — `Memory: 573440K` — could not).
pub const KERNEL_WORKING_RAM_SIZE: u64 = 4 * 1024 * 1024 * 1024
    - STAGED_BOOT_IMG_SIZE
    - GUEST_DTB_SIZE;

/// Total contiguous host PA span the host-CR3 identity map must cover for the
/// Android handoff: boot.img window + DTB region + kernel working RAM = 4 GiB,
/// exactly the relocated [4 GiB, 8 GiB) window. Mapped by four 1-GiB host-CR3
/// identity leaves (boot_x86::host_pt_map_identity_1g). MUST equal
/// `aether_translator::runtime::mmu::GUEST_PA_SIZE`.
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
/// Base PA of the PMEM `/vendor` region — placed CONTIGUOUS right after the
/// system image so a single WIN2 span (`PMEM_SYSTEM_SIZE + PMEM_VENDOR_SIZE`)
/// covers both. Exposed as a second `pmem-region` DT node → /dev/pmem1 →
/// /vendor, so second-stage init can read /vendor/etc/selinux (the SELinux
/// policy compile that FATAL-rebooted when /vendor was absent).
pub const PMEM_VENDOR_PA: u64 = PMEM_SYSTEM_PA + PMEM_SYSTEM_SIZE; // 0x3_C000_0000
/// Size of the PMEM `/vendor` region (1 GiB == `qemu/images/vendor.raw`).
pub const PMEM_VENDOR_SIZE: u64 = 0x4000_0000;

/// Boot via the generic-ramdisk flow (advertise the boot.img ramdisk as initrd)
/// rather than system-as-root. The ramdisk carries `/init` + a patched
/// `/fstab.aether` (mount `/system` directly off `/dev/block/pmem0`, no A/B /
/// super / AVB), so first-stage init reads the fstab from the ramdisk root —
/// available BEFORE the switch_root pivot, unlike the DT fstab which becomes
/// unreachable post-chroot when `/sys` detaches. The switch_root getmntent
/// empty-mnt_dir bug is handled by the MOVE_FAKE root-skip in exceptions.rs.
/// Set true to fall back to the old `root=/dev/pmem0` system-as-root path.
pub const BOOT_SYSTEM_AS_ROOT: bool = false;

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
        // memory_base MUST match the host-CR3 identity-map base — the relocated
        // 4 GiB guest-DRAM window. prepare_android_handoff_at overrides this with
        // the live `stage_pa` (also GUEST_PA_BASE), so the default and the
        // runtime value agree. Old QEMU-virt default (0x4000_0000) would leave
        // the kernel accessing unmapped guest physical addresses on every load.
        memory_base: aether_translator::runtime::mmu::GUEST_PA_BASE,
        // memory_size MUST equal what the host CR3 actually covers (4 GiB).
        // Anything the kernel tries beyond this range faults the host.
        memory_size: HANDOFF_REGION_SIZE,
        gicd_base: 0x0800_0000,
        gicd_size: 0x10000,
        gicr_base: 0x080A_0000,
        gicr_size: 0x20000,
        uart_base: 0x0900_0000,
        uart_irq_spi: 33,
        // x86 tier: PL011 is emulated (mmio_emu); keep the minimal node.
        uart_clock_hz: 0,
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
        // Second PMEM region: the /vendor image → /dev/pmem1 (SELinux policy).
        pmem_base2: PMEM_VENDOR_PA,
        pmem_size2: PMEM_VENDOR_SIZE,
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
    // `root=/dev/pmem0 rootwait rw`: the post-pivot root — once the boot.img
    // initrd ramdisk (advertised when BOOT_SYSTEM_AS_ROOT==false, see below) runs
    // its first-stage `/init` and switch_root's onto `/system`, `root=` names the
    // PMEM device that backs it. `rw` (not `ro`) so first-stage mount can fix up
    // the rootfs. `androidboot.force_normal_boot=1`: skip recovery and do a normal
    // boot even though there is no boot/recovery ramdisk distinction. `rootwait`
    // blocks until of_pmem has created /dev/pmem0. (See BOOT_SYSTEM_AS_ROOT.)
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
    // `init=/system/bin/init`: the post-ramdisk init target. With the boot.img
    // initrd present the kernel runs the ramdisk `/init` first (first-stage mount +
    // switch_root); `init=` is the command kernel_init uses for the real init once
    // root is the PMEM `/system` — pointing it straight at /system/bin/init avoids
    // kernel_init's default fallthrough /sbin/init → /etc/init (a DIRECTORY on AOSP
    // → execve EACCES -13) → /bin/init, so Android's real init runs with no
    // ambiguity and no -13 noise. (If BOOT_SYSTEM_AS_ROOT is flipped true the
    // ramdisk is not advertised and this becomes the sole, first-stage init.)
    // NOTE: `initcall_debug ignore_loglevel` is KEPT. It is nominally a kernel-boot
    // diagnostic, but removing it under WHPX re-exposes a TIMING-SENSITIVE init
    // stall: with the firehose gone the kernel boots with a different printk/IRQ
    // cadence and init blocks in-kernel after a handful of syscalls (the
    // [stall] detector fires, [pcr] PCs all in 0xffffffc008…). With the firehose
    // present, init runs healthily (validated: 760+ syscalls climbing, demand-
    // paging). The extra PL011 serial does cost COM1 VMEXITs under WHPX, but the
    // boot is still ~100× faster than TCG and init STABILITY wins over the marginal
    // kernel-boot speedup. (Proper fix = make IRQ/timer delivery timing-robust;
    // tracked separately.) Re-removing this WILL re-introduce the init stall.
    // `devtmpfs.mount=1`: force the kernel to auto-mount devtmpfs on /dev at boot
    // (CONFIG_DEVTMPFS=y is in the defconfig). Our init reaches second-stage but
    // creates ZERO device nodes (no mknodat) — so it relies on devtmpfs to
    // populate /dev, and without the auto-mount /dev/null is absent, making every
    // forked service's bionic stdio-to-/dev/null setup fail (ENOENT) → exit(1) →
    // "Attempted to kill init" panic. Auto-mounting devtmpfs provides /dev/null
    // (and the other core nodes) before init runs.
    // `transparent_hugepage=never`: DIAGNOSTIC — disable THP / khugepaged so it
    // never collapses init's freshly-faulted anon page. Tests the livelock theory
    // for the change_protection(set PTE) ↔ move_page_tables(ptep_get_and_clear)
    // loop on 0x7fba854000: if init clears the loop, khugepaged collapse was the
    // cause; if it persists, the tear-down comes from elsewhere.
    // androidboot.android_dt_dir: redirect first-stage init's DT-fstab lookup
    // from the legacy /proc/device-tree symlink (which this kernel does not
    // create — every /proc/device-tree/... open returns ENOENT) to the live
    // OF sysfs tree at /sys/firmware/devicetree/base, which CONFIG_OF_KOBJ=y
    // populates. libfstab reads <dir>/compatible + <dir>/fstab from here.
    //
    // ┌─────────────────────────────────────────────────────────────────────────┐
    // │ BRING-UP-ONLY: androidboot.selinux=permissive                           │
    // ├─────────────────────────────────────────────────────────────────────────┤
    // │ The flat-PMEM boot exposes /system off /dev/block/pmem0 and /vendor off  │
    // │ /dev/block/pmem1. The of_pmem block devices are UNLABELED (no genfscon / │
    // │ device-label rule covers them yet), and several HAL service domains lack │
    // │ contexts in this hand-rolled flat layout. Under `enforcing` that         │
    // │ produces a live `avc: denied` storm that SILENTLY kills vold (block-dev  │
    // │ access denied), gralloc, and SurfaceFlinger during bring-up — the boot   │
    // │ never reaches the display gate even though every binary is present.      │
    // │ `permissive` LOGS the denials but lets the processes run, so we can      │
    // │ drive the boot to SurfaceFlinger and collect the exact denial set.       │
    // │                                                                          │
    // │ PRODUCTION MUST RE-ENABLE ENFORCING. The ro.build.type=user invariant    │
    // │ (Hardware Authenticity, CLAUDE.md) REQUIRES SELinux enforcing. Restoring │
    // │ it requires, BEFORE flipping this back to `enforcing`:                   │
    // │   1. genfscon / device labels for the pmem block devices (pmem0/pmem1)   │
    // │      so vold/fs_mgr may open them (e.g. `block_device` u:object_r:…).    │
    // │   2. The 5 AETHER_SEPOLICY_FIXES (userspace_boot::AETHER_SEPOLICY_FIXES) │
    // │      — gralloc dma-buf, sensors iio, AETHER hwbinder, vold nvme, ueventd │
    // │      dev-node TE rules.                                                  │
    // │ ro.build.type is LEFT =user (set in the image, not the cmdline) — this   │
    // │ relaxation does NOT touch it; it is the SELinux mode only.               │
    // └─────────────────────────────────────────────────────────────────────────┘
    let cmd = b"earlycon=pl011,mmio32,0x9000000 console=ttyAMA0,115200 \
                root=/dev/pmem0 rootwait rw androidboot.force_normal_boot=1 \
                init=/system/bin/init devtmpfs.mount=1 transparent_hugepage=never \
                androidboot.hardware=aether androidboot.selinux=permissive \
                androidboot.android_dt_dir=/sys/firmware/devicetree/base/firmware/android \
                androidboot.verifiedbootstate=green androidboot.slot_suffix=_a \
                androidboot.dynamic_partitions=false \
                initcall_debug ignore_loglevel initcall_blacklist=init_kprobe_trace \
                printk.devkmsg=on";
    // printk.devkmsg=on: lift the default /dev/kmsg write rate limit (10 lines /
    // 5 s) so the vendor `aether_logcat_kmsg` service can mirror logcat warnings
    // and errors into the kernel log, i.e. onto the serial console. Userspace
    // daemons (netd, SurfaceFlinger, zygote, system_server) log only to logcat,
    // so without this their failure reasons never reach com1.log.
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
    // ── Display Gap 1: simple-framebuffer ────────────────────────────────────
    // Carve a framebuffer from the TOP of the EPT/NPT-mapped guest RAM (boot.img,
    // kernel, ramdisk and DTB all sit near the bottom, so the top is free) and
    // register its geometry (from the host GOP FB) so build_android_dtb emits the
    // reserved-memory + "simple-framebuffer" nodes → the kernel's simpledrm binds
    // and creates /dev/dri/card0. The hypervisor copies guest-FB → real GOP FB each
    // vblank (boot_x86 dispatch loop). x86-only: `boot_x86` is not built for ARM64.
    #[cfg(target_arch = "x86_64")]
    if let Some(hfb) = crate::boot_x86::host_framebuffer() {
        if hfb.base != 0 && hfb.width != 0 && hfb.height != 0 {
            let stride = (hfb.pitch_px as u64).saturating_mul(4); // 32bpp
            let raw = stride.saturating_mul(hfb.height as u64);
            let fb_size = (raw + 0x1F_FFFF) & !0x1F_FFFFu64; // round up 2 MiB
            if fb_size > 0 && fb_size < region_size_out / 2 {
                let fb_base = (stage_pa + region_size_out - fb_size) & !0x1F_FFFFu64;
                crate::kernel::set_dtb_framebuffer(crate::kernel::DtbFramebuffer {
                    base: fb_base,
                    size: fb_size,
                    width: hfb.width,
                    height: hfb.height,
                    stride: stride as u32,
                    bgr: hfb.bgr_format,
                });
            }
        }
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
        // RELOCATED: the 4 GiB window is mapped by FOUR 1-GiB host-CR3 identity
        // leaves (host_pt_map_identity_1g), not a single 1-GiB PDPT entry, so the
        // old ≤1 GiB ceiling no longer applies. It MUST exactly equal the
        // translator's GUEST_PA_SIZE (the walker's confinement window) = 4 GiB.
        assert_eq!(HANDOFF_REGION_SIZE, 4 * 1024 * 1024 * 1024);
        assert_eq!(HANDOFF_REGION_SIZE, aether_translator::runtime::mmu::GUEST_PA_SIZE);
        // 1-GiB aligned so it tiles into whole 1-GiB host-CR3 leaves.
        assert_eq!(HANDOFF_REGION_SIZE & ((1 << 30) - 1), 0);
    }

    #[test]
    fn dtb_memory_matches_mapped_region() {
        // The DTB MUST advertise exactly the region we EPT/NPT-identity-map,
        // otherwise the kernel hits unmapped GPAs on early allocations.
        let cfg = default_dtb_config();
        assert_eq!(cfg.memory_base, aether_translator::runtime::mmu::GUEST_PA_BASE);
        assert_eq!(cfg.memory_size, HANDOFF_REGION_SIZE);
        // Relocated window must exactly fill [GUEST_PA_BASE, +GUEST_PA_SIZE).
        assert_eq!(cfg.memory_size, aether_translator::runtime::mmu::GUEST_PA_SIZE);
        assert_eq!(cfg.memory_base, 0x1_0000_0000);
        assert_eq!(cfg.memory_size, 0x1_0000_0000);
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
