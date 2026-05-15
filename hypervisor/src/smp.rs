// ch35: Multi-Core SMP
//
// Brings secondary CPU cores into AETHER's EL2 control and provides the
// spin table mechanism for forwarding PSCI CPU_ON requests to guest EL1
// entry points.
//
// Two-level wake protocol:
//   Level 1 — AETHER → QEMU:  psci_cpu_on_hvc() wakes a physical core into
//              aether_secondary_entry at EL2, where it initialises per-PE
//              registers (VBAR, VTCR, VTTBR, HCR, GIC ICC) and parks in the
//              spin table WFE loop.
//   Level 2 — Guest → AETHER: When Android's kernel issues PSCI CPU_ON via
//              HVC, AETHER's exception handler calls wake_secondary_core(),
//              which writes the guest entry point into the spin table and
//              issues SEV. The parked secondary core wakes, reads the entry
//              point, and ERets to EL1 with ARM64 boot protocol registers set.
//
// Memory ordering protocol (ARM ARM B2.3 — weak memory model):
//   Primary:   context_id.store(Release) → entry_point.store(Release) → DSB ISH → SEV
//   Secondary: entry_point.load(Acquire) — if non-zero, context_id.load(Acquire)
//   The Release/Acquire pair on entry_point makes context_id visible before
//   the secondary acts on the non-zero entry_point.
//
// References:
//   ARM ARM DDI0487 Section D1.8 (SMP and the Snoop Control Unit)
//   PSCI specification DEN0022 Section 5.4 (CPU_ON)
//   ARM ARM DDI0487 Section B2.3 (memory model, WFE/SEV)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of secondary (non-boot) cores supported.
/// Sized for QEMU ch35 (3 secondaries) with headroom to MAX_CORES - 1.
pub const MAX_SECONDARY_CORES: usize = 7;

/// EL2 stack size per secondary core.
/// 16 KiB is sufficient for the EL2 initialisation path (no deep recursion).
pub const SECONDARY_STACK_SIZE: usize = 16 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Spin table — one slot per secondary core
//
// Primary writes entry_point != 0 to release the secondary from its WFE park.
// entry_point = 0 means parked. entry_point != 0 is the guest EL1 entry IPA.
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the spin table — corresponds to one secondary core.
#[repr(C, align(16))]
pub struct SpinEntry {
    /// Guest EL1 entry IPA. 0 = parked. Written with Release ordering.
    pub entry_point: AtomicU64,
    /// ARM64 boot protocol x0 value (context_id). Written with Release ordering.
    pub context_id: AtomicU64,
}

impl SpinEntry {
    const fn new() -> Self {
        Self {
            entry_point: AtomicU64::new(0),
            context_id: AtomicU64::new(0),
        }
    }
}

static SPIN_TABLE: [SpinEntry; MAX_SECONDARY_CORES] =
    [const { SpinEntry::new() }; MAX_SECONDARY_CORES];

// ─────────────────────────────────────────────────────────────────────────────
// Per-secondary EL2 stacks
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C, align(16))]
struct SecondaryStack([u8; SECONDARY_STACK_SIZE]);

// SAFETY: bare-metal, no OS, each core writes only its own slot.
static mut SECONDARY_STACKS: [SecondaryStack; MAX_SECONDARY_CORES] =
    [const { SecondaryStack([0u8; SECONDARY_STACK_SIZE]) }; MAX_SECONDARY_CORES];

// ─────────────────────────────────────────────────────────────────────────────
// Shared globals — written by primary before waking any secondary
// ─────────────────────────────────────────────────────────────────────────────

/// Stage 2 root table PA. All cores program the same VTTBR_EL2.
static S2_ROOT_PA: AtomicU64 = AtomicU64::new(0);

/// GICv3 redistributor region base PA.
/// Secondary core N computes its own GICR frame as: GICR_BASE + N * 0x20000.
static GICR_BASE_PA: AtomicU64 = AtomicU64::new(0);

/// Set the Stage 2 root PA that all secondary cores will program into VTTBR_EL2.
///
/// Must be called (with a non-zero value) before `psci_cpu_on_hvc` is issued
/// for any secondary core.
pub fn set_s2_root_pa(pa: u64) {
    S2_ROOT_PA.store(pa, Ordering::Release);
}

/// Set the GICv3 redistributor base PA.
///
/// Must be called before `psci_cpu_on_hvc` is issued for any secondary core.
pub fn set_gicr_base(pa: u64) {
    GICR_BASE_PA.store(pa, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────────────
// Level-2 wake: Android PSCI CPU_ON → EL1 guest entry
// ─────────────────────────────────────────────────────────────────────────────

/// Write the guest EL1 entry point into the spin table for `target_affinity`
/// and issue SEV to wake the parked secondary core.
///
/// Called from `handle_psci_call` in cpu.rs after `partition.cpu_on()` returns
/// `psci::SUCCESS`. The secondary core must already be parked in the WFE loop
/// inside `aether_secondary_core_main`.
///
/// # Arguments
/// - `target_affinity`: PSCI target affinity (matches MPIDR.Aff0 for QEMU virt).
/// - `entry_point`: Guest EL1 entry IPA to write into ELR_EL2 on the secondary.
/// - `context_id`: ARM64 boot protocol x0 value at EL1 entry.
pub fn wake_secondary_core(target_affinity: u64, entry_point: u64, context_id: u64) {
    // QEMU virt assigns Aff0 = core index (0 = primary, 1..N = secondaries).
    let aff0 = (target_affinity & 0xFF) as usize;
    if aff0 == 0 || aff0 > MAX_SECONDARY_CORES {
        return;
    }
    let entry = &SPIN_TABLE[aff0 - 1];
    // Write context_id before entry_point: the secondary uses entry_point as
    // the gate signal; context_id must be visible before that gate opens.
    entry.context_id.store(context_id, Ordering::Release);
    entry.entry_point.store(entry_point, Ordering::Release);
    // DSB ISH ensures the stores are globally visible before SEV.
    // SEV wakes all WFE-suspended PEs on the inner-shareable domain.
    unsafe {
        asm!(
            "dsb ish",
            "sev",
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Level-1 wake: AETHER → QEMU PSCI CPU_ON (bring secondary core to EL2)
// ─────────────────────────────────────────────────────────────────────────────

/// Issue a PSCI CPU_ON_64 HVC to physically start a secondary core in QEMU.
///
/// QEMU's virt machine model intercepts PSCI-encoded HVCs at TCG emulation
/// level, before the ARM64 exception routing logic fires. This is the same
/// mechanism OVMF uses to start secondary CPUs from EL2. AETHER at EL2 can
/// therefore issue PSCI HVCs and have QEMU bring the secondary to `entry_pa`
/// in AArch64 EL2 mode — without requiring EL3 (ATF).
///
/// # Safety
/// - `entry_pa` must be the address of `aether_secondary_entry` (or another
///   valid EL2 entry point with a valid stack setup).
/// - Must not be called for a core that is already executing.
/// - Must be called from the primary core's EL2 context during boot.
pub unsafe fn psci_cpu_on_hvc(target_mpidr: u64, entry_pa: u64, ctx: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!(
            "hvc #0",
            inout("x0") crate::cpu::psci::CPU_ON_64 as u64 => result,
            in("x1") target_mpidr,
            in("x2") entry_pa,
            in("x3") ctx,
            options(nomem, nostack),
        );
    }
    result
}

/// Physical address of the `aether_secondary_entry` assembly trampoline.
///
/// Pass this as `entry_pa` to `psci_cpu_on_hvc`. QEMU jumps here on the
/// secondary core in AArch64 EL2 mode.
pub fn secondary_entry_pa() -> u64 {
    unsafe extern "C" {
        fn aether_secondary_entry();
    }
    aether_secondary_entry as *const () as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// Secondary core Rust main — called from aether_secondary_entry assembly
// ─────────────────────────────────────────────────────────────────────────────

/// Secondary core initialisation and EL1 spin loop.
///
/// Called by `aether_secondary_entry` with x0 = raw MPIDR_EL1 value.
///
/// Sequence:
///   1. install_vectors()         — VBAR_EL2 (banked per-PE)
///   2. configure_el2_virt(s2)    — CPTR/VTCR/VTTBR/HCR/ICH_HCR (banked per-PE)
///   3. init_icc()                — ICC_SRE/PMR/IGRPEN1 (banked per-PE;
///                                  GIC redistributor already woken by primary)
///   4. partition.set_running()   — update CorePartition state
///   5. WFE spin loop             — wait for wake_secondary_core() SEV
///   6. ERET to EL1h              — guest entry with ARM64 boot protocol regs
///
/// # Safety
/// Called exactly once per secondary core from the assembly trampoline.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aether_secondary_core_main(mpidr_raw: u64) -> ! {
    let mpidr = crate::cpu::Mpidr(mpidr_raw);
    let aff0 = mpidr.aff0() as usize;

    // 1. Install exception vectors. VBAR_EL2 is banked per-PE.
    unsafe { crate::arm64::vectors::install_vectors() };

    // 2. Configure EL2 virtualization extensions.
    //    CPTR_EL2, VTCR_EL2, VTTBR_EL2, HCR_EL2, ICH_HCR_EL2 are all banked.
    //    All cores use the same Stage 2 root PA (shared page tables).
    let s2_root = S2_ROOT_PA.load(Ordering::Acquire);
    unsafe { crate::arm64::virt::configure_el2_virt(s2_root) };

    // 3. Enable GIC CPU interface on this core.
    //    The primary already woke all redistributors in init_physical_gic(N).
    //    Each secondary just needs to enable its own ICC registers.
    unsafe { crate::gic::init_icc() };

    // 4. Mark this core as Running in the partition table.
    //    Primary pre-registered all cores in Off state; this transitions to Running.
    let partition = unsafe { crate::cpu::aether_partition_mut() };
    partition.set_running(mpidr);

    // 5. Compute spin table index (Aff0=1 → index 0, Aff0=2 → index 1, …).
    if aff0 == 0 || aff0 > MAX_SECONDARY_CORES {
        // Out-of-range Aff0 — park permanently.
        loop {
            unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)); }
        }
    }
    let spin_idx = aff0 - 1;
    let entry = &SPIN_TABLE[spin_idx];

    // 6. WFE spin loop — release to EL1 when entry_point is set.
    loop {
        let ep = entry.entry_point.load(Ordering::Acquire);
        if ep != 0 {
            let ctx = entry.context_id.load(Ordering::Acquire);
            // SPSR_EL2 = 0x3C5:
            //   M[4:0] = 0b00101 = EL1h (EL1 with SP_EL1)
            //   DAIF   = 1111    (all interrupts masked at EL1 entry)
            //
            // ARM64 boot protocol (Documentation/arm64/booting.rst):
            //   x0 = context_id (device tree / secondary boot data)
            //   x1 = x2 = x3 = 0 (Linux checks these are zero)
            unsafe {
                asm!(
                    "msr elr_el2,  {elr}",
                    "msr spsr_el2, {spsr}",
                    "isb",
                    "eret",
                    elr  = in(reg) ep,
                    spsr = in(reg) 0x3C5u64,
                    in("x0") ctx,
                    in("x1") 0u64,
                    in("x2") 0u64,
                    in("x3") 0u64,
                    options(noreturn, nomem, nostack),
                );
            }
        }
        unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Assembly trampoline — QEMU delivers secondary cores here at EL2
//
// Establishes a valid SP before entering Rust. Stack is selected by Aff0:
//   core N (Aff0=N) → SECONDARY_STACKS[N-1], SP = top of that stack.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "uefi")]
core::arch::global_asm!(
    ".global aether_secondary_entry",
    ".section .text.aether_secondary_entry, \"ax\"",
    "aether_secondary_entry:",
    // Read MPIDR_EL1 — save full value for aether_secondary_core_main argument.
    "    mrs  x0, mpidr_el1",
    // Extract Aff0 (core index within cluster) from bits [7:0].
    "    and  x1, x0, #0xFF",
    // Stack array index = Aff0 - 1 (primary core, Aff0=0, never reaches here).
    "    sub  x2, x1, #1",
    // x3 = base address of SECONDARY_STACKS array.
    "    adr  x3, {stacks}",
    // x4 = size of one stack slot.
    "    mov  x4, {stack_size}",
    // x3 = &SECONDARY_STACKS[Aff0-1] = base + (Aff0-1) * SECONDARY_STACK_SIZE.
    "    madd x3, x2, x4, x3",
    // SP = top of this core's stack (ARM64 stacks grow downward).
    "    add  sp, x3, x4",
    // x0 already holds raw MPIDR_EL1 — first argument to aether_secondary_core_main.
    "    bl   aether_secondary_core_main",
    // aether_secondary_core_main is diverging (!); park here if it ever returns.
    "0:  wfe",
    "    b    0b",
    stacks     = sym SECONDARY_STACKS,
    stack_size = const SECONDARY_STACK_SIZE,
);
