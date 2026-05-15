// ch09: CPU Partitioning
//
// AETHER assigns each physical CPU core to exactly one guest partition at boot.
// Once assigned, a core runs that guest's code exclusively for the lifetime of
// the session. There is no scheduling, no time-multiplexing, no context-switching
// between guests on a single core — the core is the guest's.
//
// This module provides three mechanisms:
//
//   1. CorePartition — the static table mapping physical MPIDR values to guests.
//      Populated during secondary-core bring-up as each core reads its own
//      MPIDR_EL1 and registers itself. The first ANDROID_CORE_COUNT discovered
//      cores are assigned to Android; the remainder to Windows.
//
//   2. PSCI emulation — intercepts CPU_ON, CPU_OFF, CPU_SUSPEND, and auxiliary
//      calls made by a guest via HVC. The critical security invariant is that
//      CPU_ON requests are only honoured for target cores that belong to the
//      calling guest. Requests targeting the other guest's cores return
//      PSCI_DENIED. Reference: PSCI spec DEN0022 Section 5.
//
//   3. GIC affinity routing helpers — GICD_IROUTER expects MPIDR affinity
//      values, not simple linear core indices. The helpers here build the
//      correct 64-bit value for routing a device interrupt to a specific core
//      identified by its MPIDR. Reference: GIC spec IHI0069 Section 4.8.
//
// Primary references:
//   ARM ARM DDI0487 Section D1.8 (multiprocessing)
//   ARM ARM DDI0487 Section D7.2.74 (MPIDR_EL1 register description)
//   PSCI spec DEN0022 (Power State Coordination Interface)
//   GIC Architecture Specification IHI0069 Section 4.8 (GICD_IROUTER)
//   linux-ref/arch/arm64/kvm/psci.c (KVM PSCI reference implementation)
//   linux-ref/arch/arm64/kernel/smp.c (guest secondary-core bring-up)
//
// Skill guide warnings observed:
//   - Aff0/Aff1 are not swapped: Aff0 = core within cluster [7:0], Aff1 = cluster [15:8]
//   - GICD_IROUTER uses MPIDR affinity format, NOT a linear core index
//   - CPU_ON MUST check target affinity against the CALLING guest's core list
//     before doing anything; skipping this check is a security bug

use core::arch::asm;

use crate::partition::GuestId;

// ─────────────────────────────────────────────────────────────────────────────
// MPIDR_EL1 — Multiprocessor Affinity Register
//
// Identifies a CPU core's position in the affinity hierarchy.
// ARM ARM DDI0487 Section D7.2.74.
//
// 64-bit layout:
//   Bits  [7:0]  — Aff0: core index within its cluster
//   Bits [15:8]  — Aff1: cluster index
//   Bits [23:16] — Aff2: higher-level grouping (Aff2=0 on most SoCs)
//   Bit   [24]   — MT: 1 if cores share an L1 (hardware multithreading); 0 on SMP
//   Bits [29:25] — reserved
//   Bit   [30]   — U: 1 if this is a uniprocessor implementation
//   Bit   [31]   — RES1 in AArch64 (always reads as 1)
//   Bits [39:32] — Aff3: highest-level grouping (rarely used)
//   Bits [63:40] — reserved
//
// The PSCI and GICD_IROUTER both use the affinity-only view of this register:
// {Aff3, Aff2, Aff1, Aff0} with the RES1, MT, and U bits stripped.
// ─────────────────────────────────────────────────────────────────────────────

/// MPIDR_EL1 value for one physical core.
///
/// Wraps the raw 64-bit hardware register value. All field accessors strip
/// the RES1 and status bits so only the affinity hierarchy is exposed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mpidr(pub u64);

impl Mpidr {
    // ── Affinity field accessors ───────────────────────────────────────────

    /// Aff0: core index within its cluster (bits [7:0]).
    /// Source: ARM ARM DDI0487 Section D7.2.74 field `Aff0 [7:0]`
    #[inline]
    pub fn aff0(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// Aff1: cluster index (bits [15:8]).
    /// Source: ARM ARM DDI0487 Section D7.2.74 field `Aff1 [15:8]`
    #[inline]
    pub fn aff1(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }

    /// Aff2: higher-level grouping (bits [23:16]).
    /// Source: ARM ARM DDI0487 Section D7.2.74 field `Aff2 [23:16]`
    #[inline]
    pub fn aff2(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }

    /// Aff3: highest-level grouping (bits [39:32]).
    /// Source: ARM ARM DDI0487 Section D7.2.74 field `Aff3 [39:32]`
    #[inline]
    pub fn aff3(self) -> u8 {
        ((self.0 >> 32) & 0xFF) as u8
    }

    /// Affinity-only value: {Aff3[39:32], Aff2[23:16], Aff1[15:8], Aff0[7:0]}.
    ///
    /// Strips RES1 (bit 31), MT (bit 24), and U (bit 30) — the bits that
    /// carry no affinity information. This is the value used in:
    ///   - PSCI CPU_ON `target_affinity` argument
    ///   - GICD_IROUTER destination affinity
    ///   - VTTBR_EL2 VMID routing
    ///
    /// Source: PSCI spec DEN0022 Section 5.4.2 (target_affinity format)
    #[inline]
    pub fn affinity_value(self) -> u64 {
        // Keep Aff3 [39:32], Aff2 [23:16], Aff1 [15:8], Aff0 [7:0].
        // Clear all other bits including RES1 (31), MT (24), U (30).
        self.0 & 0x0000_00FF_00FF_FFFF
    }

    /// Read MPIDR_EL1 for the currently executing core.
    ///
    /// # Safety
    /// Must be called from EL2 on the core being identified.
    #[inline]
    pub unsafe fn read_current() -> Self {
        let val: u64;
        unsafe {
            asm!("mrs {}, mpidr_el1", out(reg) val,
                options(nomem, nostack, preserves_flags));
        }
        Self(val)
    }

    /// True if this MPIDR's affinity matches a 64-bit PSCI target affinity value.
    ///
    /// PSCI target_affinity uses the same layout as MPIDR but with RES1/MT/U
    /// bits clear. We strip those bits from both sides before comparing.
    ///
    /// Reference: PSCI spec DEN0022 Section 5.4.2
    #[inline]
    pub fn matches_psci_target(self, target: u64) -> bool {
        self.affinity_value() == (target & 0x0000_00FF_00FF_FFFF)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core state and partition table
// ─────────────────────────────────────────────────────────────────────────────

/// Power state of one physical core.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoreState {
    /// Core has not yet been discovered or brought online.
    Unknown,
    /// Core is powered off (never started or explicitly halted via CPU_OFF).
    Off,
    /// Core is running, executing its assigned guest.
    Running,
    /// Core is in a low-power idle state (WFI/CPU_SUSPEND). Will resume on interrupt.
    Suspended,
    /// CPU_ON was accepted; core is starting up toward the requested entry point.
    /// The core will transition to Running once it reaches EL1.
    PendingStartup { entry_point: u64, context_id: u64 },
}

/// Record for one physical CPU core.
#[derive(Clone, Copy, Debug)]
pub struct CoreInfo {
    /// Hardware MPIDR_EL1 value — primary identifier.
    pub mpidr: Mpidr,
    /// Which guest owns this core.
    pub guest: GuestId,
    /// Current power/execution state.
    pub state: CoreState,
}

/// Maximum number of physical cores AETHER tracks.
/// Snapdragon X Elite has 12; 16 gives comfortable headroom.
pub const MAX_CORES: usize = 16;

/// How many physical cores are assigned to Android by default.
/// Remaining (up to the total discovered count) go to Windows.
/// Adjustable at install time via AETHER configuration; 6/6 is the default.
pub const ANDROID_CORE_COUNT: usize = 6;

/// The static CPU partition table — which physical core belongs to which guest.
///
/// Populated during boot as each secondary core registers itself. Primary core
/// (the boot core, which runs AETHER's early initialisation) registers first.
pub struct CorePartition {
    cores: [CoreInfo; MAX_CORES],
    count: usize,
}

impl CorePartition {
    /// Construct an empty partition table (all slots Unknown).
    pub const fn new_empty() -> Self {
        Self {
            cores: [CoreInfo {
                mpidr: Mpidr(0),
                guest: GuestId::Android,
                state: CoreState::Unknown,
            }; MAX_CORES],
            count: 0,
        }
    }

    /// Register a newly discovered core.
    ///
    /// The first `ANDROID_CORE_COUNT` registered cores are assigned to Android;
    /// subsequent cores are assigned to Windows. The boot core (MPIDR of the
    /// CPU running AETHER's initialisation) should be registered first.
    ///
    /// Returns false if the table is full.
    pub fn register_core(&mut self, mpidr: Mpidr) -> bool {
        if self.count >= MAX_CORES {
            return false;
        }
        let guest = if self.count < ANDROID_CORE_COUNT {
            GuestId::Android
        } else {
            GuestId::Windows
        };
        self.cores[self.count] = CoreInfo {
            mpidr,
            guest,
            state: CoreState::Off,
        };
        self.count += 1;
        true
    }

    /// Mark a core as Running. Called when a secondary core has completed
    /// its EL2 initialisation and is about to ERET into its guest.
    pub fn set_running(&mut self, mpidr: Mpidr) {
        if let Some(c) = self.find_core_mut(mpidr) {
            c.state = CoreState::Running;
        }
    }

    /// Total number of registered cores.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all registered cores.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, CoreInfo> {
        self.cores[..self.count].iter()
    }

    // ── PSCI operations ───────────────────────────────────────────────────

    /// Validate and initiate CPU_ON for `target_affinity`.
    ///
    /// Security invariant: target core MUST belong to the SAME guest as the
    /// calling core. Cross-partition CPU_ON is denied.
    ///
    /// Reference: PSCI spec DEN0022 Section 5.4, skill guide verification 1.
    pub fn cpu_on(
        &mut self,
        target_affinity: u64,
        entry_point: u64,
        context_id: u64,
        caller_mpidr: Mpidr,
    ) -> i64 {
        // Identify caller's guest.
        let caller_guest = match self.find_guest(caller_mpidr) {
            Some(g) => g,
            None => return psci::DENIED, // caller not in table — refuse
        };

        // Find the target core by affinity.
        let target = match self.find_core_mut_by_affinity(target_affinity) {
            Some(c) => c,
            None => return psci::INVALID_PARAMETERS,
        };

        // CRITICAL: reject cross-partition CPU_ON.
        // Allowing a guest to start a core belonging to the other guest would
        // break static partitioning. This is the primary security check.
        if target.guest != caller_guest {
            return psci::DENIED;
        }

        match target.state {
            CoreState::Running => psci::ALREADY_ON,
            CoreState::PendingStartup { .. } => psci::ON_PENDING,
            CoreState::Off | CoreState::Suspended | CoreState::Unknown => {
                target.state = CoreState::PendingStartup { entry_point, context_id };
                psci::SUCCESS
            }
        }
    }

    /// Mark the calling core as Off (CPU_OFF).
    ///
    /// The core parks itself after returning from the PSCI handler. This call
    /// never returns to the caller — but we return SUCCESS so the handler can
    /// write it to x0 before the core halts.
    pub fn cpu_off(&mut self, caller_mpidr: Mpidr) -> i64 {
        if let Some(c) = self.find_core_mut(caller_mpidr) {
            c.state = CoreState::Off;
        }
        psci::SUCCESS
    }

    /// Query the power state of a target affinity level.
    ///
    /// Returns: 0 = ON, 1 = OFF, 2 = ON_PENDING.
    /// Reference: PSCI spec DEN0022 Section 5.5 (AFFINITY_INFO).
    pub fn affinity_info(&self, target_affinity: u64, _lowest_level: u64) -> i64 {
        match self.find_core_by_affinity(target_affinity) {
            None => psci::INVALID_PARAMETERS,
            Some(c) => match c.state {
                CoreState::Running => 0,   // ON
                CoreState::PendingStartup { .. } => 2, // ON_PENDING
                _ => 1,                    // OFF
            },
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────

    fn find_core_mut(&mut self, mpidr: Mpidr) -> Option<&mut CoreInfo> {
        let affinity = mpidr.affinity_value();
        self.cores[..self.count]
            .iter_mut()
            .find(|c| c.mpidr.affinity_value() == affinity)
    }

    fn find_core_mut_by_affinity(&mut self, target: u64) -> Option<&mut CoreInfo> {
        let target = target & 0x0000_00FF_00FF_FFFF;
        self.cores[..self.count]
            .iter_mut()
            .find(|c| c.mpidr.affinity_value() == target)
    }

    fn find_core_by_affinity(&self, target: u64) -> Option<&CoreInfo> {
        let target = target & 0x0000_00FF_00FF_FFFF;
        self.cores[..self.count]
            .iter()
            .find(|c| c.mpidr.affinity_value() == target)
    }

    fn find_guest(&self, mpidr: Mpidr) -> Option<GuestId> {
        let affinity = mpidr.affinity_value();
        self.cores[..self.count]
            .iter()
            .find(|c| c.mpidr.affinity_value() == affinity)
            .map(|c| c.guest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PSCI — Power State Coordination Interface
//
// Guests call PSCI functions via HVC (preferred) or SMC using the ARM SMCCC
// (Standard Mechanism for Calling Conventions) convention:
//   x0 = function ID (32-bit or 64-bit variant)
//   x1 = arg1, x2 = arg2, x3 = arg3
//   Return value written back to x0
//
// AETHER intercepts these calls in handle_hvc / handle_smc (exception.rs),
// dispatches to `handle_psci_call`, and writes the result to GuestContext.regs[0].
//
// Function ID encoding (SMCCC):
//   Bit  [31]:   Calling convention (0 = SMC32, 1 = SMC64)
//   Bits [30:24]: Service type (0b0100000 = Standard Secure Services = PSCI)
//   Bits [15:0]:  Function number
//
// Source: PSCI spec DEN0022, SMCCC spec DEN0028
// ─────────────────────────────────────────────────────────────────────────────

/// PSCI function IDs and return codes.
/// Source: PSCI specification DEN0022 Section 5.
pub mod psci {
    // ── Function IDs ──────────────────────────────────────────────────────
    // SMC32 variants (bit [31] = 0): argument width is 32-bit
    // SMC64 variants (bit [31] = 1): argument width is 64-bit
    // Both are handled identically in our implementation (arguments are
    // already sign-extended to 64 bits by the caller).

    /// PSCI_VERSION: returns the implemented PSCI version.
    /// Source: DEN0022 Section 5.1
    pub const VERSION:         u32 = 0x8400_0000;

    /// CPU_SUSPEND (32-bit): enter a power state on the calling core.
    /// Source: DEN0022 Section 5.3
    pub const CPU_SUSPEND_32:  u32 = 0x8400_0001;

    /// CPU_SUSPEND (64-bit): same, with 64-bit entry point.
    pub const CPU_SUSPEND_64:  u32 = 0xC400_0001;

    /// CPU_OFF: power off the calling core. Never returns to caller.
    /// Source: DEN0022 Section 5.4
    pub const CPU_OFF:         u32 = 0x8400_0002;

    /// CPU_ON (32-bit): power on a target core at a given entry point.
    /// Source: DEN0022 Section 5.5
    pub const CPU_ON_32:       u32 = 0x8400_0003;

    /// CPU_ON (64-bit): same, with 64-bit entry point.
    pub const CPU_ON_64:       u32 = 0xC400_0003;

    /// AFFINITY_INFO (32-bit): query power state of a target affinity level.
    /// Source: DEN0022 Section 5.6
    pub const AFFINITY_INFO_32: u32 = 0x8400_0004;

    /// AFFINITY_INFO (64-bit): same.
    pub const AFFINITY_INFO_64: u32 = 0xC400_0004;

    /// MIGRATE_INFO_TYPE: indicates Trusted OS migration capability.
    /// Returns 2 = "no Trusted OS present". Source: DEN0022 Section 5.9
    pub const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;

    /// SYSTEM_OFF: power down the entire system.
    /// Source: DEN0022 Section 5.11
    pub const SYSTEM_OFF:      u32 = 0x8400_0008;

    /// SYSTEM_RESET: reset the entire system.
    /// Source: DEN0022 Section 5.12
    pub const SYSTEM_RESET:    u32 = 0x8400_0009;

    // ── Return codes ──────────────────────────────────────────────────────
    // Returned in x0. Negative values are errors (two's complement as i64).
    // Source: PSCI spec DEN0022 Section 5.2

    /// Operation completed successfully.
    pub const SUCCESS:            i64 = 0;
    /// Function not implemented.
    pub const NOT_SUPPORTED:      i64 = -1;
    /// One or more arguments are invalid.
    pub const INVALID_PARAMETERS: i64 = -2;
    /// Operation denied (e.g. cross-partition CPU_ON attempt).
    pub const DENIED:             i64 = -3;
    /// Target core is already powered on.
    pub const ALREADY_ON:         i64 = -4;
    /// Target core power-on is in progress.
    pub const ON_PENDING:         i64 = -5;
    /// Internal AETHER error.
    pub const INTERNAL_FAILURE:   i64 = -6;
    /// Target is not present.
    pub const NOT_PRESENT:        i64 = -7;

    // ── PSCI version reported to guests ───────────────────────────────────
    // Format: {major[31:16], minor[15:0]} = 2.0
    // Source: DEN0022 Section 5.1
    pub const VERSION_2_0: i64 = 0x0002_0000;
}

/// Dispatch a PSCI call from a guest.
///
/// Arguments mirror the SMCCC calling convention:
/// - `func_id`:  x0 from the guest (function identifier)
/// - `arg1..3`:  x1..x3 from the guest
/// - `caller_mpidr`: MPIDR of the core that issued the call
/// - `partition`: mutable reference to the global CorePartition
///
/// Returns the value to write back to x0 in the guest context.
///
/// # Security
/// CPU_ON checks that `target_affinity` belongs to the same guest as
/// `caller_mpidr`. All other security-relevant checks are inside `CorePartition`.
pub fn handle_psci_call(
    func_id:      u64,
    arg1:         u64,
    arg2:         u64,
    arg3:         u64,
    caller_mpidr: Mpidr,
    partition:    &mut CorePartition,
) -> i64 {
    // Truncate to 32 bits: the high 32 bits encode the calling convention
    // (SMC32 vs SMC64) but both are handled identically here.
    let func32 = func_id as u32;

    match func32 {
        psci::VERSION => psci::VERSION_2_0,

        psci::CPU_ON_32 | psci::CPU_ON_64 => {
            // arg1 = target_affinity, arg2 = entry_point, arg3 = context_id
            let result = partition.cpu_on(arg1, arg2, arg3, caller_mpidr);
            if result == psci::SUCCESS {
                // Write entry_point into the EL2 spin table and issue SEV.
                // The secondary core is parked in aether_secondary_core_main
                // waiting for this signal.
                crate::smp::wake_secondary_core(arg1, arg2, arg3);
            }
            result
        }

        psci::CPU_OFF => {
            // Mark calling core as Off. The vector stub will park the core
            // after writing SUCCESS to x0.
            partition.cpu_off(caller_mpidr)
        }

        psci::CPU_SUSPEND_32 | psci::CPU_SUSPEND_64 => {
            // Static partitioning: suspend = WFI on this core. The guest
            // will WFI naturally after we return SUCCESS.
            psci::SUCCESS
        }

        psci::AFFINITY_INFO_32 | psci::AFFINITY_INFO_64 => {
            // arg1 = target_affinity, arg2 = lowest_affinity_level
            partition.affinity_info(arg1, arg2)
        }

        psci::MIGRATE_INFO_TYPE => {
            // No Trusted OS — return 2 (MIGRATE_INFO_TYPE_NOT_PRESENT).
            // Source: PSCI DEN0022 Section 5.9
            2
        }

        psci::SYSTEM_OFF => {
            // Park all cores — no clean shutdown path in current AETHER.
            // TODO(ch33): implement graceful shutdown via EL3 PSCI forwarding.
            loop {}
        }

        psci::SYSTEM_RESET => {
            // TODO(ch33): forward to EL3 firmware via SMC.
            loop {}
        }

        _ => psci::NOT_SUPPORTED,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GIC affinity routing — GICD_IROUTER
//
// The GICv3 distributor routes SPIs (Shared Peripheral Interrupts, intid ≥ 32)
// to a target PE via GICD_IROUTER<n> registers. Each register is 64 bits:
//
//   Bits  [7:0]  — Aff0 of target PE (matches MPIDR_EL1.Aff0)
//   Bits [15:8]  — Aff1 of target PE (matches MPIDR_EL1.Aff1)
//   Bits [23:16] — Aff2 of target PE (matches MPIDR_EL1.Aff2)
//   Bits [30:24] — reserved (must be 0)
//   Bit   [31]   — IRM (Interrupt Routing Mode):
//                  0 = route to specific PE identified by affinity
//                  1 = 1-of-N routing: any available PE in the system
//   Bits [39:32] — Aff3 of target PE (matches MPIDR_EL1.Aff3)
//   Bits [63:40] — reserved (must be 0)
//
// AETHER uses IRM=0 (specific PE) and routes each Android device's interrupt to
// Android's primary core (first registered Android core). The guest Linux kernel
// can reprogram GICD_IROUTER entries for its own SPIs via the GIC driver;
// AETHER traps those writes and validates the target remains within the guest's
// assigned cores (Chapter 10 fills in full validation).
//
// Source: GIC Architecture Specification IHI0069 Section 4.8
// Skill guide warning: use MPIDR affinity values, not linear core indices.
// ─────────────────────────────────────────────────────────────────────────────

/// GICD_IROUTER register layout constants.
/// Source: GIC Architecture Specification IHI0069 Section 4.8 (Table 4-24).
pub mod gicd_irouter {
    /// Bit 31: IRM — Interrupt Routing Mode.
    /// 0 = route to specific PE; 1 = 1-of-N routing.
    pub const IRM: u64 = 1 << 31;

    /// Mask for affinity fields: Aff3[39:32] | Aff2[23:16] | Aff1[15:8] | Aff0[7:0].
    pub const AFFINITY_MASK: u64 = 0x0000_00FF_00FF_FFFF;
}

/// Build a GICD_IROUTER value that routes an SPI to the specific PE
/// identified by `mpidr`.
///
/// IRM=0 (specific PE), affinity fields taken from the MPIDR affinity value.
/// This is the correct form for device interrupts assigned to a guest's core.
///
/// # Correctness
/// The `mpidr.affinity_value()` call strips RES1/MT/U bits, leaving only the
/// affinity hierarchy in the positions GICD_IROUTER expects.
/// Reference: IHI0069 Section 4.8, ARM ARM Section D7.2.74.
#[inline]
pub fn build_irouter_specific(mpidr: Mpidr) -> u64 {
    // IRM=0 (specific PE) + affinity value
    mpidr.affinity_value() & gicd_irouter::AFFINITY_MASK
    // gicd_irouter::IRM deliberately omitted — IRM=0 means specific PE
}

/// Register address for GICD_IROUTER<intid>.
///
/// Only valid for SPIs (intid ≥ 32). SGIs and PPIs are per-CPU and use a
/// different routing mechanism (GICR_* registers).
///
/// Layout: GICD_BASE + 0x6000 + intid × 8
/// Source: GIC Architecture Specification IHI0069 Section 12.2.18;
///         linux-ref/drivers/irqchip/irq-gic-v3.c line 978:
///         `base + GICD_IROUTER + i * 8` where i starts at 32.
/// Note: the base offset 0x6000 applies to the INTID directly, not to a
///       zero-based SPI index. GICD_IROUTER32 is at 0x6000 + 32×8 = 0x6100.
#[inline]
pub fn gicd_irouter_offset(intid: u32) -> u64 {
    debug_assert!(intid >= 32, "GICD_IROUTER only applies to SPIs (intid >= 32)");
    0x6000 + (intid as u64) * 8
}

/// Configure GICD_IROUTER for all SPIs in `spi_intids` to route to
/// `target_mpidr` (must be a core in the owning guest's partition).
///
/// Call this once during boot, after GICD_CTLR.ARE_S=1 has been set to enable
/// affinity routing. Chapter 10 extends this to fully validate routing requests
/// from guest kernels.
///
/// # Arguments
/// - `gicd_base`:   MMIO base address of the GIC distributor.
/// - `spi_intids`:  Slice of SPI interrupt IDs to configure (each ≥ 32).
/// - `target_mpidr`: MPIDR of the core that will receive these interrupts.
///
/// # Safety
/// - `gicd_base` must be the correct MMIO-mapped GIC distributor base address.
/// - GICD_CTLR.ARE_S must already be set (affinity routing enabled).
/// - Must be called from EL2 during single-threaded boot initialisation.
pub unsafe fn init_gic_routing(
    gicd_base:    u64,
    spi_intids:   &[u32],
    target_mpidr: Mpidr,
) {
    let irouter_val = build_irouter_specific(target_mpidr);

    for &intid in spi_intids {
        if intid < 32 {
            continue; // SGIs and PPIs do not use GICD_IROUTER — skip silently
        }
        let reg_addr = gicd_base + gicd_irouter_offset(intid);
        // Write the 64-bit GICD_IROUTER<intid> register.
        // volatile write ensures the compiler does not reorder or eliminate it.
        unsafe {
            (reg_addr as *mut u64).write_volatile(irouter_val);
        }
    }

    // DSB ensures all GICD_IROUTER writes are visible to the GIC hardware
    // before the caller proceeds to enable interrupts or start guests.
    crate::arm64::barriers::dsb_ish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Global partition table
//
// Accessed from exception handlers (handle_hvc / handle_smc in exception.rs).
// Single-threaded during boot; each core accesses its own slot after start-up.
// Using `static mut` is correct here — bare-metal, no OS, no threads crossing
// partition boundaries.
// ─────────────────────────────────────────────────────────────────────────────

/// The global CPU partition table. Initialised to empty; populated via
/// `aether_partition_mut().register_core(Mpidr::read_current())` as each
/// secondary core boots.
static mut AETHER_PARTITION: CorePartition = CorePartition::new_empty();

/// Exclusive mutable reference to the global CPU partition table.
///
/// # Safety
/// Must be called only from single-threaded EL2 context (boot or exception
/// handler where the calling core holds the only reference). Never hold this
/// reference across a `dsb` or any point where another core could be running.
#[inline]
pub unsafe fn aether_partition_mut() -> &'static mut CorePartition {
    // SAFETY: raw pointer detour avoids the Rust 2024 `static_mut_refs` lint.
    // The caller guarantees exclusive access.
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_PARTITION) }
}

/// Shared reference to the global CPU partition table.
///
/// # Safety
/// Same caller requirements as `aether_partition_mut`.
#[inline]
pub unsafe fn aether_partition() -> &'static CorePartition {
    // SAFETY: raw pointer detour — see aether_partition_mut.
    unsafe { &*core::ptr::addr_of!(AETHER_PARTITION) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // ANDROID_CORE_COUNT must fit within MAX_CORES.
    assert!(
        ANDROID_CORE_COUNT < MAX_CORES,
        "ANDROID_CORE_COUNT must be less than MAX_CORES"
    );

    // PSCI VERSION_2_0 must encode major=2, minor=0 in {major[31:16], minor[15:0]}.
    assert!(
        psci::VERSION_2_0 == 0x0002_0000,
        "PSCI VERSION_2_0 must be 0x0002_0000 (major=2, minor=0)"
    );

    // PSCI function ID sanity (SMCCC DEN0028): bit 30 distinguishes SMC32 (0)
    // from SMC64 (1).  Bit 31 is the Fast-call flag and is set for ALL PSCI
    // function IDs, so we do NOT test it here.
    assert!(
        psci::CPU_ON_64 & 0x4000_0000 != 0,
        "CPU_ON_64 must have bit 30 set (SMC64 calling convention)"
    );
    assert!(
        psci::CPU_ON_32 & 0x4000_0000 == 0,
        "CPU_ON_32 must have bit 30 clear (SMC32 calling convention)"
    );

    // GICD_IROUTER IRM bit must be at position 31.
    assert!(
        gicd_irouter::IRM == 1 << 31,
        "gicd_irouter::IRM must be bit 31 per IHI0069 Section 4.8"
    );

    // The affinity mask must cover Aff0[7:0], Aff1[15:8], Aff2[23:16], Aff3[39:32]
    // and must NOT cover IRM (bit 31).
    assert!(
        gicd_irouter::AFFINITY_MASK & gicd_irouter::IRM == 0,
        "AFFINITY_MASK must not overlap IRM bit"
    );
};
