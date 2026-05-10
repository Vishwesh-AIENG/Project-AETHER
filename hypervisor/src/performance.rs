// ch24: Performance
//
// AETHER's performance philosophy: nothing should be slower than equivalent
// native hardware.  The ARM64 chip in a Snapdragon X Elite is more capable
// than any phone chip, so Android workloads should run *faster* than on real
// devices, not slower.
//
// Performance properties of each subsystem:
//
//   CPU     — Native.  Guests execute instructions directly on the real CPU
//             at full clock speed.  AETHER only intervenes on trapped
//             operations (HVC, SMC, system-register traps, memory faults).
//             During normal application execution these are rare.
//
//   Memory  — Native.  Stage 2 translation is fully pipelined inside the
//             ARM MMU.  On modern ARM64 cores (Cortex-X4 / Oryon) a Stage 2
//             TLB hit adds zero measurable latency to ordinary loads and
//             stores.  The only risk is TLB *thrashing* when AETHER maps
//             Android's address space with 4 KiB pages instead of 2 MiB
//             blocks.  AETHER's Stage 2 mapper therefore prefers 2 MiB block
//             mappings wherever the IPA range is block-aligned and large
//             enough.  See `LargePagePolicy`.
//
//   GPU     — Native via SR-IOV.  Graphics commands flow from the Android
//             graphics stack directly to the Adreno VF.  AETHER never
//             touches a GPU command.
//
//   Storage — Native via NVMe namespace passthrough.  Reads and writes flow
//             from Android's NVMe driver directly to the controller.  AETHER
//             is not in the data path.
//
//   Network — Native via SR-IOV VF or dedicated adapter passthrough.
//             Packets bypass the hypervisor entirely.
//
//   Paravirt — Small, bounded overhead.  The virtual modem, virtual sensor
//              suite, and phone-specific peripherals are not performance-
//              critical.  Polling the gyroscope at 100 Hz costs nothing
//              measurable on a Cortex-X4 core.
//
// ── VM exit frequency ─────────────────────────────────────────────────────────
//
// Every VM exit costs roughly 1 000–5 000 cycles on ARM64 (dependent on
// operation and cache state).  In a well-tuned hypervisor, exits during
// sustained gaming should number fewer than 1 000 per second.  AETHER
// instruments every exit with `ExitCounter` so that anomalous trap rates can
// be detected during development.
//
// Top expected exit reasons during normal Android operation:
//   1. Virtual timer expiry (VTIMER_EL1) — ~100–1 000/s depending on Hz.
//   2. WFI/WFE traps — guest idle; re-enter immediately after scheduling.
//   3. PSCI calls — rare, only on core bring-up or power-state transitions.
//   4. System-register traps — should be zero after boot completes.
//   5. Stage 2 faults — should be zero during steady-state operation.
//
// If the Stage 2 fault count climbs during gameplay the working set is
// exceeding the mapped region — indicates a boot-time mapping gap.
//
// ── TLB pressure and large pages ─────────────────────────────────────────────
//
// ARM64 Stage 2 TLBs have thousands of entries on production silicon.  An
// Android gaming workload that fits in 12 GiB of RAM maps to roughly 6 144
// 2 MiB blocks — well within Stage 2 TLB capacity.  The same working set
// expressed as 4 KiB pages would require ~3 million entries, causing
// continuous TLB misses.
//
// Rule: use 2 MiB block descriptors wherever IPA and PA are both 2 MiB-
// aligned and the region spans at least one full block.  Fall back to 4 KiB
// pages only for sub-block regions (MMIO slivers, guard pages).
//
// ── L3 cache sharing ─────────────────────────────────────────────────────────
//
// The Snapdragon X Elite's L3 cache is physically shared across all cores
// regardless of partition assignment.  Windows workloads and Android workloads
// compete for L3 cache space.  This is identical to running two processes on
// native hardware and is not a hypervisor artifact.  No software mitigation
// is applied — this is physics, not policy.
//
// Primary references:
//   ARM Cortex-X4 Software Optimization Guide (developer.arm.com)
//   ARM ARM DDI0487 Section D5.5 (Stage 2 translation)
//   ARM ARM DDI0487 Section D5.10 (TLB maintenance)
//   Brendan Gregg, Systems Performance (2nd ed.) — VM exit analysis methods
//   Perfetto tracing documentation (perfetto.dev)

// ─────────────────────────────────────────────────────────────────────────────
// PerformancePath — expected overhead for each subsystem
// ─────────────────────────────────────────────────────────────────────────────

/// The overhead class AETHER imposes on a subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemOverhead {
    /// No software layer between guest and hardware. Overhead is zero.
    Native,

    /// Hardware-assisted (MMU pipeline, GIC hardware routing) with no
    /// measurable latency penalty under normal working-set sizes.
    Negligible,

    /// Software participation on the critical path. Overhead is real but
    /// bounded and acceptable for the usage pattern of this subsystem.
    Present,
}

/// Performance model for one AETHER subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SubsystemPerf {
    pub overhead: SubsystemOverhead,
    /// One-line rationale for the overhead class.
    pub rationale: &'static str,
}

/// AETHER's performance model — one entry per major subsystem.
pub const SUBSYSTEM_PERF: &[(&str, SubsystemPerf)] = &[
    (
        "cpu",
        SubsystemPerf {
            overhead: SubsystemOverhead::Native,
            rationale: "Guests execute native ARM64 instructions at full clock speed; AETHER only traps rare privileged operations.",
        },
    ),
    (
        "memory",
        SubsystemPerf {
            overhead: SubsystemOverhead::Negligible,
            rationale: "Stage 2 translation is fully pipelined in the ARM MMU; TLB hits add zero measurable latency.",
        },
    ),
    (
        "gpu",
        SubsystemPerf {
            overhead: SubsystemOverhead::Native,
            rationale: "SR-IOV VF passthrough: graphics commands go from Android driver to GPU silicon with no hypervisor involvement.",
        },
    ),
    (
        "storage",
        SubsystemPerf {
            overhead: SubsystemOverhead::Native,
            rationale: "NVMe namespace passthrough: I/O commands reach the NVMe controller directly via Android's own driver.",
        },
    ),
    (
        "network",
        SubsystemPerf {
            overhead: SubsystemOverhead::Native,
            rationale: "SR-IOV VF or dedicated adapter: packets bypass the hypervisor entirely in the data path.",
        },
    ),
    (
        "paravirt",
        SubsystemPerf {
            overhead: SubsystemOverhead::Present,
            rationale: "Virtual modem and sensors interpose on calls, but these paths are never on the performance-critical game loop.",
        },
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// ExitReason — VM exit cause categories for instrumentation
// ─────────────────────────────────────────────────────────────────────────────

/// Categories of VM exit tracked by `ExitCounter`.
///
/// Each variant corresponds to a common exit cause in AETHER's trap handlers.
/// The counters are diagnostic only; no runtime policy depends on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// WFI/WFE instruction trapped (HCR_EL2.TWI/TWE). Guest is idle.
    WfxTrap,
    /// HVC hypercall (PSCI or AETHER-specific).
    Hvc,
    /// SMC trapped (HCR_EL2.TSC). Forwarded to PSCI handler.
    Smc,
    /// System-register trap (MSR/MRS to a trapped register).
    SystemRegister,
    /// Stage 2 instruction abort — mapping gap on the code path.
    InstructionFault,
    /// Stage 2 data abort — mapping gap on the data path.
    DataFault,
    /// Physical IRQ forwarded to the guest's virtual GIC.
    PhysicalIrq,
    /// EL2 virtual timer expiry.
    VirtualTimer,
    /// Any other exit reason not enumerated above.
    Other,
}

/// Total number of `ExitReason` variants.
const EXIT_REASON_COUNT: usize = 9;

/// Maps an `ExitReason` to its slot index in `ExitCounter::counts`.
#[inline]
const fn reason_index(r: ExitReason) -> usize {
    match r {
        ExitReason::WfxTrap          => 0,
        ExitReason::Hvc              => 1,
        ExitReason::Smc              => 2,
        ExitReason::SystemRegister   => 3,
        ExitReason::InstructionFault => 4,
        ExitReason::DataFault        => 5,
        ExitReason::PhysicalIrq      => 6,
        ExitReason::VirtualTimer     => 7,
        ExitReason::Other            => 8,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExitCounter — per-core VM exit instrumentation
// ─────────────────────────────────────────────────────────────────────────────

/// Per-core VM exit counter.
///
/// Incremented in the EL2 trap handler on every exit before dispatch.
/// Reading the counters during a diagnostic window and comparing to elapsed
/// time reveals whether exit rate is within the performance target (<1 000/s
/// during sustained gaming).
///
/// The counters are `u64` to avoid overflow during long sessions.
/// They do not wrap; once saturated at `u64::MAX` they stay there.
#[derive(Debug)]
pub struct ExitCounter {
    counts: [u64; EXIT_REASON_COUNT],
}

impl ExitCounter {
    /// Create a zeroed counter (all reasons at 0).
    pub const fn new() -> Self {
        Self {
            counts: [0; EXIT_REASON_COUNT],
        }
    }

    /// Record one VM exit of the given reason.
    ///
    /// Uses saturating addition so the counter never wraps on very long
    /// sessions.
    #[inline]
    pub fn record(&mut self, reason: ExitReason) {
        let idx = reason_index(reason);
        self.counts[idx] = self.counts[idx].saturating_add(1);
    }

    /// Return the accumulated count for a specific reason.
    #[inline]
    pub fn count(&self, reason: ExitReason) -> u64 {
        self.counts[reason_index(reason)]
    }

    /// Return the total exit count across all reasons.
    pub fn total(&self) -> u64 {
        let mut sum: u64 = 0;
        for c in &self.counts {
            sum = sum.saturating_add(*c);
        }
        sum
    }

    /// Return `true` when the total count exceeds the gaming-performance
    /// threshold.  The threshold is expressed as a count, not a rate, so
    /// callers must sample over a fixed window.
    ///
    /// Threshold: 1 000 exits per second during sustained gaming.
    /// This method checks whether `total()` exceeds `threshold_per_second`
    /// over `elapsed_seconds` — both supplied by the caller to keep this
    /// type `no_std`-compatible (no wall clock here).
    pub fn exceeds_gaming_threshold(&self, threshold_per_second: u64, elapsed_seconds: u64) -> bool {
        let limit = threshold_per_second.saturating_mul(elapsed_seconds);
        self.total() > limit
    }

    /// Reset all counters to zero (e.g., between measurement windows).
    pub fn reset(&mut self) {
        self.counts = [0; EXIT_REASON_COUNT];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LargePagePolicy — Stage 2 mapping granularity preference
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for choosing the Stage 2 page table leaf size.
///
/// AETHER's Stage 2 mapper consults this policy for each range it maps.
/// The correct answer is almost always `PreferBlock` — using 4 KiB pages
/// for large RAM regions causes Stage 2 TLB thrashing.  `ForceSmall` exists
/// only for sub-block MMIO slivers and guard pages where block mapping would
/// expose adjacent regions to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargePagePolicy {
    /// Use a 2 MiB L2 block descriptor when both IPA and PA are 2 MiB-aligned
    /// and the region spans at least `PMD_SIZE` bytes.  Fall back to 4 KiB
    /// pages only for the sub-block tail.
    ///
    /// This is the correct choice for all RAM regions.  It maximises Stage 2
    /// TLB coverage and eliminates TLB thrashing.
    PreferBlock,

    /// Always use 4 KiB page descriptors regardless of alignment.
    ///
    /// Use only for MMIO slivers that are smaller than 2 MiB or that must
    /// not accidentally map adjacent MMIO registers into the guest.
    ForceSmall,
}

impl LargePagePolicy {
    /// Return whether a 2 MiB block mapping is appropriate for the given
    /// IPA base, PA base, and size.
    ///
    /// Returns `true` when:
    ///   - policy is `PreferBlock`, AND
    ///   - `ipa_base` is 2 MiB-aligned, AND
    ///   - `pa_base` is 2 MiB-aligned, AND
    ///   - `size` is at least 2 MiB.
    ///
    /// The caller is responsible for ensuring the 2 MiB range does not
    /// straddle a region boundary (e.g., mix RAM and MMIO in one block).
    #[inline]
    pub fn should_use_block(self, ipa_base: u64, pa_base: u64, size: u64) -> bool {
        if self == LargePagePolicy::ForceSmall {
            return false;
        }
        const PMD_SIZE: u64 = 2 * 1024 * 1024;
        const PMD_MASK: u64 = PMD_SIZE - 1;
        (ipa_base & PMD_MASK) == 0 && (pa_base & PMD_MASK) == 0 && size >= PMD_SIZE
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PerformanceSummary — aggregate view returned to callers
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of AETHER's performance model for a given hardware configuration.
#[derive(Debug)]
pub struct PerformanceSummary {
    /// True when the GPU VF is assigned via SR-IOV (native GPU performance).
    pub gpu_sriov_active: bool,
    /// True when the NIC is assigned via SR-IOV or dedicated passthrough.
    pub network_native: bool,
    /// True when Stage 2 RAM mappings use 2 MiB blocks (TLB-efficient).
    pub large_pages_active: bool,
}

impl PerformanceSummary {
    /// Return `true` when all performance-sensitive paths are native.
    ///
    /// A `false` result indicates at least one subsystem is falling back to
    /// software mediation (e.g., paravirt network) and should be flagged
    /// during integration testing.
    pub fn all_native(&self) -> bool {
        self.gpu_sriov_active && self.network_native && self.large_pages_active
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_counter_record_and_total() {
        let mut c = ExitCounter::new();
        assert_eq!(c.total(), 0);

        c.record(ExitReason::WfxTrap);
        c.record(ExitReason::WfxTrap);
        c.record(ExitReason::Hvc);
        c.record(ExitReason::PhysicalIrq);

        assert_eq!(c.count(ExitReason::WfxTrap), 2);
        assert_eq!(c.count(ExitReason::Hvc), 1);
        assert_eq!(c.count(ExitReason::PhysicalIrq), 1);
        assert_eq!(c.count(ExitReason::DataFault), 0);
        assert_eq!(c.total(), 4);
    }

    #[test]
    fn exit_counter_gaming_threshold() {
        let mut c = ExitCounter::new();
        // 999 exits over 1 second — within threshold
        for _ in 0..999 {
            c.record(ExitReason::VirtualTimer);
        }
        assert!(!c.exceeds_gaming_threshold(1_000, 1));

        // 1001st exit pushes it over
        c.record(ExitReason::VirtualTimer);
        c.record(ExitReason::VirtualTimer);
        assert!(c.exceeds_gaming_threshold(1_000, 1));
    }

    #[test]
    fn exit_counter_reset() {
        let mut c = ExitCounter::new();
        c.record(ExitReason::DataFault);
        c.record(ExitReason::InstructionFault);
        assert_eq!(c.total(), 2);
        c.reset();
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn exit_counter_saturating_add() {
        let mut c = ExitCounter::new();
        // Manually saturate one slot
        let idx = super::reason_index(ExitReason::Other);
        c.counts[idx] = u64::MAX;
        c.record(ExitReason::Other);
        // Must not wrap
        assert_eq!(c.count(ExitReason::Other), u64::MAX);
    }

    #[test]
    fn large_page_policy_prefer_block() {
        let policy = LargePagePolicy::PreferBlock;
        let mib2 = 2 * 1024 * 1024u64;

        // Both aligned, size >= 2 MiB → block
        assert!(policy.should_use_block(0, 0, mib2));
        assert!(policy.should_use_block(mib2, mib2, 4 * mib2));

        // IPA misaligned → no block
        assert!(!policy.should_use_block(1, 0, mib2));
        // PA misaligned → no block
        assert!(!policy.should_use_block(0, 1, mib2));
        // Too small → no block
        assert!(!policy.should_use_block(0, 0, mib2 - 1));
    }

    #[test]
    fn large_page_policy_force_small() {
        let policy = LargePagePolicy::ForceSmall;
        let mib2 = 2 * 1024 * 1024u64;
        // Even a perfectly aligned 2 MiB range returns false
        assert!(!policy.should_use_block(0, 0, mib2));
    }

    #[test]
    fn performance_summary_all_native() {
        let all = PerformanceSummary {
            gpu_sriov_active: true,
            network_native: true,
            large_pages_active: true,
        };
        assert!(all.all_native());

        let degraded = PerformanceSummary {
            gpu_sriov_active: true,
            network_native: false, // paravirt network fallback
            large_pages_active: true,
        };
        assert!(!degraded.all_native());
    }

    #[test]
    fn subsystem_perf_table_has_all_subsystems() {
        let names: &[&str] = &["cpu", "memory", "gpu", "storage", "network", "paravirt"];
        for &name in names {
            let found = SUBSYSTEM_PERF.iter().any(|(n, _)| *n == name);
            assert!(found, "missing subsystem: {}", name);
        }
    }

    #[test]
    fn cpu_and_gpu_are_native() {
        for &(name, perf) in SUBSYSTEM_PERF {
            if name == "cpu" || name == "gpu" || name == "storage" || name == "network" {
                assert_eq!(
                    perf.overhead,
                    SubsystemOverhead::Native,
                    "{} should be Native",
                    name
                );
            }
        }
    }

    #[test]
    fn paravirt_is_present_overhead() {
        let pv = SUBSYSTEM_PERF.iter().find(|(n, _)| *n == "paravirt").unwrap();
        assert_eq!(pv.1.overhead, SubsystemOverhead::Present);
    }

    #[test]
    fn memory_is_negligible_overhead() {
        let mem = SUBSYSTEM_PERF.iter().find(|(n, _)| *n == "memory").unwrap();
        assert_eq!(mem.1.overhead, SubsystemOverhead::Negligible);
    }
}
