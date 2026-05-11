// ch29: Phase One — Foundation (ARM Tier)
//
// The first phase of the AETHER roadmap.  Estimated at twelve to eighteen
// months for a small dedicated team; multiply by two to three for a single
// engineer working part-time alongside a four-year computer science degree.
//
// ── Phase One Definition ──────────────────────────────────────────────────────
//
// Phase One produces a hypervisor that:
//
//   - Boots on real Snapdragon X Elite hardware at EL2
//   - Runs a minimal Linux guest in the Android partition
//   - The guest executes code, allocates memory, and handles interrupts from
//     its assigned passthrough devices
//   - NVMe namespace passthrough is working
//   - GIC routing (physical IRQ → guest virtual IRQ via ICH_LR) is working
//   - No Android userspace, no graphics yet
//   - ARM Tier architecture validated end to end on real hardware
//
// The end state is a hypervisor that has earned the right to host Android.
// No app store, no Adreno driver, no sensor models — that is Phase Two.
//
// ── Critical Path (No Parallelism) ────────────────────────────────────────────
//
// The chapters that make up Phase One must complete in order:
//
//   ch04  ARM64 substrate            — register access, barriers, page tables
//        ↓
//   ch05  Exception handling         — vector table, GuestContext, ESR decode
//        ↓
//   ch06  Virtualization extensions  — HCR_EL2, VTCR_EL2, Stage 2 enabled
//        ↓
//   ch07  Boot                       — ExitBootServices, ERET to EL1
//        ↓
//   ch08  Memory architecture        — Stage 2 page tables, SMMU stream table
//        ↓
//   ch09  CPU partitioning           — MPIDR-based core assignment, PSCI
//        ↓
//   ch10  Interrupt routing          — physical GIC + virtual interrupt injection
//        ↓
//   ch11  Passthrough principle      — PCIe device assignment with IOMMU groups
//        ↓
//   ch14  Storage partitioning       — NVMe namespace isolation
//
// Until ch06 (Stage 2 enabled) lands, no guest can safely run.  Until ch10
// (GIC virt) lands, no device interrupt can reach the guest.  Until ch11+ch14
// land, no real hardware is passed through.  Skipping a step or running them
// in parallel produces code that must be rewritten — which takes longer than
// finishing the prerequisite would have.
//
// ── The Research Phase Is Not Optional ────────────────────────────────────────
//
// Before writing the first line of hypervisor code, a 2–4 month research
// phase is mandatory.  During this phase: read all primary sources listed in
// the SKILL.md files, build familiarity with QEMU ARM64 system emulation,
// write throw-away experimental code to verify understanding, and establish
// the development environment.  This phase is captured by the
// `ResearchPhaseStatus` type below and gated by `Phase1Config::validate()` —
// a phase that begins without research complete is rejected.
//
// ── Realistic Time Accounting ─────────────────────────────────────────────────
//
// The README's "12–18 months for a small team" estimate assumes full-time
// dedicated engineering.  AETHER is being built part-time alongside a CS
// degree.  Realistic planning multiplies by 2–3.  The `Phase1TimelineEstimate`
// type carries optimistic, realistic, and pessimistic month counts; the
// realistic value is the optimistic value multiplied by `REALISTIC_MULTIPLIER`.
//
// ── Phase Gate Criterion ──────────────────────────────────────────────────────
//
// At the end of Phase One, a single-sentence acceptance test must pass
// without workarounds: "On real Snapdragon X Elite hardware, AETHER boots at
// EL2 and runs a minimal Linux guest that prints to a passthrough UART, owns
// a passthrough NVMe namespace, and receives interrupts routed through the
// hypervisor's GIC virtualization."  Workarounds (e.g., "works on QEMU but
// not on real hardware", "interrupts work for some devices but not others")
// fail the gate.

use crate::development_workflow::{TestTier, WorkflowConfig};

// ─────────────────────────────────────────────────────────────────────────────
// ResearchPhaseStatus — the mandatory pre-implementation research phase
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks completion of the mandatory 2–4 month research phase that precedes
/// any Phase One implementation work.
///
/// Skipping any item produces code that must be rewritten.  All five must be
/// `true` before `Phase1Config::validate()` permits Phase One to begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResearchPhaseStatus {
    /// The ARM Architecture Reference Manual (ARMv8-A) chapters on exception
    /// levels, MMU, Stage 2 translation, GIC, SMMU, and the architectural
    /// timer have been read end to end.
    pub arm_arm_read: bool,
    /// The Linux KVM ARM64 subsystem (`arch/arm64/kvm/`) has been read and the
    /// reader can explain how Stage 2 page tables are constructed and how
    /// interrupt injection works in KVM.
    pub kvm_arm64_studied: bool,
    /// A working QEMU `virt` machine + GICv3 + EL2 development environment is
    /// set up locally, including a serial console and a GDB stub.
    pub qemu_environment_ready: bool,
    /// At least one throw-away experimental program has been written and run
    /// in QEMU to verify the reader can build, load, and execute bare-metal
    /// ARM64 code at EL2.
    pub experimental_code_written: bool,
    /// A dated project journal has been created and the first entries
    /// recorded.  Future-self will not remember today's reasoning without it.
    pub project_journal_started: bool,
}

impl ResearchPhaseStatus {
    /// All five research-phase items complete.  Required before Phase One.
    pub const COMPLETE: Self = Self {
        arm_arm_read:              true,
        kvm_arm64_studied:         true,
        qemu_environment_ready:    true,
        experimental_code_written: true,
        project_journal_started:   true,
    };

    /// Initial state: nothing done yet.
    pub const NOT_STARTED: Self = Self {
        arm_arm_read:              false,
        kvm_arm64_studied:         false,
        qemu_environment_ready:    false,
        experimental_code_written: false,
        project_journal_started:   false,
    };

    /// Return `true` when every research item is complete.
    pub const fn is_complete(self) -> bool {
        self.arm_arm_read
            && self.kvm_arm64_studied
            && self.qemu_environment_ready
            && self.experimental_code_written
            && self.project_journal_started
    }

    /// Validate that the research phase is complete.
    pub fn validate(&self) -> Result<(), Phase1Error> {
        if !self.is_complete() {
            return Err(Phase1Error::ResearchPhaseIncomplete);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1Milestone — the discrete milestones inside Phase One
// ─────────────────────────────────────────────────────────────────────────────

/// A single milestone within Phase One.
///
/// Milestones are listed in dependency order.  Each milestone corresponds to
/// one or more implementation chapters (4–14) of the README.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase1Milestone {
    /// ARM64 substrate stubs compile and pass unit tests (ch04).
    Arm64SubstrateReady,
    /// Exception vectors install and trap WFI/HVC into Rust handlers (ch05).
    ExceptionHandlingReady,
    /// HCR_EL2 / VTCR_EL2 / VTTBR_EL2 configured; Stage 2 translation active
    /// (ch06).
    Stage2TranslationActive,
    /// UEFI ExitBootServices completes cleanly and the hypervisor reaches
    /// `efi_main` end state with the memory map captured (ch07).
    UefiBootHandoffComplete,
    /// Stage 2 page tables map a guest's IPA window to RAM; SMMU v3 stream
    /// table entries program assigned devices to the same VMID (ch08).
    MemoryIsolationEnforced,
    /// MPIDR-based CPU partitioning + PSCI `cpu_on` enforce per-core
    /// assignment.  Cross-partition CPU hijack returns `PSCI_DENIED` (ch09).
    CpuPartitioningActive,
    /// Physical GICv3 initialized; virtual interrupt injection via ICH_LR
    /// reaches an EL1 guest; maintenance IRQ handler clears completed LRs
    /// (ch10).
    GicVirtualizationWorking,
    /// PCIe device assignment pipeline (IOMMU group check → FLR → BAR map →
    /// SMMU STE → registry) succeeds for at least one passthrough device
    /// (ch11).
    PassthroughAssignmentSuccessful,
    /// NVMe namespace management + namespace attachment route an exclusive
    /// namespace to the guest's VF.  No second controller can attach the
    /// same NSID (ch14).
    NvmeNamespaceAssigned,
    /// A minimal Linux EL1 guest in the Android partition runs in QEMU, owns
    /// a passthrough NVMe namespace, prints to a passthrough UART, and
    /// receives at least one interrupt routed through the hypervisor's
    /// GIC virtualization.
    MinimalLinuxGuestInQemu,
    /// The same minimal Linux guest runs on real Snapdragon X Elite hardware.
    /// This milestone closes Phase One.
    MinimalLinuxGuestOnHardware,
}

impl Phase1Milestone {
    /// The strict prerequisite milestone, or `None` for the first milestone.
    ///
    /// Phase One is a single critical-path sequence.  Skipping a prerequisite
    /// produces code that must be rewritten when the prerequisite lands.
    pub const fn prerequisite(self) -> Option<Phase1Milestone> {
        use Phase1Milestone::*;
        match self {
            Arm64SubstrateReady             => None,
            ExceptionHandlingReady          => Some(Arm64SubstrateReady),
            Stage2TranslationActive         => Some(ExceptionHandlingReady),
            UefiBootHandoffComplete         => Some(Stage2TranslationActive),
            MemoryIsolationEnforced         => Some(UefiBootHandoffComplete),
            CpuPartitioningActive           => Some(MemoryIsolationEnforced),
            GicVirtualizationWorking        => Some(CpuPartitioningActive),
            PassthroughAssignmentSuccessful => Some(GicVirtualizationWorking),
            NvmeNamespaceAssigned           => Some(PassthroughAssignmentSuccessful),
            MinimalLinuxGuestInQemu         => Some(NvmeNamespaceAssigned),
            MinimalLinuxGuestOnHardware     => Some(MinimalLinuxGuestInQemu),
        }
    }

    /// The development tier at which this milestone can first be validated.
    ///
    /// Most milestones can be exercised in Tier 1 (QEMU minimal).  Only
    /// `MinimalLinuxGuestOnHardware` requires real Snapdragon X Elite hardware;
    /// `MinimalLinuxGuestInQemu` exercises a real Linux kernel and therefore
    /// belongs in Tier 2.
    pub const fn validation_tier(self) -> TestTier {
        use Phase1Milestone::*;
        match self {
            MinimalLinuxGuestOnHardware => TestTier::RealHardware,
            MinimalLinuxGuestInQemu     => TestTier::QemuLinuxGuest,
            _                           => TestTier::QemuMinimal,
        }
    }

    /// Short human-readable label, for status displays and journal entries.
    pub const fn label(self) -> &'static str {
        use Phase1Milestone::*;
        match self {
            Arm64SubstrateReady             => "ARM64 substrate ready",
            ExceptionHandlingReady          => "exception handling ready",
            Stage2TranslationActive         => "Stage 2 translation active",
            UefiBootHandoffComplete         => "UEFI boot handoff complete",
            MemoryIsolationEnforced         => "memory isolation enforced",
            CpuPartitioningActive           => "CPU partitioning active",
            GicVirtualizationWorking        => "GIC virtualization working",
            PassthroughAssignmentSuccessful => "passthrough assignment successful",
            NvmeNamespaceAssigned           => "NVMe namespace assigned",
            MinimalLinuxGuestInQemu         => "minimal Linux guest in QEMU",
            MinimalLinuxGuestOnHardware     => "minimal Linux guest on hardware",
        }
    }
}

/// The complete ordered sequence of Phase One milestones.
pub const PHASE1_MILESTONES: &[Phase1Milestone] = &[
    Phase1Milestone::Arm64SubstrateReady,
    Phase1Milestone::ExceptionHandlingReady,
    Phase1Milestone::Stage2TranslationActive,
    Phase1Milestone::UefiBootHandoffComplete,
    Phase1Milestone::MemoryIsolationEnforced,
    Phase1Milestone::CpuPartitioningActive,
    Phase1Milestone::GicVirtualizationWorking,
    Phase1Milestone::PassthroughAssignmentSuccessful,
    Phase1Milestone::NvmeNamespaceAssigned,
    Phase1Milestone::MinimalLinuxGuestInQemu,
    Phase1Milestone::MinimalLinuxGuestOnHardware,
];

// ─────────────────────────────────────────────────────────────────────────────
// MilestoneState — per-milestone progress tracking
// ─────────────────────────────────────────────────────────────────────────────

/// The lifecycle state of a single Phase One milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilestoneState {
    /// Work on this milestone has not begun.  The prerequisite may also
    /// still be incomplete.
    NotStarted,
    /// Work is underway but the validation tier has not yet passed cleanly.
    InProgress,
    /// The validation tier passed cleanly without workarounds.
    Validated,
    /// The milestone was previously `Validated` but a later change broke it.
    ///
    /// A regressed milestone blocks all milestones that depend on it from
    /// being considered `Validated` in any aggregate report.  Fix the
    /// regression before resuming downstream work.
    Regressed,
}

impl MilestoneState {
    /// Return `true` only when the milestone passes its validation tier today.
    ///
    /// `NotStarted`, `InProgress`, and `Regressed` all return `false`.
    pub const fn is_validated(self) -> bool {
        matches!(self, MilestoneState::Validated)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1Tracker — per-milestone state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the state of every Phase One milestone.
///
/// Stored as a fixed-size array indexed by `Phase1Milestone` (cast to `usize`).
/// Designed to be cheap to copy and `#![no_std]`-friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase1Tracker {
    states: [MilestoneState; PHASE1_MILESTONE_COUNT],
}

/// The number of Phase One milestones.  Compile-time constant.
pub const PHASE1_MILESTONE_COUNT: usize = 11;

impl Phase1Tracker {
    /// A fresh tracker with every milestone `NotStarted`.
    pub const NEW: Self = Self {
        states: [MilestoneState::NotStarted; PHASE1_MILESTONE_COUNT],
    };

    /// Record the state of a single milestone.
    ///
    /// Returns `Err(Phase1Error::PrerequisiteIncomplete)` if the caller tries
    /// to mark a milestone `InProgress` or `Validated` before its prerequisite
    /// is `Validated`.  This enforces the critical-path invariant.
    pub fn set_state(
        &mut self,
        milestone: Phase1Milestone,
        state: MilestoneState,
    ) -> Result<(), Phase1Error> {
        if matches!(state, MilestoneState::InProgress | MilestoneState::Validated) {
            if let Some(prereq) = milestone.prerequisite() {
                if !self.state(prereq).is_validated() {
                    return Err(Phase1Error::PrerequisiteIncomplete {
                        milestone,
                        prerequisite: prereq,
                    });
                }
            }
        }
        self.states[milestone as usize] = state;
        Ok(())
    }

    /// Read the state of a single milestone.
    pub const fn state(&self, milestone: Phase1Milestone) -> MilestoneState {
        self.states[milestone as usize]
    }

    /// Return `true` when every Phase One milestone is `Validated`.
    pub const fn all_validated(&self) -> bool {
        let mut i = 0;
        while i < PHASE1_MILESTONE_COUNT {
            if !matches!(self.states[i], MilestoneState::Validated) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Return the first not-yet-validated milestone, or `None` when complete.
    pub fn first_unvalidated(&self) -> Option<Phase1Milestone> {
        for m in PHASE1_MILESTONES {
            if !self.state(*m).is_validated() {
                return Some(*m);
            }
        }
        None
    }

    /// Return `true` when any milestone is in the `Regressed` state.
    ///
    /// A regression anywhere blocks the Phase One gate even if the final
    /// milestone is currently `Validated` — the chain is only as strong as
    /// its weakest link.
    pub const fn any_regressed(&self) -> bool {
        let mut i = 0;
        while i < PHASE1_MILESTONE_COUNT {
            if matches!(self.states[i], MilestoneState::Regressed) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1TimelineEstimate — optimistic / realistic / pessimistic
// ─────────────────────────────────────────────────────────────────────────────

/// The multiplier applied to optimistic estimates to obtain a realistic one
/// when working part-time alongside a four-year computer science degree.
///
/// See SKILL.md: Claude's project timelines assume full-time dedicated work.
/// AETHER is built in 2–4 hours per weekday + 6–8 hours per weekend during
/// term.  Multiply optimistic estimates by 2–3 for realistic planning.
pub const REALISTIC_MULTIPLIER: u32 = 2;

/// The multiplier for pessimistic estimates.  Use when planning the outer
/// envelope of a phase or when a major dependency (e.g., real hardware) is
/// not yet in hand.
pub const PESSIMISTIC_MULTIPLIER: u32 = 3;

/// A three-point timeline estimate for a single phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase1TimelineEstimate {
    /// Optimistic months (matches the README's stated estimate).
    pub optimistic_months: u32,
    /// Realistic months for part-time work = optimistic × REALISTIC_MULTIPLIER.
    pub realistic_months: u32,
    /// Pessimistic months = optimistic × PESSIMISTIC_MULTIPLIER.
    pub pessimistic_months: u32,
}

impl Phase1TimelineEstimate {
    /// The README estimate: 12–18 months for a dedicated team.
    ///
    /// Optimistic = 12; realistic = 24 (multiplier 2); pessimistic = 36.
    pub const README_DEDICATED_TEAM: Self = Self {
        optimistic_months:  12,
        realistic_months:   12 * REALISTIC_MULTIPLIER,
        pessimistic_months: 12 * PESSIMISTIC_MULTIPLIER,
    };

    /// The upper-bound README estimate: 18 months.  Use when planning the
    /// outer envelope of Phase One.
    pub const README_DEDICATED_TEAM_UPPER: Self = Self {
        optimistic_months:  18,
        realistic_months:   18 * REALISTIC_MULTIPLIER,
        pessimistic_months: 18 * PESSIMISTIC_MULTIPLIER,
    };

    /// Validate the three-point estimate.
    ///
    /// Each estimate must be monotonically non-decreasing
    /// (optimistic ≤ realistic ≤ pessimistic), and none may be zero.
    pub fn validate(&self) -> Result<(), Phase1Error> {
        if self.optimistic_months == 0 {
            return Err(Phase1Error::TimelineEstimateZero);
        }
        if self.realistic_months < self.optimistic_months {
            return Err(Phase1Error::TimelineEstimateMonotonicityViolated);
        }
        if self.pessimistic_months < self.realistic_months {
            return Err(Phase1Error::TimelineEstimateMonotonicityViolated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WeeklyHourBudget — realistic hours for part-time AETHER work
// ─────────────────────────────────────────────────────────────────────────────

/// The weekly hour budget for AETHER work, split between term-time and
/// vacation weeks.
///
/// Deep systems work requires mental bandwidth that is not available after a
/// full day of lectures.  The realistic upper bound during a term week is
/// roughly 2–4 hours per weekday and 6–8 hours per weekend day; during
/// vacation it can climb to 8+ hours every day.  Plans that exceed these
/// bounds rapidly default into "no AETHER work done this week".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeeklyHourBudget {
    /// Hours per weekday during term.  Realistic cap: 4.
    pub term_weekday_hours: u8,
    /// Hours per weekend day during term.  Realistic cap: 8.
    pub term_weekend_hours: u8,
    /// Hours per day during vacation.  Realistic cap: 10.
    pub vacation_daily_hours: u8,
}

impl WeeklyHourBudget {
    /// The default realistic budget for a CS undergraduate during term.
    ///
    /// 2 h × 5 weekdays + 6 h × 2 weekend days = 22 effective hours/week
    /// during term.  Used as the default plan, overridable per individual.
    pub const DEFAULT_TERM: Self = Self {
        term_weekday_hours:   2,
        term_weekend_hours:   6,
        vacation_daily_hours: 8,
    };

    /// Effective hours per term week.
    pub const fn term_weekly_hours(self) -> u32 {
        (self.term_weekday_hours as u32) * 5 + (self.term_weekend_hours as u32) * 2
    }

    /// Effective hours per vacation week.
    pub const fn vacation_weekly_hours(self) -> u32 {
        (self.vacation_daily_hours as u32) * 7
    }

    /// Validate the budget against the realistic caps drawn from SKILL.md.
    ///
    /// Rejects plans that exceed the per-day caps — they are aspirational
    /// rather than realistic and produce schedule slippage.
    pub fn validate(&self) -> Result<(), Phase1Error> {
        if self.term_weekday_hours > 4 {
            return Err(Phase1Error::TermWeekdayHoursUnrealistic {
                hours: self.term_weekday_hours,
                cap:   4,
            });
        }
        if self.term_weekend_hours > 8 {
            return Err(Phase1Error::TermWeekendHoursUnrealistic {
                hours: self.term_weekend_hours,
                cap:   8,
            });
        }
        if self.vacation_daily_hours > 10 {
            return Err(Phase1Error::VacationDailyHoursUnrealistic {
                hours: self.vacation_daily_hours,
                cap:   10,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1GateCriterion — the single-sentence acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// The Phase One gate criterion expressed as four boolean checks.
///
/// All four must be `true` and the gate must explicitly reject workarounds
/// (e.g., "interrupts work in QEMU but not real hardware") — a workaround
/// is not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase1GateCriterion {
    /// The hypervisor boots at EL2 on real Snapdragon X Elite hardware.
    pub el2_boot_on_real_hardware: bool,
    /// A minimal Linux EL1 guest in the Android partition runs and prints
    /// to a passthrough UART.
    pub minimal_linux_guest_running: bool,
    /// The guest owns an exclusive NVMe namespace via passthrough.
    pub nvme_namespace_passthrough_working: bool,
    /// The guest receives at least one interrupt routed through the
    /// hypervisor's GIC virtualization layer.
    pub gic_routing_working: bool,
    /// No "works in QEMU but not on hardware" or other partial-credit
    /// workarounds are accepted as a pass.  Must be `false` for the gate to
    /// be considered honest.
    pub workaround_accepted: bool,
}

impl Phase1GateCriterion {
    /// The state required to pass Phase One: every functional check is `true`
    /// and no workarounds were accepted.
    pub const PASSING: Self = Self {
        el2_boot_on_real_hardware:           true,
        minimal_linux_guest_running:         true,
        nvme_namespace_passthrough_working:  true,
        gic_routing_working:                 true,
        workaround_accepted:                 false,
    };

    /// Return `true` only when every functional check is met and no
    /// workarounds were accepted.
    pub const fn passes(self) -> bool {
        self.el2_boot_on_real_hardware
            && self.minimal_linux_guest_running
            && self.nvme_namespace_passthrough_working
            && self.gic_routing_working
            && !self.workaround_accepted
    }

    /// Validate that the gate criterion has not been compromised by a
    /// workaround.  A workaround means the gate did not actually pass.
    pub fn validate(&self) -> Result<(), Phase1Error> {
        if self.workaround_accepted {
            return Err(Phase1Error::GateWorkaroundAccepted);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1Config — aggregate Phase One configuration + validation
// ─────────────────────────────────────────────────────────────────────────────

/// The aggregate configuration for Phase One.
///
/// `validate()` checks every prerequisite and invariant before Phase One can
/// be considered started or completed.
#[derive(Debug)]
pub struct Phase1Config {
    /// Whether the mandatory 2–4 month research phase is complete.
    pub research:  ResearchPhaseStatus,
    /// The three-point timeline estimate for Phase One.
    pub timeline:  Phase1TimelineEstimate,
    /// The realistic weekly hour budget.
    pub budget:    WeeklyHourBudget,
    /// Per-milestone progress state.
    pub tracker:   Phase1Tracker,
    /// The aggregate development workflow (QEMU + CI + bisection + serial).
    pub workflow:  WorkflowConfig,
    /// The Phase One gate criterion.
    pub gate:      Phase1GateCriterion,
}

impl Phase1Config {
    /// Validate the complete Phase One configuration.
    ///
    /// Checks (in order):
    ///   1. Research phase is complete.
    ///   2. Timeline estimate is monotonic and non-zero.
    ///   3. Weekly hour budget is within realistic caps.
    ///   4. Development workflow is valid (QEMU EL2 + CI + bisection).
    ///   5. No milestone is in the `Regressed` state.
    ///   6. Gate criterion was not satisfied by a workaround.
    pub fn validate(&self) -> Result<(), Phase1Error> {
        self.research.validate()?;
        self.timeline.validate()?;
        self.budget.validate()?;
        self.workflow.validate().map_err(Phase1Error::Workflow)?;
        if self.tracker.any_regressed() {
            return Err(Phase1Error::MilestoneRegressed);
        }
        self.gate.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1Summary — high-level readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Phase One readiness gate.
///
/// `phase1_complete()` returns `true` only when all five pillars are in
/// place: research done, timeline coherent, workflow ready, every milestone
/// validated, and the gate criterion passes without workarounds.
#[derive(Debug)]
pub struct Phase1Summary {
    /// True when the research phase is complete.
    pub research_complete: bool,
    /// True when the timeline estimate is monotonic and non-zero.
    pub timeline_coherent: bool,
    /// True when the development workflow is fully configured.
    pub workflow_ready: bool,
    /// True when every Phase One milestone is `Validated`.
    pub all_milestones_validated: bool,
    /// True when the gate criterion passes without workarounds.
    pub gate_passes: bool,
}

impl Phase1Summary {
    /// Return `true` when Phase One is complete and Phase Two can begin.
    pub fn phase1_complete(&self) -> bool {
        self.research_complete
            && self.timeline_coherent
            && self.workflow_ready
            && self.all_milestones_validated
            && self.gate_passes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase1Error — errors returned by Phase One configuration validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by Phase One configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase1Error {
    /// The mandatory 2–4 month research phase is not complete.
    ///
    /// Phase One implementation cannot honestly begin until the research
    /// phase is complete.  Skipping research produces code that must be
    /// rewritten when missing context is discovered.
    ResearchPhaseIncomplete,
    /// A milestone was advanced to `InProgress` or `Validated` while its
    /// prerequisite was not yet `Validated`.
    ///
    /// Phase One is a single critical-path sequence; out-of-order work
    /// becomes throwaway when the prerequisite later constrains it.
    PrerequisiteIncomplete {
        /// The milestone being advanced.
        milestone: Phase1Milestone,
        /// The prerequisite that is not yet `Validated`.
        prerequisite: Phase1Milestone,
    },
    /// A timeline estimate is zero months.
    TimelineEstimateZero,
    /// Timeline estimates are not monotonically non-decreasing.
    ///
    /// `optimistic ≤ realistic ≤ pessimistic` must hold.
    TimelineEstimateMonotonicityViolated,
    /// Term-week weekday hours exceed the realistic cap of 4.
    TermWeekdayHoursUnrealistic {
        /// Configured hours per weekday during term.
        hours: u8,
        /// Realistic cap (4).
        cap:   u8,
    },
    /// Term-week weekend hours exceed the realistic cap of 8.
    TermWeekendHoursUnrealistic {
        /// Configured hours per weekend day during term.
        hours: u8,
        /// Realistic cap (8).
        cap:   u8,
    },
    /// Vacation daily hours exceed the realistic cap of 10.
    VacationDailyHoursUnrealistic {
        /// Configured hours per day during vacation.
        hours: u8,
        /// Realistic cap (10).
        cap:   u8,
    },
    /// At least one milestone is in the `Regressed` state.
    ///
    /// A regression blocks the Phase One gate.  Fix the regression before
    /// claiming Phase One is complete.
    MilestoneRegressed,
    /// The gate criterion was accepted with a workaround.
    ///
    /// "Works in QEMU but not on hardware" or "interrupts work for some
    /// devices but not others" are not passes — they are deferred bugs.
    GateWorkaroundAccepted,
    /// Wraps a `development_workflow::WorkflowError` from the embedded
    /// workflow configuration.
    Workflow(crate::development_workflow::WorkflowError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::development_workflow::WorkflowConfig;

    // ── ResearchPhaseStatus ───────────────────────────────────────────────────

    #[test]
    fn research_complete_is_complete() {
        assert!(ResearchPhaseStatus::COMPLETE.is_complete());
    }

    #[test]
    fn research_not_started_is_not_complete() {
        assert!(!ResearchPhaseStatus::NOT_STARTED.is_complete());
    }

    #[test]
    fn research_missing_journal_is_not_complete() {
        let r = ResearchPhaseStatus {
            project_journal_started: false,
            ..ResearchPhaseStatus::COMPLETE
        };
        assert!(!r.is_complete());
    }

    #[test]
    fn research_validate_complete_ok() {
        assert!(ResearchPhaseStatus::COMPLETE.validate().is_ok());
    }

    #[test]
    fn research_validate_not_started_rejected() {
        assert_eq!(
            ResearchPhaseStatus::NOT_STARTED.validate(),
            Err(Phase1Error::ResearchPhaseIncomplete)
        );
    }

    // ── Phase1Milestone ───────────────────────────────────────────────────────

    #[test]
    fn first_milestone_has_no_prerequisite() {
        assert_eq!(Phase1Milestone::Arm64SubstrateReady.prerequisite(), None);
    }

    #[test]
    fn every_other_milestone_has_a_prerequisite() {
        for m in PHASE1_MILESTONES.iter().skip(1) {
            assert!(m.prerequisite().is_some(), "{:?} missing prerequisite", m);
        }
    }

    #[test]
    fn milestone_chain_is_linear() {
        // Walking prerequisites from the last milestone must hit every
        // milestone in PHASE1_MILESTONES exactly once.
        let mut visited = 0;
        let mut cur = Some(*PHASE1_MILESTONES.last().unwrap());
        while let Some(m) = cur {
            visited += 1;
            cur = m.prerequisite();
        }
        assert_eq!(visited, PHASE1_MILESTONE_COUNT);
    }

    #[test]
    fn final_milestone_requires_real_hardware() {
        assert_eq!(
            Phase1Milestone::MinimalLinuxGuestOnHardware.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn linux_guest_in_qemu_uses_tier2() {
        assert_eq!(
            Phase1Milestone::MinimalLinuxGuestInQemu.validation_tier(),
            TestTier::QemuLinuxGuest
        );
    }

    #[test]
    fn early_milestones_validate_in_qemu_minimal() {
        assert_eq!(
            Phase1Milestone::Arm64SubstrateReady.validation_tier(),
            TestTier::QemuMinimal
        );
        assert_eq!(
            Phase1Milestone::GicVirtualizationWorking.validation_tier(),
            TestTier::QemuMinimal
        );
    }

    #[test]
    fn milestone_labels_are_nonempty() {
        for m in PHASE1_MILESTONES {
            assert!(!m.label().is_empty());
        }
    }

    // ── MilestoneState ────────────────────────────────────────────────────────

    #[test]
    fn only_validated_state_is_validated() {
        assert!(MilestoneState::Validated.is_validated());
        assert!(!MilestoneState::NotStarted.is_validated());
        assert!(!MilestoneState::InProgress.is_validated());
        assert!(!MilestoneState::Regressed.is_validated());
    }

    // ── Phase1Tracker ─────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_all_not_started() {
        let t = Phase1Tracker::NEW;
        for m in PHASE1_MILESTONES {
            assert_eq!(t.state(*m), MilestoneState::NotStarted);
        }
    }

    #[test]
    fn first_milestone_can_be_set_without_prerequisite() {
        let mut t = Phase1Tracker::NEW;
        assert!(t.set_state(Phase1Milestone::Arm64SubstrateReady, MilestoneState::Validated).is_ok());
    }

    #[test]
    fn cannot_advance_to_in_progress_without_prerequisite() {
        let mut t = Phase1Tracker::NEW;
        let r = t.set_state(Phase1Milestone::ExceptionHandlingReady, MilestoneState::InProgress);
        assert_eq!(
            r,
            Err(Phase1Error::PrerequisiteIncomplete {
                milestone:    Phase1Milestone::ExceptionHandlingReady,
                prerequisite: Phase1Milestone::Arm64SubstrateReady,
            })
        );
    }

    #[test]
    fn cannot_advance_to_validated_without_prerequisite() {
        let mut t = Phase1Tracker::NEW;
        let r = t.set_state(Phase1Milestone::Stage2TranslationActive, MilestoneState::Validated);
        assert_eq!(
            r,
            Err(Phase1Error::PrerequisiteIncomplete {
                milestone:    Phase1Milestone::Stage2TranslationActive,
                prerequisite: Phase1Milestone::ExceptionHandlingReady,
            })
        );
    }

    #[test]
    fn can_mark_not_started_or_regressed_without_prerequisite() {
        // Resetting a milestone or recording a regression must not require the
        // prerequisite — those states are not advances.
        let mut t = Phase1Tracker::NEW;
        assert!(t.set_state(Phase1Milestone::GicVirtualizationWorking, MilestoneState::NotStarted).is_ok());
        assert!(t.set_state(Phase1Milestone::GicVirtualizationWorking, MilestoneState::Regressed).is_ok());
    }

    #[test]
    fn linear_progression_validates_every_milestone() {
        let mut t = Phase1Tracker::NEW;
        for m in PHASE1_MILESTONES {
            t.set_state(*m, MilestoneState::Validated).expect("linear progression must succeed");
        }
        assert!(t.all_validated());
        assert_eq!(t.first_unvalidated(), None);
    }

    #[test]
    fn first_unvalidated_finds_the_blocker() {
        let mut t = Phase1Tracker::NEW;
        t.set_state(Phase1Milestone::Arm64SubstrateReady, MilestoneState::Validated).unwrap();
        t.set_state(Phase1Milestone::ExceptionHandlingReady, MilestoneState::Validated).unwrap();
        t.set_state(Phase1Milestone::Stage2TranslationActive, MilestoneState::InProgress).unwrap();
        assert_eq!(
            t.first_unvalidated(),
            Some(Phase1Milestone::Stage2TranslationActive)
        );
    }

    #[test]
    fn any_regressed_detects_a_regression() {
        let mut t = Phase1Tracker::NEW;
        t.set_state(Phase1Milestone::Arm64SubstrateReady, MilestoneState::Validated).unwrap();
        t.set_state(Phase1Milestone::Arm64SubstrateReady, MilestoneState::Regressed).unwrap();
        assert!(t.any_regressed());
    }

    #[test]
    fn no_regression_in_fresh_tracker() {
        assert!(!Phase1Tracker::NEW.any_regressed());
    }

    // ── Phase1TimelineEstimate ────────────────────────────────────────────────

    #[test]
    fn readme_estimate_validates_ok() {
        assert!(Phase1TimelineEstimate::README_DEDICATED_TEAM.validate().is_ok());
    }

    #[test]
    fn readme_upper_estimate_validates_ok() {
        assert!(Phase1TimelineEstimate::README_DEDICATED_TEAM_UPPER.validate().is_ok());
    }

    #[test]
    fn realistic_is_double_optimistic() {
        let e = Phase1TimelineEstimate::README_DEDICATED_TEAM;
        assert_eq!(e.realistic_months, e.optimistic_months * REALISTIC_MULTIPLIER);
    }

    #[test]
    fn pessimistic_is_triple_optimistic() {
        let e = Phase1TimelineEstimate::README_DEDICATED_TEAM;
        assert_eq!(e.pessimistic_months, e.optimistic_months * PESSIMISTIC_MULTIPLIER);
    }

    #[test]
    fn zero_optimistic_rejected() {
        let e = Phase1TimelineEstimate {
            optimistic_months: 0,
            realistic_months:  0,
            pessimistic_months: 0,
        };
        assert_eq!(e.validate(), Err(Phase1Error::TimelineEstimateZero));
    }

    #[test]
    fn nonmonotonic_estimate_rejected() {
        let e = Phase1TimelineEstimate {
            optimistic_months:  12,
            realistic_months:   6,
            pessimistic_months: 36,
        };
        assert_eq!(e.validate(), Err(Phase1Error::TimelineEstimateMonotonicityViolated));
    }

    #[test]
    fn pessimistic_below_realistic_rejected() {
        let e = Phase1TimelineEstimate {
            optimistic_months:  12,
            realistic_months:   24,
            pessimistic_months: 18,
        };
        assert_eq!(e.validate(), Err(Phase1Error::TimelineEstimateMonotonicityViolated));
    }

    // ── WeeklyHourBudget ──────────────────────────────────────────────────────

    #[test]
    fn default_term_validates_ok() {
        assert!(WeeklyHourBudget::DEFAULT_TERM.validate().is_ok());
    }

    #[test]
    fn term_weekly_hours_computed() {
        let b = WeeklyHourBudget::DEFAULT_TERM;
        // 2 h × 5 weekdays + 6 h × 2 weekend days = 22 h/week
        assert_eq!(b.term_weekly_hours(), 22);
    }

    #[test]
    fn vacation_weekly_hours_computed() {
        let b = WeeklyHourBudget::DEFAULT_TERM;
        // 8 h × 7 days = 56 h/week
        assert_eq!(b.vacation_weekly_hours(), 56);
    }

    #[test]
    fn weekday_hours_above_cap_rejected() {
        let b = WeeklyHourBudget {
            term_weekday_hours: 5, // cap is 4
            ..WeeklyHourBudget::DEFAULT_TERM
        };
        assert_eq!(
            b.validate(),
            Err(Phase1Error::TermWeekdayHoursUnrealistic { hours: 5, cap: 4 })
        );
    }

    #[test]
    fn weekend_hours_above_cap_rejected() {
        let b = WeeklyHourBudget {
            term_weekend_hours: 9, // cap is 8
            ..WeeklyHourBudget::DEFAULT_TERM
        };
        assert_eq!(
            b.validate(),
            Err(Phase1Error::TermWeekendHoursUnrealistic { hours: 9, cap: 8 })
        );
    }

    #[test]
    fn vacation_hours_above_cap_rejected() {
        let b = WeeklyHourBudget {
            vacation_daily_hours: 11, // cap is 10
            ..WeeklyHourBudget::DEFAULT_TERM
        };
        assert_eq!(
            b.validate(),
            Err(Phase1Error::VacationDailyHoursUnrealistic { hours: 11, cap: 10 })
        );
    }

    // ── Phase1GateCriterion ───────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(Phase1GateCriterion::PASSING.passes());
    }

    #[test]
    fn passing_gate_validates_ok() {
        assert!(Phase1GateCriterion::PASSING.validate().is_ok());
    }

    #[test]
    fn workaround_fails_gate() {
        let g = Phase1GateCriterion {
            workaround_accepted: true,
            ..Phase1GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase1Error::GateWorkaroundAccepted));
    }

    #[test]
    fn missing_el2_boot_fails_gate() {
        let g = Phase1GateCriterion {
            el2_boot_on_real_hardware: false,
            ..Phase1GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_nvme_fails_gate() {
        let g = Phase1GateCriterion {
            nvme_namespace_passthrough_working: false,
            ..Phase1GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_gic_fails_gate() {
        let g = Phase1GateCriterion {
            gic_routing_working: false,
            ..Phase1GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    // ── Phase1Config ──────────────────────────────────────────────────────────

    fn fully_validated_tracker() -> Phase1Tracker {
        let mut t = Phase1Tracker::NEW;
        for m in PHASE1_MILESTONES {
            t.set_state(*m, MilestoneState::Validated).unwrap();
        }
        t
    }

    fn passing_config() -> Phase1Config {
        Phase1Config {
            research: ResearchPhaseStatus::COMPLETE,
            timeline: Phase1TimelineEstimate::README_DEDICATED_TEAM,
            budget:   WeeklyHourBudget::DEFAULT_TERM,
            tracker:  fully_validated_tracker(),
            workflow: WorkflowConfig::RECOMMENDED,
            gate:     Phase1GateCriterion::PASSING,
        }
    }

    #[test]
    fn passing_config_validates_ok() {
        assert!(passing_config().validate().is_ok());
    }

    #[test]
    fn config_rejects_incomplete_research() {
        let cfg = Phase1Config {
            research: ResearchPhaseStatus::NOT_STARTED,
            ..passing_config()
        };
        assert_eq!(cfg.validate(), Err(Phase1Error::ResearchPhaseIncomplete));
    }

    #[test]
    fn config_rejects_regression() {
        let mut tracker = fully_validated_tracker();
        tracker
            .set_state(Phase1Milestone::GicVirtualizationWorking, MilestoneState::Regressed)
            .unwrap();
        let cfg = Phase1Config {
            tracker,
            ..passing_config()
        };
        assert_eq!(cfg.validate(), Err(Phase1Error::MilestoneRegressed));
    }

    #[test]
    fn config_rejects_gate_workaround() {
        let cfg = Phase1Config {
            gate: Phase1GateCriterion {
                workaround_accepted: true,
                ..Phase1GateCriterion::PASSING
            },
            ..passing_config()
        };
        assert_eq!(cfg.validate(), Err(Phase1Error::GateWorkaroundAccepted));
    }

    // ── Phase1Summary ─────────────────────────────────────────────────────────

    #[test]
    fn phase1_summary_complete() {
        let s = Phase1Summary {
            research_complete:          true,
            timeline_coherent:          true,
            workflow_ready:             true,
            all_milestones_validated:   true,
            gate_passes:                true,
        };
        assert!(s.phase1_complete());
    }

    #[test]
    fn phase1_summary_partial_not_complete() {
        let cases = [
            Phase1Summary { research_complete: false, timeline_coherent: true,  workflow_ready: true,  all_milestones_validated: true,  gate_passes: true  },
            Phase1Summary { research_complete: true,  timeline_coherent: false, workflow_ready: true,  all_milestones_validated: true,  gate_passes: true  },
            Phase1Summary { research_complete: true,  timeline_coherent: true,  workflow_ready: false, all_milestones_validated: true,  gate_passes: true  },
            Phase1Summary { research_complete: true,  timeline_coherent: true,  workflow_ready: true,  all_milestones_validated: false, gate_passes: true  },
            Phase1Summary { research_complete: true,  timeline_coherent: true,  workflow_ready: true,  all_milestones_validated: true,  gate_passes: false },
        ];
        for s in &cases {
            assert!(!s.phase1_complete(), "expected not-complete for {:?}", s);
        }
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn milestone_count_matches_list_length() {
        assert_eq!(PHASE1_MILESTONES.len(), PHASE1_MILESTONE_COUNT);
    }

    #[test]
    fn realistic_multiplier_is_two() {
        assert_eq!(REALISTIC_MULTIPLIER, 2);
    }

    #[test]
    fn pessimistic_multiplier_is_three() {
        assert_eq!(PESSIMISTIC_MULTIPLIER, 3);
    }
}
