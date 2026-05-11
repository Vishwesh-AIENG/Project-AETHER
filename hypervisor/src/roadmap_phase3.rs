// ch31: Phase Three — x86 Tier Foundation
//
// Phase Three ports AETHER to Intel and AMD hardware.  The ARM-tier hypervisor
// produced by Phase One executes ARM64 directly at EL2; the x86-tier
// hypervisor produced by Phase Three executes at VMX-root / SVM-host and
// runs Android through the FEX-Emu dynamic binary translation engine that is
// integrated inside the hypervisor itself.
//
// README estimate: 12 months for a dedicated team; multiply by 2–3 for
// part-time work.
//
// ── Phase Three Definition ────────────────────────────────────────────────────
//
// Phase Three produces a hypervisor that:
//
//   - Boots on Intel (VT-x) and AMD (SVM) hardware in VMX-root / SVM-host
//     mode
//   - Initializes the VMCS (Intel) or VMCB (AMD) for an ARM64 Android guest
//   - Builds EPT (Intel) or NPT (AMD) translation tables that enforce the
//     same isolation Stage 2 does on ARM
//   - Integrates the FEX-Emu DBT engine (ARM64 → x86) inside the hypervisor
//     address space, with no host OS underneath
//   - Boots a full Android image inside the DBT layer
//   - Validates core applications run through the translation layer
//   - The x86 Tier architecture is end-to-end validated on real hardware
//
// Phase Three does NOT require parity with Phase Two on the ARM tier.
// SR-IOV GPU passthrough, dedicated NIC, and other hardware features that
// depend on platform-specific BIOS support are deferred to Phase Four
// performance tuning.
//
// ── Entry Gate: Phase Two Complete ────────────────────────────────────────────
//
// Phase Three should not begin until Phase Two is closed.  The ARM tier is
// the reference implementation; bugs found during the x86 port often reveal
// underlying issues in the ARM tier that are easier to fix with the ARM
// hypervisor as the reference.  Starting Phase Three in parallel with an
// incomplete Phase Two produces twice the work.
//
// ── x86 Hypervisor Mode (VMX-Root / SVM-Host) ─────────────────────────────────
//
// On x86, the hypervisor runs in VMX-root mode (Intel) or SVM-host mode
// (AMD).  Both are roughly equivalent to ARM's EL2 — a privilege level
// strictly above the guest OS.  There is no host OS underneath; AETHER takes
// over from UEFI and never returns.
//
// The two flavors differ only in the control structure name:
//   - Intel VT-x → VMCS (VM Control Structure), accessed via VMREAD/VMWRITE
//   - AMD SVM   → VMCB (VM Control Block),     a 4 KiB MMIO-style region
//
// `X86VirtualizationFlavor` captures the distinction; the rest of the
// hypervisor treats them uniformly.
//
// ── EPT / NPT Mapping ─────────────────────────────────────────────────────────
//
// The Stage 2 page tables AETHER builds on ARM (IPA → PA) have direct x86
// counterparts:
//   - Intel: EPT (Extended Page Tables; guest physical → host physical)
//   - AMD:   NPT (Nested Page Tables; same semantics, different encoding)
//
// The semantics are identical to Stage 2: a second translation stage that
// the guest cannot see or modify, owned exclusively by the hypervisor.
//
// ── FEX-Emu Integration ───────────────────────────────────────────────────────
//
// FEX-Emu is an open-source ARM64 → x86 dynamic binary translator.  In the
// AETHER architecture, FEX is linked into the hypervisor address space and
// runs in VMX-root mode alongside the rest of AETHER.  The Android guest
// sees an ARM64 environment; FEX translates ARM64 instructions to x86 at
// runtime and the translated code executes at VMX non-root level.
//
// This is structurally different from running FEX as a userspace program on
// a host Linux kernel.  No host kernel exists.  FEX is part of the
// hypervisor.
//
// ── Realistic Time Accounting ─────────────────────────────────────────────────
//
// 12 months optimistic → 24 months realistic → 36 months pessimistic.
// The x86 port is roughly equal in effort to Phase One: it is, in effect,
// "Phase One again on a different ISA".

use crate::development_workflow::TestTier;
use crate::roadmap_phase1::{PESSIMISTIC_MULTIPLIER, REALISTIC_MULTIPLIER};
use crate::roadmap_phase2::Phase2Summary;

// ─────────────────────────────────────────────────────────────────────────────
// X86VirtualizationFlavor — Intel VT-x vs AMD SVM
// ─────────────────────────────────────────────────────────────────────────────

/// The two x86 hardware virtualization extensions AETHER supports.
///
/// Intel's VT-x and AMD's SVM are functionally equivalent but use different
/// control structures, register names, and instruction encodings.  AETHER's
/// x86-tier hypervisor implements both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86VirtualizationFlavor {
    /// Intel VT-x.  Hypervisor runs in VMX-root mode.  Control structure
    /// is the 4 KiB VMCS, accessed via the `VMREAD` / `VMWRITE` instructions
    /// (no plain memory access).  Memory translation uses Extended Page
    /// Tables (EPT).
    IntelVtx,
    /// AMD SVM.  Hypervisor runs in SVM-host mode.  Control structure is the
    /// 4 KiB VMCB, accessed as a normal MMIO-style region.  Memory
    /// translation uses Nested Page Tables (NPT).
    AmdSvm,
}

impl X86VirtualizationFlavor {
    /// The name of the per-vCPU control structure on this flavor.
    pub const fn control_structure_name(self) -> &'static str {
        match self {
            X86VirtualizationFlavor::IntelVtx => "VMCS",
            X86VirtualizationFlavor::AmdSvm   => "VMCB",
        }
    }

    /// The name of the second-stage page table on this flavor.
    pub const fn second_stage_table_name(self) -> &'static str {
        match self {
            X86VirtualizationFlavor::IntelVtx => "EPT",
            X86VirtualizationFlavor::AmdSvm   => "NPT",
        }
    }

    /// The privilege mode AETHER occupies on this flavor (informational).
    pub const fn hypervisor_mode_name(self) -> &'static str {
        match self {
            X86VirtualizationFlavor::IntelVtx => "VMX-root",
            X86VirtualizationFlavor::AmdSvm   => "SVM-host",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecondStageTableConfig — EPT / NPT configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the x86 second-stage translation tables (EPT or NPT).
///
/// The semantics mirror ARM Stage 2: a guest-physical → host-physical
/// translation owned exclusively by the hypervisor.  Page size is 4 KiB by
/// default to match the ARM tier; 2 MiB and 1 GiB large pages are used where
/// the guest mapping permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondStageTableConfig {
    /// The virtualization flavor (determines EPT vs NPT encoding).
    pub flavor: X86VirtualizationFlavor,
    /// Whether 4-level paging is used (5-level paging is the alternative
    /// on Intel Sapphire Rapids and later).  AETHER targets 4-level paging
    /// initially; 5-level is a Phase Four optimization.
    pub four_level_paging: bool,
    /// Whether `EPT.Accessed` / `EPT.Dirty` bits are enabled.
    ///
    /// Required for the Spectre / branch-target-injection mitigations to
    /// work correctly on Intel.  Set `true` for any production build.
    pub accessed_dirty_bits_enabled: bool,
    /// Whether the `INVEPT` / `INVNPT` instruction is issued after every
    /// guest-physical mapping change.
    ///
    /// Must be `true`.  Skipping the invalidation produces stale TLB entries
    /// that can leak data across guests or between hypervisor and guest.
    pub invalidate_on_mapping_change: bool,
}

impl SecondStageTableConfig {
    /// Production configuration for Intel VT-x.
    pub const INTEL_PRODUCTION: Self = Self {
        flavor:                       X86VirtualizationFlavor::IntelVtx,
        four_level_paging:            true,
        accessed_dirty_bits_enabled:  true,
        invalidate_on_mapping_change: true,
    };

    /// Production configuration for AMD SVM.
    pub const AMD_PRODUCTION: Self = Self {
        flavor:                       X86VirtualizationFlavor::AmdSvm,
        four_level_paging:            true,
        accessed_dirty_bits_enabled:  true,
        invalidate_on_mapping_change: true,
    };

    /// Validate the second-stage table configuration.
    pub fn validate(&self) -> Result<(), Phase3Error> {
        if !self.four_level_paging {
            return Err(Phase3Error::PagingLevelUnsupported);
        }
        if !self.invalidate_on_mapping_change {
            return Err(Phase3Error::SecondStageTlbInvalidationDisabled);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FexEmuIntegration — FEX-Emu DBT integration mode
// ─────────────────────────────────────────────────────────────────────────────

/// How the FEX-Emu DBT engine is integrated with AETHER on the x86 tier.
///
/// On the ARM tier this enum has no meaning — Android executes natively at
/// EL1.  On the x86 tier, every ARM64 instruction the guest executes is
/// translated to x86 at runtime by FEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FexEmuIntegrationMode {
    /// FEX-Emu runs inside the hypervisor address space (no host OS).
    ///
    /// This is the only valid mode for AETHER's x86 tier.  FEX shares the
    /// hypervisor's address space and runs in VMX-root / SVM-host mode.
    InHypervisor,
    /// FEX-Emu runs as a host-userland program.
    ///
    /// **Rejected by AETHER.**  This is the upstream FEX deployment model;
    /// it requires a host Linux kernel underneath, which violates the
    /// No-Boundary Principle.  Listed here only so the type system can
    /// reject it at configuration time.
    HostUserland,
}

impl FexEmuIntegrationMode {
    /// Return `true` when this integration mode is acceptable for AETHER's
    /// no-host-OS architecture.
    pub const fn is_no_host_os_compatible(self) -> bool {
        matches!(self, FexEmuIntegrationMode::InHypervisor)
    }
}

/// Configuration for the FEX-Emu DBT engine on the x86 tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FexEmuConfig {
    /// Integration mode — must be `InHypervisor` for AETHER.
    pub mode: FexEmuIntegrationMode,
    /// Whether the JIT cache is persisted across guest reboots.
    ///
    /// Persisted caches dramatically reduce cold-boot translation overhead
    /// at the cost of a small disk footprint.  Recommended `true` for
    /// production.
    pub persist_jit_cache: bool,
    /// Whether AOT (ahead-of-time) translation is enabled for hot ARM64
    /// binaries shipped in the Android image.  Recommended `true` for
    /// production to avoid first-run JIT latency on system apps.
    pub aot_translation_enabled: bool,
}

impl FexEmuConfig {
    /// Production FEX configuration for the x86 tier.
    pub const PRODUCTION: Self = Self {
        mode:                    FexEmuIntegrationMode::InHypervisor,
        persist_jit_cache:       true,
        aot_translation_enabled: true,
    };

    /// Validate that the FEX integration is acceptable for AETHER.
    pub fn validate(&self) -> Result<(), Phase3Error> {
        if !self.mode.is_no_host_os_compatible() {
            return Err(Phase3Error::FexEmuRequiresHostOs);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3Milestone — the discrete milestones inside Phase Three
// ─────────────────────────────────────────────────────────────────────────────

/// A single milestone within Phase Three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase3Milestone {
    /// Phase Two complete on the ARM tier.  Entry gate to Phase Three.
    Phase2GateClosed,
    /// CPUID / cpu-feature probe confirms VMX (Intel) or SVM (AMD) is
    /// available and enabled in BIOS firmware.  Without this, the host
    /// cannot enter VMX-root / SVM-host mode at all.
    VmxOrSvmAvailable,
    /// AETHER successfully executes `VMXON` (Intel) or sets `EFER.SVME`
    /// (AMD) and enters root / host mode.  At this point the hypervisor
    /// controls the CPU.
    HypervisorEntersRootMode,
    /// VMCS (Intel) / VMCB (AMD) is initialized for the Android guest.
    /// Host-state and guest-state areas are populated with sane defaults.
    VmcsVmcbInitialized,
    /// EPT (Intel) / NPT (AMD) tables map the guest's full IPA window to
    /// host physical addresses.  TLB invalidation policy enforced.
    EptOrNptActive,
    /// FEX-Emu DBT engine is linked into the hypervisor address space and
    /// boots a "Hello world" ARM64 binary through the translation layer.
    FexEmuExecutesArm64Binary,
    /// The Linux kernel boots inside the Android partition via FEX.
    /// The kernel's ARM64 instructions are translated to x86 at runtime
    /// and the kernel reaches `start_kernel`.
    LinuxKernelBootsThroughDbt,
    /// Android userspace boots through the DBT layer; `init` runs, system
    /// services start, the framework is up.  Shell-only; no GPU yet.
    AndroidUserspaceBootsThroughDbt,
    /// Core applications validated through the translation layer.  At least
    /// one application from each of the Phase Two hard-requirement
    /// categories runs.  Performance is not yet tuned (that is Phase Four).
    CoreAppsValidatedThroughDbt,
    /// x86 Tier validated end to end on real Intel and AMD hardware.
    /// Closes Phase Three.
    X86TierValidatedOnHardware,
}

impl Phase3Milestone {
    /// The strict prerequisite milestone, or `None` for the first.
    pub const fn prerequisite(self) -> Option<Phase3Milestone> {
        use Phase3Milestone::*;
        match self {
            Phase2GateClosed                  => None,
            VmxOrSvmAvailable                 => Some(Phase2GateClosed),
            HypervisorEntersRootMode          => Some(VmxOrSvmAvailable),
            VmcsVmcbInitialized               => Some(HypervisorEntersRootMode),
            EptOrNptActive                    => Some(VmcsVmcbInitialized),
            FexEmuExecutesArm64Binary         => Some(EptOrNptActive),
            LinuxKernelBootsThroughDbt        => Some(FexEmuExecutesArm64Binary),
            AndroidUserspaceBootsThroughDbt   => Some(LinuxKernelBootsThroughDbt),
            CoreAppsValidatedThroughDbt       => Some(AndroidUserspaceBootsThroughDbt),
            X86TierValidatedOnHardware        => Some(CoreAppsValidatedThroughDbt),
        }
    }

    /// The development tier at which this milestone is first validated.
    pub const fn validation_tier(self) -> TestTier {
        use Phase3Milestone::*;
        match self {
            X86TierValidatedOnHardware => TestTier::RealHardware,
            // Most Phase 3 milestones go through the QEMU Tier-2 loop with
            // a Linux/Android guest running through FEX.  QEMU is used as
            // the x86 host emulator with KVM acceleration where possible.
            _                          => TestTier::QemuLinuxGuest,
        }
    }

    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        use Phase3Milestone::*;
        match self {
            Phase2GateClosed                => "Phase 2 gate closed",
            VmxOrSvmAvailable               => "VT-x / SVM available",
            HypervisorEntersRootMode        => "hypervisor enters root mode",
            VmcsVmcbInitialized             => "VMCS / VMCB initialized",
            EptOrNptActive                  => "EPT / NPT active",
            FexEmuExecutesArm64Binary       => "FEX-Emu executes ARM64 binary",
            LinuxKernelBootsThroughDbt      => "Linux kernel boots through DBT",
            AndroidUserspaceBootsThroughDbt => "Android userspace boots through DBT",
            CoreAppsValidatedThroughDbt     => "core apps validated through DBT",
            X86TierValidatedOnHardware      => "x86 tier validated on hardware",
        }
    }
}

/// The number of Phase Three milestones.
pub const PHASE3_MILESTONE_COUNT: usize = 10;

/// The complete ordered sequence of Phase Three milestones.
pub const PHASE3_MILESTONES: &[Phase3Milestone] = &[
    Phase3Milestone::Phase2GateClosed,
    Phase3Milestone::VmxOrSvmAvailable,
    Phase3Milestone::HypervisorEntersRootMode,
    Phase3Milestone::VmcsVmcbInitialized,
    Phase3Milestone::EptOrNptActive,
    Phase3Milestone::FexEmuExecutesArm64Binary,
    Phase3Milestone::LinuxKernelBootsThroughDbt,
    Phase3Milestone::AndroidUserspaceBootsThroughDbt,
    Phase3Milestone::CoreAppsValidatedThroughDbt,
    Phase3Milestone::X86TierValidatedOnHardware,
];

// ─────────────────────────────────────────────────────────────────────────────
// Phase3MilestoneState + Phase3Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// The lifecycle state of a single Phase Three milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase3MilestoneState {
    /// Work has not begun.
    NotStarted,
    /// Work is underway but validation has not passed cleanly.
    InProgress,
    /// Validation tier passed cleanly without workarounds.
    Validated,
    /// Previously `Validated` but later regressed.
    Regressed,
}

impl Phase3MilestoneState {
    /// Return `true` only when the milestone passes its validation tier today.
    pub const fn is_validated(self) -> bool {
        matches!(self, Phase3MilestoneState::Validated)
    }
}

/// Tracks the state of every Phase Three milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase3Tracker {
    states: [Phase3MilestoneState; PHASE3_MILESTONE_COUNT],
}

impl Phase3Tracker {
    /// A fresh tracker with every milestone `NotStarted`.
    pub const NEW: Self = Self {
        states: [Phase3MilestoneState::NotStarted; PHASE3_MILESTONE_COUNT],
    };

    /// Record the state of a single milestone.
    pub fn set_state(
        &mut self,
        milestone: Phase3Milestone,
        state: Phase3MilestoneState,
    ) -> Result<(), Phase3Error> {
        if matches!(state, Phase3MilestoneState::InProgress | Phase3MilestoneState::Validated) {
            if let Some(prereq) = milestone.prerequisite() {
                if !self.state(prereq).is_validated() {
                    return Err(Phase3Error::PrerequisiteIncomplete {
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
    pub const fn state(&self, milestone: Phase3Milestone) -> Phase3MilestoneState {
        self.states[milestone as usize]
    }

    /// Return `true` when every milestone is `Validated`.
    pub const fn all_validated(&self) -> bool {
        let mut i = 0;
        while i < PHASE3_MILESTONE_COUNT {
            if !matches!(self.states[i], Phase3MilestoneState::Validated) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Return the first not-yet-validated milestone.
    pub fn first_unvalidated(&self) -> Option<Phase3Milestone> {
        for m in PHASE3_MILESTONES {
            if !self.state(*m).is_validated() {
                return Some(*m);
            }
        }
        None
    }

    /// Return `true` when any milestone is in the `Regressed` state.
    pub const fn any_regressed(&self) -> bool {
        let mut i = 0;
        while i < PHASE3_MILESTONE_COUNT {
            if matches!(self.states[i], Phase3MilestoneState::Regressed) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3TimelineEstimate — README estimate with realistic multipliers
// ─────────────────────────────────────────────────────────────────────────────

/// A three-point timeline estimate for Phase Three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase3TimelineEstimate {
    /// Optimistic months (matches the README's stated estimate).
    pub optimistic_months: u32,
    /// Realistic months = optimistic × REALISTIC_MULTIPLIER.
    pub realistic_months: u32,
    /// Pessimistic months = optimistic × PESSIMISTIC_MULTIPLIER.
    pub pessimistic_months: u32,
}

impl Phase3TimelineEstimate {
    /// README estimate: 12 months for a dedicated team.
    pub const README_DEDICATED_TEAM: Self = Self {
        optimistic_months:  12,
        realistic_months:   12 * REALISTIC_MULTIPLIER,
        pessimistic_months: 12 * PESSIMISTIC_MULTIPLIER,
    };

    /// Validate non-zero and monotonic.
    pub fn validate(&self) -> Result<(), Phase3Error> {
        if self.optimistic_months == 0 {
            return Err(Phase3Error::TimelineEstimateZero);
        }
        if self.realistic_months < self.optimistic_months
            || self.pessimistic_months < self.realistic_months
        {
            return Err(Phase3Error::TimelineEstimateMonotonicityViolated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3GateCriterion — the Phase Three acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// The Phase Three acceptance test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase3GateCriterion {
    /// AETHER boots into VMX-root mode on a real Intel CPU.
    pub intel_vtx_boot_on_real_hardware: bool,
    /// AETHER boots into SVM-host mode on a real AMD CPU.
    ///
    /// Both Intel and AMD must work — supporting only one is half the gate.
    pub amd_svm_boot_on_real_hardware: bool,
    /// Android boots through FEX-Emu inside the hypervisor.
    pub android_runs_through_dbt: bool,
    /// At least one app per Phase 2 hard-requirement category runs through
    /// the DBT layer.
    pub core_apps_run_through_dbt: bool,
    /// EPT / NPT TLB invalidation is enforced on every mapping change.
    pub ept_npt_invalidation_enforced: bool,
    /// FEX-Emu runs inside the hypervisor — no host OS.
    pub fex_in_hypervisor: bool,
    /// No "works in QEMU but not on real hardware" workarounds were accepted.
    pub workaround_accepted: bool,
}

impl Phase3GateCriterion {
    /// The state required to pass Phase Three.
    pub const PASSING: Self = Self {
        intel_vtx_boot_on_real_hardware: true,
        amd_svm_boot_on_real_hardware:   true,
        android_runs_through_dbt:        true,
        core_apps_run_through_dbt:       true,
        ept_npt_invalidation_enforced:   true,
        fex_in_hypervisor:               true,
        workaround_accepted:             false,
    };

    /// Return `true` only when every check is met and no workaround accepted.
    pub const fn passes(self) -> bool {
        self.intel_vtx_boot_on_real_hardware
            && self.amd_svm_boot_on_real_hardware
            && self.android_runs_through_dbt
            && self.core_apps_run_through_dbt
            && self.ept_npt_invalidation_enforced
            && self.fex_in_hypervisor
            && !self.workaround_accepted
    }

    /// Validate the gate criterion.
    pub fn validate(&self) -> Result<(), Phase3Error> {
        if self.workaround_accepted {
            return Err(Phase3Error::GateWorkaroundAccepted);
        }
        if !self.fex_in_hypervisor {
            return Err(Phase3Error::FexEmuRequiresHostOs);
        }
        if !self.ept_npt_invalidation_enforced {
            return Err(Phase3Error::SecondStageTlbInvalidationDisabled);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3Config — aggregate configuration + validation
// ─────────────────────────────────────────────────────────────────────────────

/// The aggregate configuration for Phase Three.
#[derive(Debug)]
pub struct Phase3Config {
    /// Phase Two readiness — Phase Three cannot start until Phase Two closes.
    pub phase2: Phase2Summary,
    /// Three-point timeline estimate.
    pub timeline: Phase3TimelineEstimate,
    /// Second-stage page table configuration (EPT or NPT).
    pub second_stage: SecondStageTableConfig,
    /// FEX-Emu integration configuration.
    pub fex: FexEmuConfig,
    /// Per-milestone progress state.
    pub tracker: Phase3Tracker,
    /// The Phase Three gate criterion.
    pub gate: Phase3GateCriterion,
}

impl Phase3Config {
    /// Validate the complete Phase Three configuration.
    pub fn validate(&self) -> Result<(), Phase3Error> {
        if !self.phase2.phase2_complete() {
            return Err(Phase3Error::Phase2NotComplete);
        }
        self.timeline.validate()?;
        self.second_stage.validate()?;
        self.fex.validate()?;
        if self.tracker.any_regressed() {
            return Err(Phase3Error::MilestoneRegressed);
        }
        // Phase 2 gate state must mirror the Phase 2 summary
        if self.phase2.phase2_complete()
            && !self.tracker.state(Phase3Milestone::Phase2GateClosed).is_validated()
        {
            return Err(Phase3Error::Phase2GateNotRecorded);
        }
        self.gate.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3Summary — high-level readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Phase Three readiness gate.
#[derive(Debug)]
pub struct Phase3Summary {
    /// True when Phase Two is complete.
    pub phase2_complete: bool,
    /// True when EPT/NPT and FEX-Emu are both correctly configured.
    pub virtualization_stack_ready: bool,
    /// True when every Phase Three milestone is `Validated`.
    pub all_milestones_validated: bool,
    /// True when the gate criterion passes.
    pub gate_passes: bool,
}

impl Phase3Summary {
    /// Return `true` when Phase Three is complete and Phase Four can begin.
    pub fn phase3_complete(&self) -> bool {
        self.phase2_complete
            && self.virtualization_stack_ready
            && self.all_milestones_validated
            && self.gate_passes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase3Error — errors returned by Phase Three configuration validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by Phase Three configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase3Error {
    /// Phase Two has not been completed.  Phase Three cannot start.
    Phase2NotComplete,
    /// Phase Two is complete but the tracker does not reflect this.
    Phase2GateNotRecorded,
    /// A milestone was advanced before its prerequisite was `Validated`.
    PrerequisiteIncomplete {
        /// The milestone being advanced.
        milestone:    Phase3Milestone,
        /// The prerequisite that is not yet `Validated`.
        prerequisite: Phase3Milestone,
    },
    /// A timeline estimate is zero months.
    TimelineEstimateZero,
    /// Timeline estimates are not monotonically non-decreasing.
    TimelineEstimateMonotonicityViolated,
    /// EPT / NPT TLB invalidation is disabled, allowing stale entries to
    /// leak between guest and hypervisor.
    SecondStageTlbInvalidationDisabled,
    /// Paging level is not 4-level (5-level is a future feature, not
    /// production-ready in Phase Three).
    PagingLevelUnsupported,
    /// FEX-Emu is configured to run as a host-userland program.
    ///
    /// AETHER has no host OS — FEX must run inside the hypervisor.
    FexEmuRequiresHostOs,
    /// At least one milestone is in the `Regressed` state.
    MilestoneRegressed,
    /// The gate criterion was accepted with a workaround.
    GateWorkaroundAccepted,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_phase2_summary() -> Phase2Summary {
        Phase2Summary {
            phase1_complete:          true,
            all_milestones_validated: true,
            app_coverage_complete:    true,
            gate_passes:              true,
        }
    }

    // ── X86VirtualizationFlavor ───────────────────────────────────────────────

    #[test]
    fn intel_uses_vmcs_and_ept() {
        let f = X86VirtualizationFlavor::IntelVtx;
        assert_eq!(f.control_structure_name(), "VMCS");
        assert_eq!(f.second_stage_table_name(), "EPT");
        assert_eq!(f.hypervisor_mode_name(), "VMX-root");
    }

    #[test]
    fn amd_uses_vmcb_and_npt() {
        let f = X86VirtualizationFlavor::AmdSvm;
        assert_eq!(f.control_structure_name(), "VMCB");
        assert_eq!(f.second_stage_table_name(), "NPT");
        assert_eq!(f.hypervisor_mode_name(), "SVM-host");
    }

    // ── SecondStageTableConfig ────────────────────────────────────────────────

    #[test]
    fn intel_production_validates() {
        assert!(SecondStageTableConfig::INTEL_PRODUCTION.validate().is_ok());
    }

    #[test]
    fn amd_production_validates() {
        assert!(SecondStageTableConfig::AMD_PRODUCTION.validate().is_ok());
    }

    #[test]
    fn five_level_paging_rejected() {
        let cfg = SecondStageTableConfig {
            four_level_paging: false,
            ..SecondStageTableConfig::INTEL_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::PagingLevelUnsupported));
    }

    #[test]
    fn missing_invalidation_rejected() {
        let cfg = SecondStageTableConfig {
            invalidate_on_mapping_change: false,
            ..SecondStageTableConfig::INTEL_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::SecondStageTlbInvalidationDisabled));
    }

    // ── FexEmuConfig ──────────────────────────────────────────────────────────

    #[test]
    fn in_hypervisor_mode_is_no_host_os_compatible() {
        assert!(FexEmuIntegrationMode::InHypervisor.is_no_host_os_compatible());
    }

    #[test]
    fn host_userland_mode_is_rejected() {
        assert!(!FexEmuIntegrationMode::HostUserland.is_no_host_os_compatible());
    }

    #[test]
    fn fex_production_validates() {
        assert!(FexEmuConfig::PRODUCTION.validate().is_ok());
    }

    #[test]
    fn fex_host_userland_rejected() {
        let cfg = FexEmuConfig {
            mode: FexEmuIntegrationMode::HostUserland,
            ..FexEmuConfig::PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::FexEmuRequiresHostOs));
    }

    // ── Phase3Milestone ───────────────────────────────────────────────────────

    #[test]
    fn first_milestone_has_no_prerequisite() {
        assert_eq!(Phase3Milestone::Phase2GateClosed.prerequisite(), None);
    }

    #[test]
    fn every_other_milestone_has_a_prerequisite() {
        for m in PHASE3_MILESTONES.iter().skip(1) {
            assert!(m.prerequisite().is_some(), "{:?} missing prerequisite", m);
        }
    }

    #[test]
    fn milestone_chain_is_linear() {
        let mut visited = 0;
        let mut cur = Some(*PHASE3_MILESTONES.last().unwrap());
        while let Some(m) = cur {
            visited += 1;
            cur = m.prerequisite();
        }
        assert_eq!(visited, PHASE3_MILESTONE_COUNT);
    }

    #[test]
    fn final_milestone_requires_hardware() {
        assert_eq!(
            Phase3Milestone::X86TierValidatedOnHardware.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn milestone_count_matches() {
        assert_eq!(PHASE3_MILESTONES.len(), PHASE3_MILESTONE_COUNT);
    }

    #[test]
    fn milestone_labels_are_nonempty() {
        for m in PHASE3_MILESTONES {
            assert!(!m.label().is_empty());
        }
    }

    // ── Phase3Tracker ─────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_all_not_started() {
        let t = Phase3Tracker::NEW;
        for m in PHASE3_MILESTONES {
            assert_eq!(t.state(*m), Phase3MilestoneState::NotStarted);
        }
    }

    #[test]
    fn cannot_advance_without_prerequisite() {
        let mut t = Phase3Tracker::NEW;
        let r = t.set_state(Phase3Milestone::VmxOrSvmAvailable, Phase3MilestoneState::InProgress);
        assert_eq!(
            r,
            Err(Phase3Error::PrerequisiteIncomplete {
                milestone:    Phase3Milestone::VmxOrSvmAvailable,
                prerequisite: Phase3Milestone::Phase2GateClosed,
            })
        );
    }

    #[test]
    fn linear_progression_validates_every_milestone() {
        let mut t = Phase3Tracker::NEW;
        for m in PHASE3_MILESTONES {
            t.set_state(*m, Phase3MilestoneState::Validated).expect("linear must succeed");
        }
        assert!(t.all_validated());
        assert_eq!(t.first_unvalidated(), None);
    }

    #[test]
    fn regression_detected() {
        let mut t = Phase3Tracker::NEW;
        t.set_state(Phase3Milestone::Phase2GateClosed, Phase3MilestoneState::Validated).unwrap();
        t.set_state(Phase3Milestone::Phase2GateClosed, Phase3MilestoneState::Regressed).unwrap();
        assert!(t.any_regressed());
    }

    // ── Phase3TimelineEstimate ────────────────────────────────────────────────

    #[test]
    fn readme_estimate_validates() {
        assert!(Phase3TimelineEstimate::README_DEDICATED_TEAM.validate().is_ok());
    }

    #[test]
    fn readme_realistic_is_24_months() {
        assert_eq!(Phase3TimelineEstimate::README_DEDICATED_TEAM.realistic_months, 24);
    }

    #[test]
    fn readme_pessimistic_is_36_months() {
        assert_eq!(Phase3TimelineEstimate::README_DEDICATED_TEAM.pessimistic_months, 36);
    }

    #[test]
    fn zero_optimistic_rejected() {
        let e = Phase3TimelineEstimate {
            optimistic_months: 0,
            realistic_months:  0,
            pessimistic_months: 0,
        };
        assert_eq!(e.validate(), Err(Phase3Error::TimelineEstimateZero));
    }

    #[test]
    fn nonmonotonic_rejected() {
        let e = Phase3TimelineEstimate {
            optimistic_months:  12,
            realistic_months:   6,
            pessimistic_months: 36,
        };
        assert_eq!(e.validate(), Err(Phase3Error::TimelineEstimateMonotonicityViolated));
    }

    // ── Phase3GateCriterion ───────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(Phase3GateCriterion::PASSING.passes());
    }

    #[test]
    fn passing_gate_validates() {
        assert!(Phase3GateCriterion::PASSING.validate().is_ok());
    }

    #[test]
    fn workaround_fails() {
        let g = Phase3GateCriterion {
            workaround_accepted: true,
            ..Phase3GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase3Error::GateWorkaroundAccepted));
    }

    #[test]
    fn missing_intel_boot_fails_gate() {
        let g = Phase3GateCriterion {
            intel_vtx_boot_on_real_hardware: false,
            ..Phase3GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_amd_boot_fails_gate() {
        let g = Phase3GateCriterion {
            amd_svm_boot_on_real_hardware: false,
            ..Phase3GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn fex_outside_hypervisor_fails_gate() {
        let g = Phase3GateCriterion {
            fex_in_hypervisor: false,
            ..Phase3GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase3Error::FexEmuRequiresHostOs));
    }

    #[test]
    fn missing_invalidation_fails_gate() {
        let g = Phase3GateCriterion {
            ept_npt_invalidation_enforced: false,
            ..Phase3GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase3Error::SecondStageTlbInvalidationDisabled));
    }

    // ── Phase3Config ──────────────────────────────────────────────────────────

    fn fully_validated_phase3_tracker() -> Phase3Tracker {
        let mut t = Phase3Tracker::NEW;
        for m in PHASE3_MILESTONES {
            t.set_state(*m, Phase3MilestoneState::Validated).unwrap();
        }
        t
    }

    fn passing_phase3_config() -> Phase3Config {
        Phase3Config {
            phase2:       complete_phase2_summary(),
            timeline:     Phase3TimelineEstimate::README_DEDICATED_TEAM,
            second_stage: SecondStageTableConfig::INTEL_PRODUCTION,
            fex:          FexEmuConfig::PRODUCTION,
            tracker:      fully_validated_phase3_tracker(),
            gate:         Phase3GateCriterion::PASSING,
        }
    }

    #[test]
    fn passing_phase3_config_validates() {
        assert!(passing_phase3_config().validate().is_ok());
    }

    #[test]
    fn config_rejects_incomplete_phase2() {
        let mut p2 = complete_phase2_summary();
        p2.gate_passes = false;
        let cfg = Phase3Config {
            phase2: p2,
            ..passing_phase3_config()
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::Phase2NotComplete));
    }

    #[test]
    fn config_rejects_unrecorded_phase2_gate() {
        let mut tracker = fully_validated_phase3_tracker();
        tracker.states[Phase3Milestone::Phase2GateClosed as usize] = Phase3MilestoneState::InProgress;
        let cfg = Phase3Config {
            tracker,
            ..passing_phase3_config()
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::Phase2GateNotRecorded));
    }

    #[test]
    fn config_rejects_host_userland_fex() {
        let cfg = Phase3Config {
            fex: FexEmuConfig {
                mode: FexEmuIntegrationMode::HostUserland,
                ..FexEmuConfig::PRODUCTION
            },
            ..passing_phase3_config()
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::FexEmuRequiresHostOs));
    }

    #[test]
    fn config_rejects_regression() {
        let mut tracker = fully_validated_phase3_tracker();
        tracker
            .set_state(Phase3Milestone::EptOrNptActive, Phase3MilestoneState::Regressed)
            .unwrap();
        let cfg = Phase3Config {
            tracker,
            ..passing_phase3_config()
        };
        assert_eq!(cfg.validate(), Err(Phase3Error::MilestoneRegressed));
    }

    // ── Phase3Summary ─────────────────────────────────────────────────────────

    #[test]
    fn phase3_summary_complete() {
        let s = Phase3Summary {
            phase2_complete:             true,
            virtualization_stack_ready:  true,
            all_milestones_validated:    true,
            gate_passes:                 true,
        };
        assert!(s.phase3_complete());
    }

    #[test]
    fn phase3_summary_partial_not_complete() {
        let cases = [
            Phase3Summary { phase2_complete: false, virtualization_stack_ready: true,  all_milestones_validated: true,  gate_passes: true  },
            Phase3Summary { phase2_complete: true,  virtualization_stack_ready: false, all_milestones_validated: true,  gate_passes: true  },
            Phase3Summary { phase2_complete: true,  virtualization_stack_ready: true,  all_milestones_validated: false, gate_passes: true  },
            Phase3Summary { phase2_complete: true,  virtualization_stack_ready: true,  all_milestones_validated: true,  gate_passes: false },
        ];
        for s in &cases {
            assert!(!s.phase3_complete(), "expected not-complete for {:?}", s);
        }
    }
}
