// ch32: Phase Four — Performance And Compatibility
//
// Phase Four takes the working AETHER produced by Phases One through Three
// and tunes it for native performance and application compatibility.
//
// README estimate: 12 months for a dedicated team; multiply by 2–3 for
// part-time work.
//
// ── Phase Four Definition ─────────────────────────────────────────────────────
//
// Phase Four delivers:
//
//   - Graphics path tuned for native performance (frame-time targets met)
//   - Sensor models refined against real device measurements (correct
//     statistical fingerprint vs. real Pixel / Galaxy / OnePlus hardware)
//   - Application compatibility validated across the top 1 000 Play Store
//     applications (or the closest open-source equivalent)
//   - Bug fixes for any application that misbehaves
//   - The CompatibilityReport summarises results across both ARM and x86
//     tiers (ARM should be near-native; x86 sees DBT overhead)
//
// Phase Four does NOT include user-facing polish (installer, configuration
// tools, support infrastructure) — that is Phase Five.
//
// ── Entry Gate: Phase Three Complete ──────────────────────────────────────────
//
// Phase Four requires both tiers (ARM and x86) to be functional end to end.
// Tuning performance before correctness is wrong-order: a graphics
// optimisation that loses a frame on an attestation-sensitive sensor is a
// regression on a stack that does not yet boot.
//
// ── Performance Targets ───────────────────────────────────────────────────────
//
// The targets are stated as upper bounds (worse is rejected).  All values
// are conservative and consistent with the README's "near-native" claim for
// the ARM tier.  The x86 tier targets are looser to account for DBT
// overhead, which is real but bounded.
//
//   Graphics frame time (60 Hz display, P99):
//     ARM tier: ≤ 16.7 ms   — must hold for SurfaceFlinger composition path
//     x86 tier: ≤ 33.3 ms   — DBT overhead permitted up to 2× native
//
//   App launch time, cold (P99):
//     ARM tier: ≤  800 ms   — typical for production Android phones
//     x86 tier: ≤ 1 800 ms  — DBT JIT-compile cost on first launch
//
//   VM exit budget (gaming workload, hypervisor exits per second):
//     ARM tier: <  1 000   — see ch24 performance.rs; native = essentially zero
//     x86 tier: < 10 000   — additional FEX-induced exits accepted
//
// ── Sensor Fidelity Targets ───────────────────────────────────────────────────
//
// The sensor models from ch12 are physics-accurate by design.  Phase Four
// validates them statistically against real reference hardware:
//
//   Accelerometer: σ ≈ 9.3 mm/s² (BMI160 at 40 Hz BW; ch12 ACCEL_SIGMA_MPS2)
//   Gyroscope:     σ ≈ 55 mdps    (BMI160; ch12 GYRO_SIGMA_DPS)
//   Magnetometer:  σ ≈ 0.3 µT     (BMM150; ch12 MAG_SIGMA_UT)
//
// A model that diverges from these by more than 10% in either direction
// must be retuned before Phase Four can close.
//
// ── App Compatibility ─────────────────────────────────────────────────────────
//
// The compatibility gate is "≥ 95% of the top 1 000 Play Store apps run
// correctly".  Failing 5% is acceptable for Phase Four; persistent failures
// are documented for Phase Five follow-up.  Apps that fail solely due to
// `MEETS_DEVICE_INTEGRITY` (e.g., banking, certain DRM-locked content) are
// expected to fail and are tracked separately — they do not count against
// the 95% target because the attestation problem is design, not bug.
//
// ── Realistic Time Accounting ─────────────────────────────────────────────────
//
// 12 months optimistic → 24 months realistic → 36 months pessimistic.
// Performance work is open-ended; budget conservatively.

use crate::development_workflow::TestTier;
use crate::performance::SubsystemOverhead;
use crate::roadmap_phase1::{PESSIMISTIC_MULTIPLIER, REALISTIC_MULTIPLIER};
use crate::roadmap_phase3::Phase3Summary;

// ─────────────────────────────────────────────────────────────────────────────
// PerformanceTarget — a single performance bound for a tier
// ─────────────────────────────────────────────────────────────────────────────

/// A single Phase Four performance target.
///
/// Targets are stated as upper bounds: the measured value must be `≤` the
/// target for the gate to pass.  ARM-tier and x86-tier targets differ
/// because the x86 tier carries DBT overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceTarget {
    /// Upper bound for the ARM tier (native execution).
    pub arm_tier_bound: u32,
    /// Upper bound for the x86 tier (DBT execution).
    ///
    /// Must be `>= arm_tier_bound` because DBT cannot be faster than native.
    pub x86_tier_bound: u32,
    /// The unit of the bound (informational; used for display only).
    pub unit: &'static str,
}

impl PerformanceTarget {
    /// Validate that the x86 bound is not tighter than the ARM bound.
    pub const fn validate(&self) -> Result<(), Phase4Error> {
        if self.x86_tier_bound < self.arm_tier_bound {
            return Err(Phase4Error::X86BoundTighterThanArm);
        }
        if self.arm_tier_bound == 0 {
            return Err(Phase4Error::PerformanceBoundZero);
        }
        Ok(())
    }
}

/// Graphics frame-time budget at 60 Hz (P99, milliseconds).
///
/// 16.7 ms is the 60 Hz frame budget.  ARM tier must hit it; x86 tier is
/// permitted up to 2× (33.3 ms) due to DBT overhead.
pub const FRAME_TIME_P99_MS: PerformanceTarget = PerformanceTarget {
    arm_tier_bound: 17,  // round up from 16.7 ms
    x86_tier_bound: 33,  // round down from 33.3 ms
    unit:           "ms (P99)",
};

/// Cold app launch time budget (P99, milliseconds).
pub const COLD_LAUNCH_P99_MS: PerformanceTarget = PerformanceTarget {
    arm_tier_bound: 800,
    x86_tier_bound: 1_800,
    unit:           "ms (P99)",
};

/// VM exit rate during gaming workload (per second).
///
/// See `performance.rs ExitCounter` and the < 1 000 exits/s gaming threshold.
pub const VM_EXITS_PER_SEC: PerformanceTarget = PerformanceTarget {
    arm_tier_bound: 1_000,
    x86_tier_bound: 10_000,
    unit:           "exits/s",
};

/// A performance measurement compared against a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceMeasurement {
    /// The target this measurement is checked against.
    pub target: PerformanceTarget,
    /// The actual measured value on the ARM tier.
    pub arm_measured: u32,
    /// The actual measured value on the x86 tier.
    pub x86_measured: u32,
}

impl PerformanceMeasurement {
    /// Return `true` when both tiers meet their target.
    pub const fn within_target(&self) -> bool {
        self.arm_measured <= self.target.arm_tier_bound
            && self.x86_measured <= self.target.x86_tier_bound
    }

    /// Validate the measurement against the target.
    pub const fn validate(&self) -> Result<(), Phase4Error> {
        if self.arm_measured > self.target.arm_tier_bound {
            return Err(Phase4Error::ArmTargetMissed {
                measured: self.arm_measured,
                bound:    self.target.arm_tier_bound,
            });
        }
        if self.x86_measured > self.target.x86_tier_bound {
            return Err(Phase4Error::X86TargetMissed {
                measured: self.x86_measured,
                bound:    self.target.x86_tier_bound,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubsystemPerfState — Phase Four subsystem performance assertion
// ─────────────────────────────────────────────────────────────────────────────

/// Per-subsystem performance state on a single tier.
///
/// Mirrors `performance.rs SubsystemOverhead` but as the Phase Four gate's
/// view: a subsystem either holds at `Native` / `Negligible`, or it has
/// regressed to `Present` (paravirt-class overhead) and must be retuned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsystemPerfState {
    /// CPU subsystem overhead.  Expected `Native` on ARM tier.
    pub cpu:      SubsystemOverhead,
    /// Memory subsystem overhead.  Expected `Negligible` on both tiers.
    pub memory:   SubsystemOverhead,
    /// GPU subsystem overhead.  Expected `Native` (SR-IOV passthrough).
    pub gpu:      SubsystemOverhead,
    /// Storage subsystem overhead.  Expected `Native` (NVMe passthrough).
    pub storage:  SubsystemOverhead,
    /// Network subsystem overhead.  Expected `Native` (SR-IOV / dedicated).
    pub network:  SubsystemOverhead,
}

impl SubsystemPerfState {
    /// The expected ARM-tier state at Phase Four close.
    pub const ARM_TARGET: Self = Self {
        cpu:     SubsystemOverhead::Native,
        memory:  SubsystemOverhead::Negligible,
        gpu:     SubsystemOverhead::Native,
        storage: SubsystemOverhead::Native,
        network: SubsystemOverhead::Native,
    };

    /// The expected x86-tier state at Phase Four close.
    ///
    /// CPU is `Present` because of DBT; everything else matches ARM.
    pub const X86_TARGET: Self = Self {
        cpu:     SubsystemOverhead::Present,
        memory:  SubsystemOverhead::Negligible,
        gpu:     SubsystemOverhead::Native,
        storage: SubsystemOverhead::Native,
        network: SubsystemOverhead::Native,
    };

    /// Return `true` when CPU/GPU/Storage/Network are all `Native` and Memory
    /// is `Negligible`.  Used as the "fully native ARM stack" gate.
    pub const fn arm_native(&self) -> bool {
        matches!(self.cpu, SubsystemOverhead::Native)
            && matches!(self.memory, SubsystemOverhead::Negligible)
            && matches!(self.gpu, SubsystemOverhead::Native)
            && matches!(self.storage, SubsystemOverhead::Native)
            && matches!(self.network, SubsystemOverhead::Native)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SensorFidelityCheck — statistical fidelity check vs. real reference hardware
// ─────────────────────────────────────────────────────────────────────────────

/// One sensor's measured σ vs. expected σ from the ch12 reference parameters.
///
/// All values are in "millis" of the natural unit (1e-3 of the unit) so they
/// fit in `u32` without floating point.  `ACCEL_SIGMA_MPS2 = 9.303 mm/s²`
/// becomes `9_303` in mm/s² (mm = 1e-3 m).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorFidelityCheck {
    /// Sensor name (for diagnostics).
    pub sensor: &'static str,
    /// Expected σ, in milli-units (matches ch12 reference values).
    pub expected_sigma_milli: u32,
    /// Measured σ on real reference hardware, in milli-units.
    pub measured_sigma_milli: u32,
    /// Allowed relative tolerance in tenths of a percent.
    /// 100 = 10% (the README target).
    pub tolerance_tenths_percent: u32,
}

impl SensorFidelityCheck {
    /// BMI160 accelerometer reference (ch12 ACCEL_SIGMA_MPS2 = 9.303 mm/s²)
    /// with 10% tolerance.
    pub const ACCEL_REFERENCE: Self = Self {
        sensor:                  "accelerometer",
        expected_sigma_milli:    9_303,  // 9.303 mm/s² in micro-m/s²
        measured_sigma_milli:    9_303,  // matched at construction; override in tests
        tolerance_tenths_percent: 100,    // 10%
    };

    /// BMI160 gyroscope reference (ch12 GYRO_SIGMA_DPS = 55 mdps) with 10%
    /// tolerance.
    pub const GYRO_REFERENCE: Self = Self {
        sensor:                  "gyroscope",
        expected_sigma_milli:    55,
        measured_sigma_milli:    55,
        tolerance_tenths_percent: 100,
    };

    /// BMM150 magnetometer reference (ch12 MAG_SIGMA_UT = 0.3 µT) with 10%
    /// tolerance.
    pub const MAG_REFERENCE: Self = Self {
        sensor:                  "magnetometer",
        expected_sigma_milli:    300,  // 0.3 µT in nT
        measured_sigma_milli:    300,
        tolerance_tenths_percent: 100,
    };

    /// Return `true` when measured σ is within tolerance of expected σ.
    pub const fn within_tolerance(&self) -> bool {
        let exp = self.expected_sigma_milli as u64;
        let meas = self.measured_sigma_milli as u64;
        // tolerance in thousandths of one (e.g. 100 → 0.100)
        let tol = self.tolerance_tenths_percent as u64;
        // Allowed deviation in milli-units: exp × tol / 1000
        let delta_max = (exp * tol) / 1_000;
        let actual_delta = if meas >= exp { meas - exp } else { exp - meas };
        actual_delta <= delta_max
    }

    /// Validate the check.
    pub fn validate(&self) -> Result<(), Phase4Error> {
        if self.tolerance_tenths_percent == 0 {
            return Err(Phase4Error::SensorToleranceZero);
        }
        if !self.within_tolerance() {
            return Err(Phase4Error::SensorOutOfTolerance {
                sensor:   self.sensor,
                measured: self.measured_sigma_milli,
                expected: self.expected_sigma_milli,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AppCompatibilityReport — top-1000 Play Store app validation
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate result of running the top-1 000 Play Store apps through AETHER.
///
/// Apps that fail solely because of the design-mandated attestation
/// limitation are recorded separately and do not count against the 95%
/// pass-rate target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppCompatibilityReport {
    /// Total apps tested (typically 1 000).
    pub total_apps: u32,
    /// Apps that ran correctly end to end.
    pub apps_passing: u32,
    /// Apps that failed solely because of the design-mandated attestation
    /// limitation (no Google certification → no `MEETS_DEVICE_INTEGRITY`).
    pub apps_failing_attestation_only: u32,
    /// Required pass rate as tenths of a percent (e.g. 950 = 95.0%).
    pub required_pass_rate_tenths: u32,
}

impl AppCompatibilityReport {
    /// The README target: 1 000 apps total, 95% pass rate (= 950 ‰).
    pub const README_TARGET_TEMPLATE: Self = Self {
        total_apps:                      1_000,
        apps_passing:                    0,      // populated by measurement
        apps_failing_attestation_only:   0,
        required_pass_rate_tenths:       950,    // 95.0%
    };

    /// Pass rate in tenths of a percent
    /// (`apps_passing / (total - attestation_only)`).
    pub const fn observed_pass_rate_tenths(&self) -> u32 {
        let denominator = self.total_apps.saturating_sub(self.apps_failing_attestation_only);
        if denominator == 0 {
            return 0;
        }
        // (passing × 1000) / denominator with saturating math
        let passing = self.apps_passing as u64;
        ((passing * 1_000) / (denominator as u64)) as u32
    }

    /// Return `true` when the observed pass rate meets the required threshold.
    pub const fn meets_target(&self) -> bool {
        self.observed_pass_rate_tenths() >= self.required_pass_rate_tenths
    }

    /// Validate the report.
    pub fn validate(&self) -> Result<(), Phase4Error> {
        if self.total_apps == 0 {
            return Err(Phase4Error::AppReportTotalZero);
        }
        if self.apps_passing > self.total_apps {
            return Err(Phase4Error::AppReportPassingExceedsTotal);
        }
        if self.apps_failing_attestation_only > self.total_apps {
            return Err(Phase4Error::AppReportAttestationFailuresExceedsTotal);
        }
        if !self.meets_target() {
            return Err(Phase4Error::AppCompatibilityTargetMissed {
                observed_tenths: self.observed_pass_rate_tenths(),
                required_tenths: self.required_pass_rate_tenths,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4Milestone — discrete milestones inside Phase Four
// ─────────────────────────────────────────────────────────────────────────────

/// A single milestone within Phase Four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase4Milestone {
    /// Phase Three complete on both tiers.  Entry gate.
    Phase3GateClosed,
    /// Graphics frame-time at P99 within target on the ARM tier.
    ArmTierFrameTimeWithinTarget,
    /// Graphics frame-time at P99 within target on the x86 tier (DBT).
    X86TierFrameTimeWithinTarget,
    /// Cold launch time at P99 within target on both tiers.
    ColdLaunchWithinTarget,
    /// VM exit rate under load within target on both tiers.
    VmExitRateWithinTarget,
    /// Sensor models within 10% tolerance of reference hardware
    /// measurements (accel, gyro, magnetometer).
    SensorFidelityWithinTolerance,
    /// At least 95% of the top 1 000 Play Store apps run correctly,
    /// excluding apps that fail solely due to attestation.
    AppCompatibilityTargetMet,
    /// Open compatibility issues triaged and a fix-or-defer decision made
    /// for each.  No silent unknowns left behind.
    AllCompatBugsTriaged,
    /// 24-hour soak run on both ARM and x86 hardware passes without crash,
    /// hang, or thermal throttling that violates the perf targets.
    SoakPassesOnBothTiers,
}

impl Phase4Milestone {
    /// Strict prerequisite milestone, or `None` for the first.
    pub const fn prerequisite(self) -> Option<Phase4Milestone> {
        use Phase4Milestone::*;
        match self {
            Phase3GateClosed              => None,
            ArmTierFrameTimeWithinTarget  => Some(Phase3GateClosed),
            X86TierFrameTimeWithinTarget  => Some(ArmTierFrameTimeWithinTarget),
            ColdLaunchWithinTarget        => Some(X86TierFrameTimeWithinTarget),
            VmExitRateWithinTarget        => Some(ColdLaunchWithinTarget),
            SensorFidelityWithinTolerance => Some(VmExitRateWithinTarget),
            AppCompatibilityTargetMet     => Some(SensorFidelityWithinTolerance),
            AllCompatBugsTriaged          => Some(AppCompatibilityTargetMet),
            SoakPassesOnBothTiers         => Some(AllCompatBugsTriaged),
        }
    }

    /// The development tier at which this milestone is first validated.
    pub const fn validation_tier(self) -> TestTier {
        use Phase4Milestone::*;
        match self {
            // Every Phase 4 performance target must be measured on real
            // hardware — QEMU performance numbers are not meaningful.
            SoakPassesOnBothTiers
            | ArmTierFrameTimeWithinTarget
            | X86TierFrameTimeWithinTarget
            | ColdLaunchWithinTarget
            | VmExitRateWithinTarget => TestTier::RealHardware,
            // Sensor fidelity and app compatibility are run against captured
            // traces; QEMU + Linux/Android guest is acceptable.
            _                        => TestTier::QemuLinuxGuest,
        }
    }

    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        use Phase4Milestone::*;
        match self {
            Phase3GateClosed              => "Phase 3 gate closed",
            ArmTierFrameTimeWithinTarget  => "ARM tier frame time within target",
            X86TierFrameTimeWithinTarget  => "x86 tier frame time within target",
            ColdLaunchWithinTarget        => "cold launch within target",
            VmExitRateWithinTarget        => "VM exit rate within target",
            SensorFidelityWithinTolerance => "sensor fidelity within tolerance",
            AppCompatibilityTargetMet     => "app compatibility target met",
            AllCompatBugsTriaged          => "all compat bugs triaged",
            SoakPassesOnBothTiers         => "soak passes on both tiers",
        }
    }
}

/// The number of Phase Four milestones.
pub const PHASE4_MILESTONE_COUNT: usize = 9;

/// The complete ordered sequence of Phase Four milestones.
pub const PHASE4_MILESTONES: &[Phase4Milestone] = &[
    Phase4Milestone::Phase3GateClosed,
    Phase4Milestone::ArmTierFrameTimeWithinTarget,
    Phase4Milestone::X86TierFrameTimeWithinTarget,
    Phase4Milestone::ColdLaunchWithinTarget,
    Phase4Milestone::VmExitRateWithinTarget,
    Phase4Milestone::SensorFidelityWithinTolerance,
    Phase4Milestone::AppCompatibilityTargetMet,
    Phase4Milestone::AllCompatBugsTriaged,
    Phase4Milestone::SoakPassesOnBothTiers,
];

// ─────────────────────────────────────────────────────────────────────────────
// Phase4MilestoneState + Phase4Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// The lifecycle state of a single Phase Four milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase4MilestoneState {
    /// Work has not begun.
    NotStarted,
    /// Work is underway but validation has not passed cleanly.
    InProgress,
    /// Validation tier passed cleanly without workarounds.
    Validated,
    /// Previously `Validated` but later regressed.
    Regressed,
}

impl Phase4MilestoneState {
    /// Return `true` only when the milestone passes its validation tier today.
    pub const fn is_validated(self) -> bool {
        matches!(self, Phase4MilestoneState::Validated)
    }
}

/// Tracks the state of every Phase Four milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4Tracker {
    states: [Phase4MilestoneState; PHASE4_MILESTONE_COUNT],
}

impl Phase4Tracker {
    /// Fresh tracker with every milestone `NotStarted`.
    pub const NEW: Self = Self {
        states: [Phase4MilestoneState::NotStarted; PHASE4_MILESTONE_COUNT],
    };

    /// Record a milestone state, enforcing prerequisite ordering.
    pub fn set_state(
        &mut self,
        milestone: Phase4Milestone,
        state: Phase4MilestoneState,
    ) -> Result<(), Phase4Error> {
        if matches!(state, Phase4MilestoneState::InProgress | Phase4MilestoneState::Validated) {
            if let Some(prereq) = milestone.prerequisite() {
                if !self.state(prereq).is_validated() {
                    return Err(Phase4Error::PrerequisiteIncomplete {
                        milestone,
                        prerequisite: prereq,
                    });
                }
            }
        }
        self.states[milestone as usize] = state;
        Ok(())
    }

    /// Read a milestone's state.
    pub const fn state(&self, milestone: Phase4Milestone) -> Phase4MilestoneState {
        self.states[milestone as usize]
    }

    /// Return `true` when every milestone is `Validated`.
    pub const fn all_validated(&self) -> bool {
        let mut i = 0;
        while i < PHASE4_MILESTONE_COUNT {
            if !matches!(self.states[i], Phase4MilestoneState::Validated) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// First not-yet-validated milestone.
    pub fn first_unvalidated(&self) -> Option<Phase4Milestone> {
        for m in PHASE4_MILESTONES {
            if !self.state(*m).is_validated() {
                return Some(*m);
            }
        }
        None
    }

    /// Return `true` when any milestone is in the `Regressed` state.
    pub const fn any_regressed(&self) -> bool {
        let mut i = 0;
        while i < PHASE4_MILESTONE_COUNT {
            if matches!(self.states[i], Phase4MilestoneState::Regressed) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4TimelineEstimate
// ─────────────────────────────────────────────────────────────────────────────

/// Three-point timeline estimate for Phase Four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4TimelineEstimate {
    /// Optimistic months (README estimate).
    pub optimistic_months: u32,
    /// Realistic months = optimistic × REALISTIC_MULTIPLIER.
    pub realistic_months: u32,
    /// Pessimistic months = optimistic × PESSIMISTIC_MULTIPLIER.
    pub pessimistic_months: u32,
}

impl Phase4TimelineEstimate {
    /// README estimate: 12 months for a dedicated team.
    pub const README_DEDICATED_TEAM: Self = Self {
        optimistic_months:  12,
        realistic_months:   12 * REALISTIC_MULTIPLIER,
        pessimistic_months: 12 * PESSIMISTIC_MULTIPLIER,
    };

    /// Validate non-zero and monotonic.
    pub fn validate(&self) -> Result<(), Phase4Error> {
        if self.optimistic_months == 0 {
            return Err(Phase4Error::TimelineEstimateZero);
        }
        if self.realistic_months < self.optimistic_months
            || self.pessimistic_months < self.realistic_months
        {
            return Err(Phase4Error::TimelineEstimateMonotonicityViolated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4GateCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// The Phase Four acceptance test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4GateCriterion {
    /// ARM-tier subsystem state matches `SubsystemPerfState::ARM_TARGET`
    /// (CPU/GPU/Storage/Network native, memory negligible).
    pub arm_native_subsystems: bool,
    /// Graphics frame-time within bound on both tiers.
    pub frame_time_within_bound: bool,
    /// Cold launch time within bound on both tiers.
    pub cold_launch_within_bound: bool,
    /// VM exit rate within bound on both tiers.
    pub vm_exit_rate_within_bound: bool,
    /// All three sensor fidelity checks pass.
    pub sensors_within_tolerance: bool,
    /// App compatibility report meets target.
    pub app_compat_target_met: bool,
    /// 24-hour soak passes on both tiers.
    pub soak_passes_on_both_tiers: bool,
    /// No workaround compromise accepted.
    pub workaround_accepted: bool,
}

impl Phase4GateCriterion {
    /// The state required to pass Phase Four.
    pub const PASSING: Self = Self {
        arm_native_subsystems:      true,
        frame_time_within_bound:    true,
        cold_launch_within_bound:   true,
        vm_exit_rate_within_bound:  true,
        sensors_within_tolerance:   true,
        app_compat_target_met:      true,
        soak_passes_on_both_tiers:  true,
        workaround_accepted:        false,
    };

    /// Return `true` only when every check is met.
    pub const fn passes(self) -> bool {
        self.arm_native_subsystems
            && self.frame_time_within_bound
            && self.cold_launch_within_bound
            && self.vm_exit_rate_within_bound
            && self.sensors_within_tolerance
            && self.app_compat_target_met
            && self.soak_passes_on_both_tiers
            && !self.workaround_accepted
    }

    /// Validate the gate criterion.
    pub fn validate(&self) -> Result<(), Phase4Error> {
        if self.workaround_accepted {
            return Err(Phase4Error::GateWorkaroundAccepted);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4Config — aggregate configuration + validation
// ─────────────────────────────────────────────────────────────────────────────

/// The aggregate configuration for Phase Four.
#[derive(Debug)]
pub struct Phase4Config {
    /// Phase Three readiness — entry gate.
    pub phase3: Phase3Summary,
    /// Three-point timeline estimate.
    pub timeline: Phase4TimelineEstimate,
    /// ARM-tier subsystem performance state.
    pub arm_subsystems: SubsystemPerfState,
    /// x86-tier subsystem performance state.
    pub x86_subsystems: SubsystemPerfState,
    /// Performance measurements vs targets.
    pub frame_time_measurement:    PerformanceMeasurement,
    /// Cold app launch measurement.
    pub cold_launch_measurement:   PerformanceMeasurement,
    /// VM exit rate measurement.
    pub vm_exit_measurement:       PerformanceMeasurement,
    /// Accelerometer fidelity check.
    pub accel_fidelity:            SensorFidelityCheck,
    /// Gyroscope fidelity check.
    pub gyro_fidelity:             SensorFidelityCheck,
    /// Magnetometer fidelity check.
    pub mag_fidelity:              SensorFidelityCheck,
    /// App compatibility report.
    pub app_compat:                AppCompatibilityReport,
    /// Per-milestone progress state.
    pub tracker:                   Phase4Tracker,
    /// Phase Four gate criterion.
    pub gate:                      Phase4GateCriterion,
}

impl Phase4Config {
    /// Validate the complete Phase Four configuration.
    pub fn validate(&self) -> Result<(), Phase4Error> {
        if !self.phase3.phase3_complete() {
            return Err(Phase4Error::Phase3NotComplete);
        }
        self.timeline.validate()?;
        // Validate all performance targets are coherent
        self.frame_time_measurement.target.validate()?;
        self.cold_launch_measurement.target.validate()?;
        self.vm_exit_measurement.target.validate()?;
        // Validate measurements meet targets
        self.frame_time_measurement.validate()?;
        self.cold_launch_measurement.validate()?;
        self.vm_exit_measurement.validate()?;
        // Validate sensor fidelity
        self.accel_fidelity.validate()?;
        self.gyro_fidelity.validate()?;
        self.mag_fidelity.validate()?;
        // App compatibility target met
        self.app_compat.validate()?;
        // ARM subsystems all native
        if !self.arm_subsystems.arm_native() {
            return Err(Phase4Error::ArmSubsystemNotNative);
        }
        // No regression in tracker
        if self.tracker.any_regressed() {
            return Err(Phase4Error::MilestoneRegressed);
        }
        // Phase 3 gate state must mirror Phase 3 summary
        if self.phase3.phase3_complete()
            && !self.tracker.state(Phase4Milestone::Phase3GateClosed).is_validated()
        {
            return Err(Phase4Error::Phase3GateNotRecorded);
        }
        self.gate.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4Summary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Phase Four readiness gate.
#[derive(Debug)]
pub struct Phase4Summary {
    /// True when Phase Three is complete.
    pub phase3_complete: bool,
    /// True when every performance target is met on both tiers.
    pub perf_targets_met: bool,
    /// True when sensor fidelity is within tolerance.
    pub sensor_fidelity_ok: bool,
    /// True when app compatibility target is met.
    pub app_compat_ok: bool,
    /// True when every milestone is `Validated`.
    pub all_milestones_validated: bool,
    /// True when the gate criterion passes.
    pub gate_passes: bool,
}

impl Phase4Summary {
    /// Return `true` when Phase Four is complete and Phase Five can begin.
    pub fn phase4_complete(&self) -> bool {
        self.phase3_complete
            && self.perf_targets_met
            && self.sensor_fidelity_ok
            && self.app_compat_ok
            && self.all_milestones_validated
            && self.gate_passes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase4Error
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by Phase Four configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase4Error {
    /// Phase Three has not been completed.
    Phase3NotComplete,
    /// Phase Three is complete but the tracker does not reflect this.
    Phase3GateNotRecorded,
    /// A milestone was advanced before its prerequisite was `Validated`.
    PrerequisiteIncomplete {
        /// The milestone being advanced.
        milestone:    Phase4Milestone,
        /// The prerequisite that is not yet `Validated`.
        prerequisite: Phase4Milestone,
    },
    /// A timeline estimate is zero months.
    TimelineEstimateZero,
    /// Timeline estimates are not monotonically non-decreasing.
    TimelineEstimateMonotonicityViolated,
    /// Performance target's x86 bound is tighter than its ARM bound.
    ///
    /// DBT cannot be faster than native — this would be a logic error in
    /// the target itself.
    X86BoundTighterThanArm,
    /// Performance bound is zero.
    PerformanceBoundZero,
    /// ARM-tier measurement missed its target.
    ArmTargetMissed {
        /// Measured value.
        measured: u32,
        /// Upper bound from the target.
        bound:    u32,
    },
    /// x86-tier measurement missed its target.
    X86TargetMissed {
        /// Measured value.
        measured: u32,
        /// Upper bound from the target.
        bound:    u32,
    },
    /// Sensor fidelity tolerance is zero — degenerate check.
    SensorToleranceZero,
    /// A sensor's measured σ is out of tolerance from the reference.
    SensorOutOfTolerance {
        /// Sensor name.
        sensor:   &'static str,
        /// Measured σ (milli-units).
        measured: u32,
        /// Expected σ (milli-units).
        expected: u32,
    },
    /// App compatibility report total apps is zero.
    AppReportTotalZero,
    /// App compatibility report passing count exceeds total.
    AppReportPassingExceedsTotal,
    /// Attestation-failure count exceeds total.
    AppReportAttestationFailuresExceedsTotal,
    /// App compatibility target missed.
    AppCompatibilityTargetMissed {
        /// Observed pass rate in tenths of a percent.
        observed_tenths: u32,
        /// Required pass rate in tenths of a percent.
        required_tenths: u32,
    },
    /// ARM subsystems are not all `Native`.
    ArmSubsystemNotNative,
    /// At least one milestone is in the `Regressed` state.
    MilestoneRegressed,
    /// Gate criterion accepted with a workaround.
    GateWorkaroundAccepted,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_phase3_summary() -> Phase3Summary {
        Phase3Summary {
            phase2_complete:            true,
            virtualization_stack_ready: true,
            all_milestones_validated:   true,
            gate_passes:                true,
        }
    }

    // ── PerformanceTarget ─────────────────────────────────────────────────────

    #[test]
    fn frame_time_target_validates() {
        assert!(FRAME_TIME_P99_MS.validate().is_ok());
    }

    #[test]
    fn cold_launch_target_validates() {
        assert!(COLD_LAUNCH_P99_MS.validate().is_ok());
    }

    #[test]
    fn vm_exits_target_validates() {
        assert!(VM_EXITS_PER_SEC.validate().is_ok());
    }

    #[test]
    fn arm_tier_frame_budget_under_one_frame() {
        // ARM tier must hit the 60 Hz frame budget (16.7 ms → rounded to 17)
        assert!(FRAME_TIME_P99_MS.arm_tier_bound <= 17);
    }

    #[test]
    fn x86_tier_frame_budget_is_at_most_2x_arm() {
        assert!(FRAME_TIME_P99_MS.x86_tier_bound <= FRAME_TIME_P99_MS.arm_tier_bound * 2);
    }

    #[test]
    fn x86_tighter_than_arm_rejected() {
        let t = PerformanceTarget {
            arm_tier_bound: 100,
            x86_tier_bound: 50,  // tighter than ARM — impossible
            unit:           "ms",
        };
        assert_eq!(t.validate(), Err(Phase4Error::X86BoundTighterThanArm));
    }

    #[test]
    fn zero_bound_rejected() {
        let t = PerformanceTarget {
            arm_tier_bound: 0,
            x86_tier_bound: 0,
            unit:           "ms",
        };
        assert_eq!(t.validate(), Err(Phase4Error::PerformanceBoundZero));
    }

    // ── PerformanceMeasurement ────────────────────────────────────────────────

    #[test]
    fn within_target_measurement_validates() {
        let m = PerformanceMeasurement {
            target:        FRAME_TIME_P99_MS,
            arm_measured:  14,
            x86_measured:  28,
        };
        assert!(m.within_target());
        assert!(m.validate().is_ok());
    }

    #[test]
    fn arm_over_target_rejected() {
        let m = PerformanceMeasurement {
            target:        FRAME_TIME_P99_MS,
            arm_measured:  20,  // over 17 ms
            x86_measured:  28,
        };
        assert!(!m.within_target());
        assert_eq!(m.validate(), Err(Phase4Error::ArmTargetMissed { measured: 20, bound: 17 }));
    }

    #[test]
    fn x86_over_target_rejected() {
        let m = PerformanceMeasurement {
            target:        FRAME_TIME_P99_MS,
            arm_measured:  14,
            x86_measured:  40,  // over 33 ms
        };
        assert!(!m.within_target());
        assert_eq!(m.validate(), Err(Phase4Error::X86TargetMissed { measured: 40, bound: 33 }));
    }

    // ── SubsystemPerfState ────────────────────────────────────────────────────

    #[test]
    fn arm_target_is_native() {
        assert!(SubsystemPerfState::ARM_TARGET.arm_native());
    }

    #[test]
    fn x86_target_cpu_is_present() {
        // x86 tier carries DBT overhead — CPU subsystem is not "Native"
        let x = SubsystemPerfState::X86_TARGET;
        assert_eq!(x.cpu, SubsystemOverhead::Present);
        assert!(!x.arm_native());  // cannot pass the ARM-tier gate
    }

    // ── SensorFidelityCheck ───────────────────────────────────────────────────

    #[test]
    fn accel_reference_passes_tolerance() {
        assert!(SensorFidelityCheck::ACCEL_REFERENCE.within_tolerance());
        assert!(SensorFidelityCheck::ACCEL_REFERENCE.validate().is_ok());
    }

    #[test]
    fn gyro_reference_passes_tolerance() {
        assert!(SensorFidelityCheck::GYRO_REFERENCE.within_tolerance());
    }

    #[test]
    fn mag_reference_passes_tolerance() {
        assert!(SensorFidelityCheck::MAG_REFERENCE.within_tolerance());
    }

    #[test]
    fn measured_within_5_percent_passes() {
        // 5% over: 9_303 → 9_768 (4.99% high)
        let c = SensorFidelityCheck {
            measured_sigma_milli: 9_768,
            ..SensorFidelityCheck::ACCEL_REFERENCE
        };
        assert!(c.within_tolerance());
    }

    #[test]
    fn measured_over_10_percent_fails() {
        // 15% over: 9_303 → 10_700
        let c = SensorFidelityCheck {
            measured_sigma_milli: 10_700,
            ..SensorFidelityCheck::ACCEL_REFERENCE
        };
        assert!(!c.within_tolerance());
        assert_eq!(
            c.validate(),
            Err(Phase4Error::SensorOutOfTolerance {
                sensor:   "accelerometer",
                measured: 10_700,
                expected: 9_303,
            })
        );
    }

    #[test]
    fn measured_under_10_percent_fails() {
        // 15% under: 9_303 → 7_900
        let c = SensorFidelityCheck {
            measured_sigma_milli: 7_900,
            ..SensorFidelityCheck::ACCEL_REFERENCE
        };
        assert!(!c.within_tolerance());
    }

    #[test]
    fn zero_tolerance_rejected() {
        let c = SensorFidelityCheck {
            tolerance_tenths_percent: 0,
            ..SensorFidelityCheck::ACCEL_REFERENCE
        };
        assert_eq!(c.validate(), Err(Phase4Error::SensorToleranceZero));
    }

    // ── AppCompatibilityReport ────────────────────────────────────────────────

    #[test]
    fn perfect_report_meets_target() {
        let r = AppCompatibilityReport {
            apps_passing:                 1_000,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert!(r.meets_target());
        assert_eq!(r.observed_pass_rate_tenths(), 1_000);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn ninety_five_percent_meets_target() {
        let r = AppCompatibilityReport {
            apps_passing:                 950,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert!(r.meets_target());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn ninety_percent_fails_target() {
        let r = AppCompatibilityReport {
            apps_passing:                 900,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert!(!r.meets_target());
        assert_eq!(
            r.validate(),
            Err(Phase4Error::AppCompatibilityTargetMissed { observed_tenths: 900, required_tenths: 950 })
        );
    }

    #[test]
    fn attestation_failures_excluded_from_pass_rate() {
        // 950/1000 = 95.0%; if 50 fail attestation, denominator = 950 →
        // need apps_passing/950 >= 0.95 → apps_passing >= 902.5 → 903.
        let r = AppCompatibilityReport {
            apps_passing:                 903,
            apps_failing_attestation_only: 50,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert!(r.meets_target(), "rate = {}", r.observed_pass_rate_tenths());
    }

    #[test]
    fn zero_total_rejected() {
        let r = AppCompatibilityReport {
            total_apps:    0,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert_eq!(r.validate(), Err(Phase4Error::AppReportTotalZero));
    }

    #[test]
    fn passing_exceeds_total_rejected() {
        let r = AppCompatibilityReport {
            apps_passing: 1_500,
            ..AppCompatibilityReport::README_TARGET_TEMPLATE
        };
        assert_eq!(r.validate(), Err(Phase4Error::AppReportPassingExceedsTotal));
    }

    // ── Phase4Milestone ───────────────────────────────────────────────────────

    #[test]
    fn first_milestone_has_no_prerequisite() {
        assert_eq!(Phase4Milestone::Phase3GateClosed.prerequisite(), None);
    }

    #[test]
    fn milestone_chain_is_linear() {
        let mut visited = 0;
        let mut cur = Some(*PHASE4_MILESTONES.last().unwrap());
        while let Some(m) = cur {
            visited += 1;
            cur = m.prerequisite();
        }
        assert_eq!(visited, PHASE4_MILESTONE_COUNT);
    }

    #[test]
    fn perf_milestones_validate_on_real_hardware() {
        assert_eq!(
            Phase4Milestone::ArmTierFrameTimeWithinTarget.validation_tier(),
            TestTier::RealHardware
        );
        assert_eq!(
            Phase4Milestone::SoakPassesOnBothTiers.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn milestone_count_matches() {
        assert_eq!(PHASE4_MILESTONES.len(), PHASE4_MILESTONE_COUNT);
    }

    // ── Phase4Tracker ─────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_all_not_started() {
        let t = Phase4Tracker::NEW;
        for m in PHASE4_MILESTONES {
            assert_eq!(t.state(*m), Phase4MilestoneState::NotStarted);
        }
    }

    #[test]
    fn cannot_advance_without_prerequisite() {
        let mut t = Phase4Tracker::NEW;
        let r = t.set_state(Phase4Milestone::ArmTierFrameTimeWithinTarget, Phase4MilestoneState::Validated);
        assert_eq!(
            r,
            Err(Phase4Error::PrerequisiteIncomplete {
                milestone:    Phase4Milestone::ArmTierFrameTimeWithinTarget,
                prerequisite: Phase4Milestone::Phase3GateClosed,
            })
        );
    }

    #[test]
    fn linear_progression_works() {
        let mut t = Phase4Tracker::NEW;
        for m in PHASE4_MILESTONES {
            t.set_state(*m, Phase4MilestoneState::Validated).expect("linear must succeed");
        }
        assert!(t.all_validated());
    }

    // ── Phase4TimelineEstimate ────────────────────────────────────────────────

    #[test]
    fn readme_estimate_validates() {
        assert!(Phase4TimelineEstimate::README_DEDICATED_TEAM.validate().is_ok());
    }

    #[test]
    fn readme_realistic_24_months() {
        assert_eq!(Phase4TimelineEstimate::README_DEDICATED_TEAM.realistic_months, 24);
    }

    #[test]
    fn zero_optimistic_rejected_p4() {
        let e = Phase4TimelineEstimate { optimistic_months: 0, realistic_months: 0, pessimistic_months: 0 };
        assert_eq!(e.validate(), Err(Phase4Error::TimelineEstimateZero));
    }

    // ── Phase4GateCriterion ───────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(Phase4GateCriterion::PASSING.passes());
        assert!(Phase4GateCriterion::PASSING.validate().is_ok());
    }

    #[test]
    fn workaround_fails() {
        let g = Phase4GateCriterion {
            workaround_accepted: true,
            ..Phase4GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase4Error::GateWorkaroundAccepted));
    }

    #[test]
    fn missing_arm_native_fails() {
        let g = Phase4GateCriterion {
            arm_native_subsystems: false,
            ..Phase4GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    // ── Phase4Config ──────────────────────────────────────────────────────────

    fn fully_validated_phase4_tracker() -> Phase4Tracker {
        let mut t = Phase4Tracker::NEW;
        for m in PHASE4_MILESTONES {
            t.set_state(*m, Phase4MilestoneState::Validated).unwrap();
        }
        t
    }

    fn passing_phase4_config() -> Phase4Config {
        Phase4Config {
            phase3:                  complete_phase3_summary(),
            timeline:                Phase4TimelineEstimate::README_DEDICATED_TEAM,
            arm_subsystems:          SubsystemPerfState::ARM_TARGET,
            x86_subsystems:          SubsystemPerfState::X86_TARGET,
            frame_time_measurement:  PerformanceMeasurement {
                target:       FRAME_TIME_P99_MS,
                arm_measured: 14,
                x86_measured: 28,
            },
            cold_launch_measurement: PerformanceMeasurement {
                target:       COLD_LAUNCH_P99_MS,
                arm_measured: 600,
                x86_measured: 1_500,
            },
            vm_exit_measurement:     PerformanceMeasurement {
                target:       VM_EXITS_PER_SEC,
                arm_measured: 500,
                x86_measured: 5_000,
            },
            accel_fidelity:          SensorFidelityCheck::ACCEL_REFERENCE,
            gyro_fidelity:           SensorFidelityCheck::GYRO_REFERENCE,
            mag_fidelity:            SensorFidelityCheck::MAG_REFERENCE,
            app_compat:              AppCompatibilityReport {
                apps_passing:                 950,
                ..AppCompatibilityReport::README_TARGET_TEMPLATE
            },
            tracker:                 fully_validated_phase4_tracker(),
            gate:                    Phase4GateCriterion::PASSING,
        }
    }

    #[test]
    fn passing_phase4_config_validates() {
        assert!(passing_phase4_config().validate().is_ok());
    }

    #[test]
    fn config_rejects_incomplete_phase3() {
        let mut p3 = complete_phase3_summary();
        p3.gate_passes = false;
        let cfg = Phase4Config {
            phase3: p3,
            ..passing_phase4_config()
        };
        assert_eq!(cfg.validate(), Err(Phase4Error::Phase3NotComplete));
    }

    #[test]
    fn config_rejects_failed_perf_measurement() {
        let cfg = Phase4Config {
            frame_time_measurement: PerformanceMeasurement {
                target:       FRAME_TIME_P99_MS,
                arm_measured: 25,  // misses 17 ms bound
                x86_measured: 28,
            },
            ..passing_phase4_config()
        };
        assert_eq!(
            cfg.validate(),
            Err(Phase4Error::ArmTargetMissed { measured: 25, bound: 17 })
        );
    }

    #[test]
    fn config_rejects_sensor_out_of_tolerance() {
        let cfg = Phase4Config {
            accel_fidelity: SensorFidelityCheck {
                measured_sigma_milli: 12_000, // 28% off
                ..SensorFidelityCheck::ACCEL_REFERENCE
            },
            ..passing_phase4_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(Phase4Error::SensorOutOfTolerance { sensor: "accelerometer", .. })
        ));
    }

    #[test]
    fn config_rejects_failed_compat() {
        let cfg = Phase4Config {
            app_compat: AppCompatibilityReport {
                apps_passing: 800,
                ..AppCompatibilityReport::README_TARGET_TEMPLATE
            },
            ..passing_phase4_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(Phase4Error::AppCompatibilityTargetMissed { .. })
        ));
    }

    #[test]
    fn config_rejects_non_native_arm() {
        let cfg = Phase4Config {
            arm_subsystems: SubsystemPerfState {
                cpu: SubsystemOverhead::Present,
                ..SubsystemPerfState::ARM_TARGET
            },
            ..passing_phase4_config()
        };
        assert_eq!(cfg.validate(), Err(Phase4Error::ArmSubsystemNotNative));
    }

    // ── Phase4Summary ─────────────────────────────────────────────────────────

    #[test]
    fn phase4_summary_complete() {
        let s = Phase4Summary {
            phase3_complete:           true,
            perf_targets_met:          true,
            sensor_fidelity_ok:        true,
            app_compat_ok:             true,
            all_milestones_validated:  true,
            gate_passes:               true,
        };
        assert!(s.phase4_complete());
    }

    #[test]
    fn phase4_summary_partial_not_complete() {
        let mut base = Phase4Summary {
            phase3_complete:           true,
            perf_targets_met:          true,
            sensor_fidelity_ok:        true,
            app_compat_ok:             true,
            all_milestones_validated:  true,
            gate_passes:               true,
        };
        base.phase3_complete = false;            assert!(!base.phase4_complete());
        base.phase3_complete = true;
        base.perf_targets_met = false;           assert!(!base.phase4_complete());
        base.perf_targets_met = true;
        base.sensor_fidelity_ok = false;         assert!(!base.phase4_complete());
        base.sensor_fidelity_ok = true;
        base.app_compat_ok = false;              assert!(!base.phase4_complete());
        base.app_compat_ok = true;
        base.all_milestones_validated = false;   assert!(!base.phase4_complete());
        base.all_milestones_validated = true;
        base.gate_passes = false;                assert!(!base.phase4_complete());
    }
}
