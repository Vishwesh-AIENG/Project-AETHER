// ch30: Phase Two — Android Bring-Up (ARM Tier)
//
// Phase Two takes the bare hypervisor produced by Phase One and brings up the
// full Android stack inside the ARM-tier Android partition.  README estimate:
// six to nine months for a dedicated team; multiply by 2–3 for part-time work.
//
// ── Phase Two Definition ──────────────────────────────────────────────────────
//
// Phase Two delivers an Android partition that:
//
//   - Boots a complete AOSP image built against AETHER's `aether_arm64`
//     device target with `ro.build.type = user`
//   - Integrates microG for the Google Play Services API surface (Auth, FCM
//     direct, Fused Location via Mozilla MLS, Maps via OSM tiles)
//   - Toggles between paravirtualized sensors (Irwin-Hall Gaussian, BMI160
//     parameters) and Phone Bridge Mode (USB-tethered phone hardware)
//   - Routes Adreno SR-IOV VF to the partition; the GPU driver loads and
//     SurfaceFlinger composes frames
//   - Passes basic SafetyNet checks (`MEETS_BASIC_INTEGRITY = true`); the
//     stronger `MEETS_DEVICE_INTEGRITY` verdict is unattainable by design
//   - Runs at least one app from each of the seven application categories
//     listed below
//
// ── Critical Path (After Phase One) ───────────────────────────────────────────
//
// Phase Two builds on the Phase One foundation.  Within Phase Two, the
// chapter dependencies are:
//
//   ch12  Paravirt sensors + modem    — independent, may begin first
//   ch13  GPU SR-IOV (Adreno VF)      — independent (needs hardware)
//   ch15  Network partitioning        — independent (needs hardware)
//   ch16  USB / input routing         — depends on ch12 (HID + bridge)
//        ↓
//   ch19  Bootloader (AVB, A/B)       — depends on ch11/ch14 (passthrough)
//        ↓
//   ch20  Linux kernel + DTB          — depends on ch19
//        ↓
//   ch21  AOSP userspace + HALs       — depends on ch20 (DTB matches HALs)
//        ↓
//   ch22  microG substitution         — depends on ch21
//        ↓
//   ch23  Play Store policy           — depends on ch22 (microG ships first)
//
// ── App-Category Coverage Test ────────────────────────────────────────────────
//
// The Phase Two gate is not "Android boots".  It is "Android runs apps from
// every meaningful category".  The seven categories are:
//
//   1. Communication                  WhatsApp, Signal, Telegram
//   2. Maps / navigation              OsmAnd, Organic Maps
//   3. Web browsing                   Firefox, Vanadium, Brave
//   4. Media playback                 NewPipe, VLC
//   5. Productivity                   Markor, F-Droid, Joplin
//   6. Banking / attestation-sensitive (at least one — typically fails;
//                                      recorded for Phase Four follow-up)
//   7. Gaming (light)                 Open-source games from F-Droid
//
// `AppCategoryCoverage` records pass/fail status per category.
//
// ── Realistic Time Accounting ─────────────────────────────────────────────────
//
// The README estimate of 6–9 months assumes a dedicated team.  For part-time
// work, multiply by 2–3.  `Phase2TimelineEstimate::README_LOWER` and
// `README_UPPER` give the bounds.

use crate::aosp::BuildType;
use crate::development_workflow::TestTier;
use crate::microg::PlayIntegrityMaxVerdict;
use crate::roadmap_phase1::{PESSIMISTIC_MULTIPLIER, Phase1Summary, REALISTIC_MULTIPLIER};

// ─────────────────────────────────────────────────────────────────────────────
// Phase2Milestone — the discrete milestones inside Phase Two
// ─────────────────────────────────────────────────────────────────────────────

/// A single milestone within Phase Two.
///
/// Order reflects the dependency order in the README:
///   bootloader → kernel → userspace → microG → Play store policy →
///   sensors → GPU → end-to-end Android validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase2Milestone {
    /// Phase One complete.  This is the entry gate to Phase Two.
    ///
    /// Without a working hypervisor (Phase One), no Android bring-up work can
    /// be honestly tested.  Skipping this gate means later Android failures
    /// cannot be attributed correctly between hypervisor bugs and userspace
    /// bugs.
    Phase1GateClosed,
    /// AOSP source tree synced and `aether_arm64` device configuration
    /// directory created (ch21).
    AospSourceSynced,
    /// Android bootloader environment: AVB2 vbmeta verification + A/B slot
    /// selection succeed against a real boot.img produced by AOSP (ch19).
    BootloaderVerified,
    /// Linux kernel boots in the Android partition with a DTB constructed
    /// from AETHER's device tree builder; GKI mandatory config satisfied
    /// (ch20).
    KernelBootsWithDtb,
    /// Android userspace reaches `boot_completed` — `init` runs, system
    /// services start, the framework is up.  Shell-only at this point;
    /// no SurfaceFlinger / display (ch21).
    UserspaceReachesBootCompleted,
    /// SurfaceFlinger composes frames to the Adreno SR-IOV VF; the system
    /// UI is visible (ch13).
    AdrenoVfRendersUi,
    /// Paravirtualized BMI160 sensor stream is delivered through the Sensor
    /// HAL; sample values exhibit correct Irwin-Hall Gaussian noise (ch12).
    ParavirtSensorsLive,
    /// Phone Bridge Mode toggles cleanly: USB-tethered phone hardware
    /// replaces paravirt sensors when active, and vice versa (ch12/ch16).
    PhoneBridgeToggleWorking,
    /// Virtual modem responds to 3GPP TS 27.007 AT commands; data calls
    /// route through the assigned NIC (ch12/ch15).
    VirtualModemAttached,
    /// microG installed in the system image; `signature_spoofing_policy =
    /// Enabled` is in effect; FCM / Authentication / Fused Location reach
    /// at least their declared coverage level (ch22).
    MicroGServicesRunning,
    /// At least one app installs from F-Droid and one from Aurora Store with
    /// anonymous proxy; neither store falls back to the genuine Play Store
    /// automatic path (ch23).
    AppStoreInstallsSucceed,
    /// SafetyNet basicIntegrity == true.  This is the maximum verdict
    /// achievable; `MEETS_DEVICE_INTEGRITY` is unattainable by design and
    /// any apparent pass at that level indicates a misconfiguration.
    SafetyNetBasicIntegrityPasses,
    /// Apps from every category in `APP_CATEGORIES` run successfully.
    /// `AppCategoryCoverage::all_passing()` returns `true`.
    AppCategoryCoverageComplete,
    /// End-to-end Android validation on real Snapdragon X Elite hardware
    /// completes a 24-hour soak run without crash.  Closes Phase Two.
    AndroidStableOnHardware,
}

impl Phase2Milestone {
    /// The strict prerequisite milestone, or `None` for the first.
    pub const fn prerequisite(self) -> Option<Phase2Milestone> {
        use Phase2Milestone::*;
        match self {
            Phase1GateClosed              => None,
            AospSourceSynced              => Some(Phase1GateClosed),
            BootloaderVerified            => Some(AospSourceSynced),
            KernelBootsWithDtb            => Some(BootloaderVerified),
            UserspaceReachesBootCompleted => Some(KernelBootsWithDtb),
            AdrenoVfRendersUi             => Some(UserspaceReachesBootCompleted),
            ParavirtSensorsLive           => Some(AdrenoVfRendersUi),
            PhoneBridgeToggleWorking      => Some(ParavirtSensorsLive),
            VirtualModemAttached          => Some(PhoneBridgeToggleWorking),
            MicroGServicesRunning         => Some(VirtualModemAttached),
            AppStoreInstallsSucceed       => Some(MicroGServicesRunning),
            SafetyNetBasicIntegrityPasses => Some(AppStoreInstallsSucceed),
            AppCategoryCoverageComplete   => Some(SafetyNetBasicIntegrityPasses),
            AndroidStableOnHardware       => Some(AppCategoryCoverageComplete),
        }
    }

    /// The development tier at which this milestone can first be validated.
    pub const fn validation_tier(self) -> TestTier {
        use Phase2Milestone::*;
        match self {
            AndroidStableOnHardware => TestTier::RealHardware,
            // Most Phase Two work is exercised in the Tier 2 (real Linux/
            // Android kernel guest) QEMU loop, which can use the snapshot
            // checkpoint to skip the long boot.
            _                       => TestTier::QemuLinuxGuest,
        }
    }

    /// Human-readable label for status displays.
    pub const fn label(self) -> &'static str {
        use Phase2Milestone::*;
        match self {
            Phase1GateClosed              => "Phase 1 gate closed",
            AospSourceSynced              => "AOSP source synced",
            BootloaderVerified            => "bootloader verified",
            KernelBootsWithDtb            => "kernel boots with DTB",
            UserspaceReachesBootCompleted => "userspace reaches boot_completed",
            AdrenoVfRendersUi             => "Adreno VF renders UI",
            ParavirtSensorsLive           => "paravirt sensors live",
            PhoneBridgeToggleWorking      => "Phone Bridge toggle working",
            VirtualModemAttached          => "virtual modem attached",
            MicroGServicesRunning         => "microG services running",
            AppStoreInstallsSucceed       => "app store installs succeed",
            SafetyNetBasicIntegrityPasses => "SafetyNet basicIntegrity passes",
            AppCategoryCoverageComplete   => "app-category coverage complete",
            AndroidStableOnHardware       => "Android stable on hardware",
        }
    }
}

/// The number of Phase Two milestones.
pub const PHASE2_MILESTONE_COUNT: usize = 14;

/// The complete ordered sequence of Phase Two milestones.
pub const PHASE2_MILESTONES: &[Phase2Milestone] = &[
    Phase2Milestone::Phase1GateClosed,
    Phase2Milestone::AospSourceSynced,
    Phase2Milestone::BootloaderVerified,
    Phase2Milestone::KernelBootsWithDtb,
    Phase2Milestone::UserspaceReachesBootCompleted,
    Phase2Milestone::AdrenoVfRendersUi,
    Phase2Milestone::ParavirtSensorsLive,
    Phase2Milestone::PhoneBridgeToggleWorking,
    Phase2Milestone::VirtualModemAttached,
    Phase2Milestone::MicroGServicesRunning,
    Phase2Milestone::AppStoreInstallsSucceed,
    Phase2Milestone::SafetyNetBasicIntegrityPasses,
    Phase2Milestone::AppCategoryCoverageComplete,
    Phase2Milestone::AndroidStableOnHardware,
];

// ─────────────────────────────────────────────────────────────────────────────
// MilestoneState — per-milestone progress (reused from Phase 1 in shape, but
// duplicated here to keep the modules independent)
// ─────────────────────────────────────────────────────────────────────────────

/// The lifecycle state of a single Phase Two milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase2MilestoneState {
    /// Work on this milestone has not begun.
    NotStarted,
    /// Work is underway but the validation tier has not yet passed cleanly.
    InProgress,
    /// The validation tier passed cleanly without workarounds.
    Validated,
    /// The milestone was previously `Validated` but later regressed.
    Regressed,
}

impl Phase2MilestoneState {
    /// Return `true` only when the milestone passes its validation tier today.
    pub const fn is_validated(self) -> bool {
        matches!(self, Phase2MilestoneState::Validated)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2Tracker — per-milestone state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the state of every Phase Two milestone.  Indexed by `Phase2Milestone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase2Tracker {
    states: [Phase2MilestoneState; PHASE2_MILESTONE_COUNT],
}

impl Phase2Tracker {
    /// A fresh tracker with every milestone `NotStarted`.
    pub const NEW: Self = Self {
        states: [Phase2MilestoneState::NotStarted; PHASE2_MILESTONE_COUNT],
    };

    /// Record the state of a single milestone.
    ///
    /// Returns `Err(PrerequisiteIncomplete)` if the caller advances a
    /// milestone before its prerequisite is `Validated`.
    pub fn set_state(
        &mut self,
        milestone: Phase2Milestone,
        state: Phase2MilestoneState,
    ) -> Result<(), Phase2Error> {
        if matches!(state, Phase2MilestoneState::InProgress | Phase2MilestoneState::Validated) {
            if let Some(prereq) = milestone.prerequisite() {
                if !self.state(prereq).is_validated() {
                    return Err(Phase2Error::PrerequisiteIncomplete {
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
    pub const fn state(&self, milestone: Phase2Milestone) -> Phase2MilestoneState {
        self.states[milestone as usize]
    }

    /// Return `true` when every Phase Two milestone is `Validated`.
    pub const fn all_validated(&self) -> bool {
        let mut i = 0;
        while i < PHASE2_MILESTONE_COUNT {
            if !matches!(self.states[i], Phase2MilestoneState::Validated) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Return the first not-yet-validated milestone, or `None`.
    pub fn first_unvalidated(&self) -> Option<Phase2Milestone> {
        for m in PHASE2_MILESTONES {
            if !self.state(*m).is_validated() {
                return Some(*m);
            }
        }
        None
    }

    /// Return `true` when any milestone is in the `Regressed` state.
    pub const fn any_regressed(&self) -> bool {
        let mut i = 0;
        while i < PHASE2_MILESTONE_COUNT {
            if matches!(self.states[i], Phase2MilestoneState::Regressed) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AppCategory — the seven app categories used in the coverage gate
// ─────────────────────────────────────────────────────────────────────────────

/// An Android application category covered by the Phase Two acceptance test.
///
/// The gate is "Android runs apps from every meaningful category", not merely
/// "Android boots".  The seven categories below cover the practical surface
/// area of an Android phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppCategory {
    /// Messaging / VoIP: WhatsApp, Signal, Telegram.
    Communication,
    /// Maps and navigation: OsmAnd, Organic Maps.
    MapsNavigation,
    /// Web browsing: Firefox, Vanadium, Brave.
    WebBrowsing,
    /// Media playback: NewPipe, VLC.
    MediaPlayback,
    /// Productivity: Markor, F-Droid client, Joplin.
    Productivity,
    /// Banking / attestation-sensitive: at least one bank app.
    ///
    /// Most banking apps will fail under microG because they require
    /// `MEETS_DEVICE_INTEGRITY`, which is unattainable without Google
    /// certification.  Recorded for Phase Four follow-up rather than
    /// treated as a hard pass requirement.
    BankingAttestation,
    /// Light gaming from F-Droid: open-source games.
    LightGaming,
}

/// The number of app categories.
pub const APP_CATEGORY_COUNT: usize = 7;

/// The complete list of app categories covered by Phase Two.
pub const APP_CATEGORIES: &[AppCategory] = &[
    AppCategory::Communication,
    AppCategory::MapsNavigation,
    AppCategory::WebBrowsing,
    AppCategory::MediaPlayback,
    AppCategory::Productivity,
    AppCategory::BankingAttestation,
    AppCategory::LightGaming,
];

impl AppCategory {
    /// Return `true` when this category is treated as a hard pass requirement.
    ///
    /// `BankingAttestation` is recorded for follow-up but does not gate
    /// Phase Two — the underlying attestation-failure problem is a Phase
    /// Four investigation, not a Phase Two blocker.
    pub const fn is_hard_requirement(self) -> bool {
        !matches!(self, AppCategory::BankingAttestation)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AppCategoryCoverage — per-category pass/fail tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which app categories have at least one app running successfully.
///
/// Stored as a fixed-size bitmask indexed by `AppCategory`.  Designed to be
/// cheap to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppCategoryCoverage {
    passing: [bool; APP_CATEGORY_COUNT],
}

impl AppCategoryCoverage {
    /// A coverage table with no categories yet passing.
    pub const EMPTY: Self = Self {
        passing: [false; APP_CATEGORY_COUNT],
    };

    /// A coverage table with every hard-requirement category passing.
    ///
    /// `BankingAttestation` is left `false` because the attestation failure
    /// is expected; do not lie in the gate report.
    pub const HARD_REQUIREMENTS_PASS: Self = Self {
        passing: [
            true,  // Communication
            true,  // MapsNavigation
            true,  // WebBrowsing
            true,  // MediaPlayback
            true,  // Productivity
            false, // BankingAttestation (expected fail)
            true,  // LightGaming
        ],
    };

    /// Record that a category has at least one app running.
    pub fn mark_passing(&mut self, category: AppCategory) {
        self.passing[category as usize] = true;
    }

    /// Return `true` when the given category passes.
    pub const fn is_passing(&self, category: AppCategory) -> bool {
        self.passing[category as usize]
    }

    /// Return `true` when every hard-requirement category passes.
    ///
    /// `BankingAttestation` is not required (recorded for Phase Four).
    pub const fn all_hard_requirements_passing(&self) -> bool {
        let mut i = 0;
        while i < APP_CATEGORY_COUNT {
            let cat = match i {
                0 => AppCategory::Communication,
                1 => AppCategory::MapsNavigation,
                2 => AppCategory::WebBrowsing,
                3 => AppCategory::MediaPlayback,
                4 => AppCategory::Productivity,
                5 => AppCategory::BankingAttestation,
                _ => AppCategory::LightGaming,
            };
            if cat.is_hard_requirement() && !self.passing[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Return the first hard-requirement category that does not yet pass.
    pub fn first_failing_hard_requirement(&self) -> Option<AppCategory> {
        for cat in APP_CATEGORIES {
            if cat.is_hard_requirement() && !self.is_passing(*cat) {
                return Some(*cat);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2TimelineEstimate — README estimate with realistic multipliers
// ─────────────────────────────────────────────────────────────────────────────

/// A three-point timeline estimate for Phase Two.
///
/// Uses the same multiplier constants as Phase One: realistic = optimistic × 2,
/// pessimistic = optimistic × 3.  See `roadmap_phase1` for the rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase2TimelineEstimate {
    /// Optimistic months (matches the README's stated lower bound).
    pub optimistic_months: u32,
    /// Realistic months = optimistic × REALISTIC_MULTIPLIER.
    pub realistic_months: u32,
    /// Pessimistic months = optimistic × PESSIMISTIC_MULTIPLIER.
    pub pessimistic_months: u32,
}

impl Phase2TimelineEstimate {
    /// README lower bound: 6 months for a dedicated team.
    pub const README_LOWER: Self = Self {
        optimistic_months:  6,
        realistic_months:   6 * REALISTIC_MULTIPLIER,
        pessimistic_months: 6 * PESSIMISTIC_MULTIPLIER,
    };

    /// README upper bound: 9 months for a dedicated team.
    pub const README_UPPER: Self = Self {
        optimistic_months:  9,
        realistic_months:   9 * REALISTIC_MULTIPLIER,
        pessimistic_months: 9 * PESSIMISTIC_MULTIPLIER,
    };

    /// Validate that the estimate is non-zero and monotonic.
    pub fn validate(&self) -> Result<(), Phase2Error> {
        if self.optimistic_months == 0 {
            return Err(Phase2Error::TimelineEstimateZero);
        }
        if self.realistic_months < self.optimistic_months
            || self.pessimistic_months < self.realistic_months
        {
            return Err(Phase2Error::TimelineEstimateMonotonicityViolated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2GateCriterion — the Phase Two acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// The Phase Two acceptance test, expressed as a set of boolean checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase2GateCriterion {
    /// AOSP image is `ro.build.type = user` — required for SafetyNet basic
    /// integrity and the Phase Two gate; userdebug / eng fail.
    pub build_type: BuildType,
    /// SurfaceFlinger composes frames on the Adreno SR-IOV VF and the system
    /// UI is visible (i.e. the user can interact with Android).
    pub adreno_vf_rendering: bool,
    /// microG `MEETS_BASIC_INTEGRITY` is achieved.  This is the maximum
    /// Play Integrity verdict possible without Google certification.
    pub microg_basic_integrity: bool,
    /// Hard-requirement app categories all pass (see `AppCategoryCoverage`).
    pub hard_app_categories_pass: bool,
    /// 24-hour soak run on real hardware passes without crash, hang, or
    /// resource exhaustion.
    pub soak_passes_on_hardware: bool,
    /// No `MEETS_DEVICE_INTEGRITY` claim is made.  This stronger verdict is
    /// unattainable by design; a `true` value here indicates a misconfigured
    /// gate, not a pass.
    pub claims_device_integrity: bool,
}

impl Phase2GateCriterion {
    /// The state required to pass Phase Two.
    pub const PASSING: Self = Self {
        build_type:               BuildType::User,
        adreno_vf_rendering:      true,
        microg_basic_integrity:   true,
        hard_app_categories_pass: true,
        soak_passes_on_hardware:  true,
        claims_device_integrity:  false,
    };

    /// Return `true` only when every check is met.
    pub const fn passes(self) -> bool {
        matches!(self.build_type, BuildType::User)
            && self.adreno_vf_rendering
            && self.microg_basic_integrity
            && self.hard_app_categories_pass
            && self.soak_passes_on_hardware
            && !self.claims_device_integrity
    }

    /// Validate the gate criterion.
    pub fn validate(&self) -> Result<(), Phase2Error> {
        if !matches!(self.build_type, BuildType::User) {
            return Err(Phase2Error::BuildTypeNotUser {
                build_type: self.build_type,
            });
        }
        if self.claims_device_integrity {
            return Err(Phase2Error::DeviceIntegrityClaimed);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2Config — aggregate configuration + validation
// ─────────────────────────────────────────────────────────────────────────────

/// The aggregate configuration for Phase Two.
#[derive(Debug)]
pub struct Phase2Config {
    /// Phase One readiness — Phase Two cannot start until Phase One closes.
    pub phase1: Phase1Summary,
    /// Three-point timeline estimate for Phase Two.
    pub timeline: Phase2TimelineEstimate,
    /// Per-milestone progress state.
    pub tracker: Phase2Tracker,
    /// App-category coverage state.
    pub coverage: AppCategoryCoverage,
    /// The maximum Play Integrity verdict the configuration may claim.
    ///
    /// Must be `PlayIntegrityMaxVerdict::BasicOnly` — the stronger
    /// `MEETS_DEVICE_INTEGRITY` verdict is unattainable without Google
    /// certification, and claiming it makes the gate dishonest.
    pub max_verdict: PlayIntegrityMaxVerdict,
    /// The Phase Two gate criterion.
    pub gate: Phase2GateCriterion,
}

impl Phase2Config {
    /// Validate the complete Phase Two configuration.
    ///
    /// Checks (in order):
    ///   1. Phase One is complete (the entry gate).
    ///   2. Timeline estimate is non-zero and monotonic.
    ///   3. No milestone is in the `Regressed` state.
    ///   4. The first Phase Two milestone (`Phase1GateClosed`) is `Validated`
    ///      iff the Phase One summary reports complete.
    ///   5. App-category coverage hard requirements all pass.
    ///   6. `max_verdict` is `BasicOnly` (no `DeviceIntegrity` claim).
    ///   7. Gate criterion validates (user build, no device-integrity claim).
    pub fn validate(&self) -> Result<(), Phase2Error> {
        if !self.phase1.phase1_complete() {
            return Err(Phase2Error::Phase1NotComplete);
        }
        self.timeline.validate()?;
        if self.tracker.any_regressed() {
            return Err(Phase2Error::MilestoneRegressed);
        }
        // Phase 1 gate state must mirror the Phase 1 summary
        if self.phase1.phase1_complete()
            && !self.tracker.state(Phase2Milestone::Phase1GateClosed).is_validated()
        {
            return Err(Phase2Error::Phase1GateNotRecorded);
        }
        if !self.coverage.all_hard_requirements_passing() {
            return Err(Phase2Error::AppCategoryCoverageIncomplete {
                first_failing: self.coverage.first_failing_hard_requirement().unwrap_or(AppCategory::Communication),
            });
        }
        if !matches!(self.max_verdict, PlayIntegrityMaxVerdict::BasicOnly) {
            return Err(Phase2Error::DeviceIntegrityClaimed);
        }
        self.gate.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2Summary — high-level readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Phase Two readiness gate.
#[derive(Debug)]
pub struct Phase2Summary {
    /// True when Phase One is complete.
    pub phase1_complete: bool,
    /// True when every Phase Two milestone is `Validated`.
    pub all_milestones_validated: bool,
    /// True when every hard-requirement app category passes.
    pub app_coverage_complete: bool,
    /// True when the gate criterion passes (user build, no DeviceIntegrity).
    pub gate_passes: bool,
}

impl Phase2Summary {
    /// Return `true` when Phase Two is complete and Phase Three can begin.
    pub fn phase2_complete(&self) -> bool {
        self.phase1_complete
            && self.all_milestones_validated
            && self.app_coverage_complete
            && self.gate_passes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase2Error — errors returned by Phase Two configuration validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by Phase Two configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase2Error {
    /// Phase One has not been completed.  Phase Two cannot start.
    Phase1NotComplete,
    /// Phase One is complete but the tracker does not reflect this.
    ///
    /// `Phase2Milestone::Phase1GateClosed` must be `Validated` whenever the
    /// embedded `Phase1Summary::phase1_complete()` returns `true`.
    Phase1GateNotRecorded,
    /// A milestone was advanced before its prerequisite was `Validated`.
    PrerequisiteIncomplete {
        /// The milestone being advanced.
        milestone:    Phase2Milestone,
        /// The prerequisite that is not yet `Validated`.
        prerequisite: Phase2Milestone,
    },
    /// A timeline estimate is zero months.
    TimelineEstimateZero,
    /// Timeline estimates are not monotonically non-decreasing.
    TimelineEstimateMonotonicityViolated,
    /// At least one milestone is in the `Regressed` state.
    MilestoneRegressed,
    /// At least one hard-requirement app category does not yet pass.
    AppCategoryCoverageIncomplete {
        /// The first failing hard-requirement category.
        first_failing: AppCategory,
    },
    /// The configuration claims `MEETS_DEVICE_INTEGRITY`, which is
    /// unattainable without Google certification.
    DeviceIntegrityClaimed,
    /// AOSP build type is not `User` — fails SafetyNet basic integrity and
    /// the Phase Two gate.
    BuildTypeNotUser {
        /// The non-user build type that was rejected.
        build_type: BuildType,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_phase1_summary() -> Phase1Summary {
        Phase1Summary {
            research_complete:        true,
            timeline_coherent:        true,
            workflow_ready:           true,
            all_milestones_validated: true,
            gate_passes:              true,
        }
    }

    // ── Phase2Milestone ───────────────────────────────────────────────────────

    #[test]
    fn first_milestone_has_no_prerequisite() {
        assert_eq!(Phase2Milestone::Phase1GateClosed.prerequisite(), None);
    }

    #[test]
    fn every_other_milestone_has_a_prerequisite() {
        for m in PHASE2_MILESTONES.iter().skip(1) {
            assert!(m.prerequisite().is_some(), "{:?} missing prerequisite", m);
        }
    }

    #[test]
    fn milestone_chain_is_linear() {
        let mut visited = 0;
        let mut cur = Some(*PHASE2_MILESTONES.last().unwrap());
        while let Some(m) = cur {
            visited += 1;
            cur = m.prerequisite();
        }
        assert_eq!(visited, PHASE2_MILESTONE_COUNT);
    }

    #[test]
    fn final_milestone_requires_real_hardware() {
        assert_eq!(
            Phase2Milestone::AndroidStableOnHardware.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn other_milestones_use_qemu_linux_guest_tier() {
        for m in PHASE2_MILESTONES {
            if *m != Phase2Milestone::AndroidStableOnHardware {
                assert_eq!(m.validation_tier(), TestTier::QemuLinuxGuest);
            }
        }
    }

    #[test]
    fn milestone_labels_are_nonempty() {
        for m in PHASE2_MILESTONES {
            assert!(!m.label().is_empty());
        }
    }

    #[test]
    fn milestone_count_matches_list_length() {
        assert_eq!(PHASE2_MILESTONES.len(), PHASE2_MILESTONE_COUNT);
    }

    // ── Phase2Tracker ─────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_all_not_started() {
        let t = Phase2Tracker::NEW;
        for m in PHASE2_MILESTONES {
            assert_eq!(t.state(*m), Phase2MilestoneState::NotStarted);
        }
    }

    #[test]
    fn first_milestone_can_be_set_without_prerequisite() {
        let mut t = Phase2Tracker::NEW;
        assert!(t.set_state(Phase2Milestone::Phase1GateClosed, Phase2MilestoneState::Validated).is_ok());
    }

    #[test]
    fn cannot_advance_without_prerequisite() {
        let mut t = Phase2Tracker::NEW;
        let r = t.set_state(Phase2Milestone::AospSourceSynced, Phase2MilestoneState::InProgress);
        assert_eq!(
            r,
            Err(Phase2Error::PrerequisiteIncomplete {
                milestone:    Phase2Milestone::AospSourceSynced,
                prerequisite: Phase2Milestone::Phase1GateClosed,
            })
        );
    }

    #[test]
    fn linear_progression_validates_every_milestone() {
        let mut t = Phase2Tracker::NEW;
        for m in PHASE2_MILESTONES {
            t.set_state(*m, Phase2MilestoneState::Validated).expect("linear must succeed");
        }
        assert!(t.all_validated());
        assert_eq!(t.first_unvalidated(), None);
    }

    #[test]
    fn first_unvalidated_finds_blocker() {
        let mut t = Phase2Tracker::NEW;
        t.set_state(Phase2Milestone::Phase1GateClosed, Phase2MilestoneState::Validated).unwrap();
        assert_eq!(t.first_unvalidated(), Some(Phase2Milestone::AospSourceSynced));
    }

    #[test]
    fn regression_detected() {
        let mut t = Phase2Tracker::NEW;
        t.set_state(Phase2Milestone::Phase1GateClosed, Phase2MilestoneState::Validated).unwrap();
        t.set_state(Phase2Milestone::Phase1GateClosed, Phase2MilestoneState::Regressed).unwrap();
        assert!(t.any_regressed());
    }

    // ── AppCategoryCoverage ───────────────────────────────────────────────────

    #[test]
    fn empty_coverage_does_not_pass() {
        assert!(!AppCategoryCoverage::EMPTY.all_hard_requirements_passing());
    }

    #[test]
    fn hard_requirements_preset_passes() {
        assert!(AppCategoryCoverage::HARD_REQUIREMENTS_PASS.all_hard_requirements_passing());
    }

    #[test]
    fn banking_attestation_is_not_hard_requirement() {
        assert!(!AppCategory::BankingAttestation.is_hard_requirement());
    }

    #[test]
    fn every_other_category_is_hard_requirement() {
        for cat in APP_CATEGORIES {
            if *cat != AppCategory::BankingAttestation {
                assert!(cat.is_hard_requirement(), "{:?} should be hard requirement", cat);
            }
        }
    }

    #[test]
    fn missing_communication_fails_coverage() {
        let mut c = AppCategoryCoverage::HARD_REQUIREMENTS_PASS;
        c.passing[AppCategory::Communication as usize] = false;
        assert!(!c.all_hard_requirements_passing());
        assert_eq!(c.first_failing_hard_requirement(), Some(AppCategory::Communication));
    }

    #[test]
    fn mark_passing_records_category() {
        let mut c = AppCategoryCoverage::EMPTY;
        c.mark_passing(AppCategory::WebBrowsing);
        assert!(c.is_passing(AppCategory::WebBrowsing));
        assert!(!c.is_passing(AppCategory::Communication));
    }

    #[test]
    fn app_category_count_matches() {
        assert_eq!(APP_CATEGORIES.len(), APP_CATEGORY_COUNT);
    }

    // ── Phase2TimelineEstimate ────────────────────────────────────────────────

    #[test]
    fn readme_lower_validates_ok() {
        assert!(Phase2TimelineEstimate::README_LOWER.validate().is_ok());
    }

    #[test]
    fn readme_upper_validates_ok() {
        assert!(Phase2TimelineEstimate::README_UPPER.validate().is_ok());
    }

    #[test]
    fn readme_lower_realistic_is_12_months() {
        // 6 months optimistic × 2 = 12 realistic
        assert_eq!(Phase2TimelineEstimate::README_LOWER.realistic_months, 12);
    }

    #[test]
    fn readme_upper_pessimistic_is_27_months() {
        // 9 months optimistic × 3 = 27 pessimistic
        assert_eq!(Phase2TimelineEstimate::README_UPPER.pessimistic_months, 27);
    }

    #[test]
    fn zero_optimistic_rejected() {
        let e = Phase2TimelineEstimate {
            optimistic_months: 0,
            realistic_months:  0,
            pessimistic_months: 0,
        };
        assert_eq!(e.validate(), Err(Phase2Error::TimelineEstimateZero));
    }

    #[test]
    fn nonmonotonic_rejected() {
        let e = Phase2TimelineEstimate {
            optimistic_months:  9,
            realistic_months:   3,
            pessimistic_months: 27,
        };
        assert_eq!(e.validate(), Err(Phase2Error::TimelineEstimateMonotonicityViolated));
    }

    // ── Phase2GateCriterion ───────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(Phase2GateCriterion::PASSING.passes());
    }

    #[test]
    fn passing_gate_validates() {
        assert!(Phase2GateCriterion::PASSING.validate().is_ok());
    }

    #[test]
    fn userdebug_fails_gate() {
        let g = Phase2GateCriterion {
            build_type: BuildType::Userdebug,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(
            g.validate(),
            Err(Phase2Error::BuildTypeNotUser { build_type: BuildType::Userdebug })
        );
    }

    #[test]
    fn eng_fails_gate() {
        let g = Phase2GateCriterion {
            build_type: BuildType::Eng,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn device_integrity_claim_fails_gate() {
        let g = Phase2GateCriterion {
            claims_device_integrity: true,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase2Error::DeviceIntegrityClaimed));
    }

    #[test]
    fn missing_adreno_fails_gate() {
        let g = Phase2GateCriterion {
            adreno_vf_rendering: false,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_basic_integrity_fails_gate() {
        let g = Phase2GateCriterion {
            microg_basic_integrity: false,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_soak_fails_gate() {
        let g = Phase2GateCriterion {
            soak_passes_on_hardware: false,
            ..Phase2GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    // ── Phase2Config ──────────────────────────────────────────────────────────

    fn fully_validated_phase2_tracker() -> Phase2Tracker {
        let mut t = Phase2Tracker::NEW;
        for m in PHASE2_MILESTONES {
            t.set_state(*m, Phase2MilestoneState::Validated).unwrap();
        }
        t
    }

    fn passing_phase2_config() -> Phase2Config {
        Phase2Config {
            phase1:       complete_phase1_summary(),
            timeline:     Phase2TimelineEstimate::README_LOWER,
            tracker:      fully_validated_phase2_tracker(),
            coverage:     AppCategoryCoverage::HARD_REQUIREMENTS_PASS,
            max_verdict:  PlayIntegrityMaxVerdict::BasicOnly,
            gate:         Phase2GateCriterion::PASSING,
        }
    }

    #[test]
    fn passing_phase2_config_validates() {
        assert!(passing_phase2_config().validate().is_ok());
    }

    #[test]
    fn config_rejects_incomplete_phase1() {
        let mut p1 = complete_phase1_summary();
        p1.gate_passes = false;
        let cfg = Phase2Config {
            phase1: p1,
            ..passing_phase2_config()
        };
        assert_eq!(cfg.validate(), Err(Phase2Error::Phase1NotComplete));
    }

    #[test]
    fn config_rejects_unrecorded_phase1_gate() {
        let mut tracker = fully_validated_phase2_tracker();
        // Phase 1 summary says complete, but tracker says Phase1GateClosed is not Validated.
        tracker.states[Phase2Milestone::Phase1GateClosed as usize] = Phase2MilestoneState::InProgress;
        let cfg = Phase2Config {
            tracker,
            ..passing_phase2_config()
        };
        assert_eq!(cfg.validate(), Err(Phase2Error::Phase1GateNotRecorded));
    }

    #[test]
    fn config_rejects_regression() {
        let mut tracker = fully_validated_phase2_tracker();
        tracker
            .set_state(Phase2Milestone::AdrenoVfRendersUi, Phase2MilestoneState::Regressed)
            .unwrap();
        let cfg = Phase2Config {
            tracker,
            ..passing_phase2_config()
        };
        assert_eq!(cfg.validate(), Err(Phase2Error::MilestoneRegressed));
    }

    #[test]
    fn config_rejects_incomplete_coverage() {
        let mut coverage = AppCategoryCoverage::HARD_REQUIREMENTS_PASS;
        coverage.passing[AppCategory::WebBrowsing as usize] = false;
        let cfg = Phase2Config {
            coverage,
            ..passing_phase2_config()
        };
        assert_eq!(
            cfg.validate(),
            Err(Phase2Error::AppCategoryCoverageIncomplete { first_failing: AppCategory::WebBrowsing })
        );
    }

    #[test]
    fn config_rejects_userdebug_build() {
        let cfg = Phase2Config {
            gate: Phase2GateCriterion {
                build_type: BuildType::Userdebug,
                ..Phase2GateCriterion::PASSING
            },
            ..passing_phase2_config()
        };
        assert_eq!(
            cfg.validate(),
            Err(Phase2Error::BuildTypeNotUser { build_type: BuildType::Userdebug })
        );
    }

    // ── Phase2Summary ─────────────────────────────────────────────────────────

    #[test]
    fn phase2_summary_complete() {
        let s = Phase2Summary {
            phase1_complete:          true,
            all_milestones_validated: true,
            app_coverage_complete:    true,
            gate_passes:              true,
        };
        assert!(s.phase2_complete());
    }

    #[test]
    fn phase2_summary_partial_not_complete() {
        let cases = [
            Phase2Summary { phase1_complete: false, all_milestones_validated: true,  app_coverage_complete: true,  gate_passes: true  },
            Phase2Summary { phase1_complete: true,  all_milestones_validated: false, app_coverage_complete: true,  gate_passes: true  },
            Phase2Summary { phase1_complete: true,  all_milestones_validated: true,  app_coverage_complete: false, gate_passes: true  },
            Phase2Summary { phase1_complete: true,  all_milestones_validated: true,  app_coverage_complete: true,  gate_passes: false },
        ];
        for s in &cases {
            assert!(!s.phase2_complete(), "expected not-complete for {:?}", s);
        }
    }
}
