// ch33: Phase Five — Polish And Release
//
// Phase Five takes a working, performant, app-compatible AETHER and brings it
// to public release.  README estimate: 6–12 months for a dedicated team;
// multiply by 2–3 for part-time work.
//
// ── Phase Five Definition ─────────────────────────────────────────────────────
//
// Phase Five delivers:
//
//   - Installer (UEFI app + scripts that detect tier, partition NVMe,
//     populate Secure Boot keys, flash AETHER and Android, register UEFI
//     boot entry)
//   - Configuration tools (CLI + minimal GUI for Phone Bridge toggle, sensor
//     model selection, Aurora account mode)
//   - Documentation (user manual, contributor guide, troubleshooting guide,
//     architecture overview that matches the code)
//   - Support infrastructure (issue tracker, security disclosure mailbox,
//     contributor agreement, code review workflow)
//   - Cross-partition input switching mechanism (hardware-triggered Ctrl+Alt
//     +Tab routed via ch16; software trigger always returns Forbidden)
//   - Open source licenses (GPLv2 or MIT for hypervisor core, Apache 2.0 for
//     AOSP overlays, Creative Commons for documentation, MIT for installer)
//   - Public release on GitHub with a clear contributor guide and a
//     documented Phase 6+ roadmap
//
// Sustaining development after release requires either commercial revenue
// (enterprise licensing, OEM deals) or contributor volume; without one of
// these the project stalls.  Phase Five is the point at which the project
// either becomes a public concern or remains a personal one.
//
// ── Entry Gate: Phase Four Complete ───────────────────────────────────────────
//
// Releasing a polished but performance-broken Android is worse than releasing
// nothing — the project's reputation is established by first impressions.
// Phase Five must wait for Phase Four to close honestly.

use crate::development_workflow::TestTier;
use crate::roadmap_phase1::{PESSIMISTIC_MULTIPLIER, REALISTIC_MULTIPLIER};
use crate::roadmap_phase4::Phase4Summary;

// ─────────────────────────────────────────────────────────────────────────────
// LicenseChoice — open-source license per artifact
// ─────────────────────────────────────────────────────────────────────────────

/// The open-source licenses AETHER uses for its public release.
///
/// The selection is constrained by upstream choices (AOSP is Apache 2.0; many
/// kernel-adjacent components are GPLv2) and by AETHER's own preference for
/// permissive licensing where compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseChoice {
    /// GPL v2 — used for the hypervisor core when GPL contamination is
    /// acceptable (e.g., if Linux kernel headers are statically linked).
    GplV2,
    /// MIT — permissive license for the installer, tooling, and any code
    /// without a GPL upstream constraint.
    Mit,
    /// Apache 2.0 — AETHER's AOSP overlays inherit this from upstream AOSP.
    Apache2,
    /// Creative Commons Attribution-ShareAlike — documentation and the
    /// README/SKILL.md files.
    CcBySa,
    /// Proprietary — explicitly rejected for any AETHER component.
    ///
    /// Listed only so configuration validation can reject it: a proprietary
    /// component in the release blocks community audit and undermines trust.
    Proprietary,
}

impl LicenseChoice {
    /// Return `true` when this license is acceptable for an AETHER release.
    ///
    /// All four open-source choices are acceptable.  Proprietary is rejected.
    pub const fn is_acceptable(self) -> bool {
        !matches!(self, LicenseChoice::Proprietary)
    }

    /// Return `true` when this license permits closed-source derivative works
    /// (i.e., it is permissive rather than copyleft).
    pub const fn is_permissive(self) -> bool {
        matches!(self, LicenseChoice::Mit | LicenseChoice::Apache2)
    }
}

/// The license assignment for the four AETHER release components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseAssignment {
    /// License for the hypervisor core (Rust crate).
    pub hypervisor_core: LicenseChoice,
    /// License for AOSP overlays (the `device/aether/...` directories).
    pub aosp_overlays: LicenseChoice,
    /// License for the documentation (README, SKILL.md, user manual).
    pub documentation: LicenseChoice,
    /// License for the installer and tooling.
    pub installer_and_tools: LicenseChoice,
}

impl LicenseAssignment {
    /// The recommended assignment per the SKILL.md guidance:
    ///   - Hypervisor core: GPL v2 (security-critical, copyleft chosen so
    ///     forks remain auditable)
    ///   - AOSP overlays: Apache 2.0 (inherited from AOSP)
    ///   - Documentation: CC BY-SA
    ///   - Installer / tooling: MIT (permissive — encourages commercial OEM
    ///     adoption without GPL contamination of vendor toolchains)
    pub const RECOMMENDED: Self = Self {
        hypervisor_core:     LicenseChoice::GplV2,
        aosp_overlays:       LicenseChoice::Apache2,
        documentation:       LicenseChoice::CcBySa,
        installer_and_tools: LicenseChoice::Mit,
    };

    /// Validate the license assignment.
    ///
    /// Rejects proprietary anywhere.  Also rejects an AOSP overlay license
    /// other than Apache 2.0 — AOSP is Apache-licensed and the overlay
    /// inherits the constraint.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.hypervisor_core.is_acceptable() {
            return Err(Phase5Error::ProprietaryLicense { component: "hypervisor core" });
        }
        if !self.aosp_overlays.is_acceptable() {
            return Err(Phase5Error::ProprietaryLicense { component: "AOSP overlays" });
        }
        if !self.documentation.is_acceptable() {
            return Err(Phase5Error::ProprietaryLicense { component: "documentation" });
        }
        if !self.installer_and_tools.is_acceptable() {
            return Err(Phase5Error::ProprietaryLicense { component: "installer and tools" });
        }
        if !matches!(self.aosp_overlays, LicenseChoice::Apache2) {
            return Err(Phase5Error::AospOverlayLicenseNotApache2 { actual: self.aosp_overlays });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallerCapability — what the installer must do
// ─────────────────────────────────────────────────────────────────────────────

/// The capabilities the AETHER installer must provide.
///
/// Skipping any of these capabilities makes the installation either
/// dangerous (e.g., no Secure Boot enrollment) or impractical (e.g., no
/// tier auto-detection — user must specify ARM vs x86 manually).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallerCapabilities {
    /// Auto-detect ARM tier vs x86 tier at install time.
    ///
    /// Without this the user must specify the tier manually, which is
    /// error-prone and produces unbootable installs.
    pub auto_detect_tier: bool,
    /// Partition the NVMe device into Android + AETHER EFI partitions.
    pub partition_nvme: bool,
    /// Enroll Secure Boot keys (PK → KEK → db → dbx) so the firmware
    /// trusts AETHER's signed binaries.
    ///
    /// Without this the installation works only with Secure Boot disabled,
    /// which weakens the security baseline of the platform.
    pub enroll_secure_boot_keys: bool,
    /// Register the AETHER UEFI boot entry as the default boot target.
    pub register_uefi_boot_entry: bool,
    /// Flash the Android boot/system/vendor partitions.
    pub flash_android: bool,
    /// Persist a recovery image that can restore the previous OS if AETHER
    /// fails to boot.
    pub recovery_image: bool,
}

impl InstallerCapabilities {
    /// The required capability set for a Phase Five release.
    pub const REQUIRED: Self = Self {
        auto_detect_tier:         true,
        partition_nvme:           true,
        enroll_secure_boot_keys:  true,
        register_uefi_boot_entry: true,
        flash_android:            true,
        recovery_image:           true,
    };

    /// Return `true` when every required capability is present.
    pub const fn complete(self) -> bool {
        self.auto_detect_tier
            && self.partition_nvme
            && self.enroll_secure_boot_keys
            && self.register_uefi_boot_entry
            && self.flash_android
            && self.recovery_image
    }

    /// Validate the capability set.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.auto_detect_tier {
            return Err(Phase5Error::InstallerMissingCapability { capability: "auto_detect_tier" });
        }
        if !self.partition_nvme {
            return Err(Phase5Error::InstallerMissingCapability { capability: "partition_nvme" });
        }
        if !self.enroll_secure_boot_keys {
            return Err(Phase5Error::InstallerMissingCapability { capability: "enroll_secure_boot_keys" });
        }
        if !self.register_uefi_boot_entry {
            return Err(Phase5Error::InstallerMissingCapability { capability: "register_uefi_boot_entry" });
        }
        if !self.flash_android {
            return Err(Phase5Error::InstallerMissingCapability { capability: "flash_android" });
        }
        if !self.recovery_image {
            return Err(Phase5Error::InstallerMissingCapability { capability: "recovery_image" });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DocumentationDeliverable — required docs for a release
// ─────────────────────────────────────────────────────────────────────────────

/// The documents AETHER must ship at public release.
///
/// Per the SKILL.md guidance: "the Phase 5 release should include a clear
/// contributor guide, a documented architecture that matches the code, a
/// test suite with documented coverage targets, and a public roadmap for
/// Phase 6 features".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentationDeliverables {
    /// User manual: how to install, run, switch partitions, toggle Phone
    /// Bridge Mode, troubleshoot.
    pub user_manual: bool,
    /// Contributor guide: how to build, run tests, submit a PR, the code
    /// review workflow, the contributor agreement.
    pub contributor_guide: bool,
    /// Architecture document that matches the code as shipped.
    ///
    /// "Documents the architecture as it actually is" — not as it was
    /// planned three years ago.
    pub architecture_doc: bool,
    /// Troubleshooting guide for common installation and runtime failures.
    pub troubleshooting_guide: bool,
    /// Public Phase 6+ roadmap (multi-monitor, audio passthrough, suspend/
    /// resume, etc.).
    pub phase6_roadmap: bool,
    /// Test-suite coverage report with documented coverage targets.
    pub coverage_report: bool,
    /// Security disclosure policy (where to report, how response works,
    /// embargo conventions).
    pub security_disclosure: bool,
}

impl DocumentationDeliverables {
    /// The required deliverable set for Phase Five.
    pub const REQUIRED: Self = Self {
        user_manual:           true,
        contributor_guide:     true,
        architecture_doc:      true,
        troubleshooting_guide: true,
        phase6_roadmap:        true,
        coverage_report:       true,
        security_disclosure:   true,
    };

    /// Return `true` when every required document is present.
    pub const fn complete(self) -> bool {
        self.user_manual
            && self.contributor_guide
            && self.architecture_doc
            && self.troubleshooting_guide
            && self.phase6_roadmap
            && self.coverage_report
            && self.security_disclosure
    }

    /// Validate the deliverable set.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.user_manual {
            return Err(Phase5Error::DocumentationMissing { document: "user_manual" });
        }
        if !self.contributor_guide {
            return Err(Phase5Error::DocumentationMissing { document: "contributor_guide" });
        }
        if !self.architecture_doc {
            return Err(Phase5Error::DocumentationMissing { document: "architecture_doc" });
        }
        if !self.troubleshooting_guide {
            return Err(Phase5Error::DocumentationMissing { document: "troubleshooting_guide" });
        }
        if !self.phase6_roadmap {
            return Err(Phase5Error::DocumentationMissing { document: "phase6_roadmap" });
        }
        if !self.coverage_report {
            return Err(Phase5Error::DocumentationMissing { document: "coverage_report" });
        }
        if !self.security_disclosure {
            return Err(Phase5Error::DocumentationMissing { document: "security_disclosure" });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SupportInfrastructure — the support stack required at release
// ─────────────────────────────────────────────────────────────────────────────

/// The support infrastructure required at public release.
///
/// Without these in place, the project stalls quickly after release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportInfrastructure {
    /// Public issue tracker (GitHub Issues, GitLab, or equivalent).
    pub issue_tracker: bool,
    /// Security disclosure mailbox (e.g., `security@aether.example`).
    pub security_mailbox: bool,
    /// Code review workflow documented (e.g., "two approvals required for
    /// hypervisor/src, one for docs").
    pub code_review_workflow: bool,
    /// Contributor License Agreement (CLA) or DCO sign-off requirement,
    /// whichever the project chooses.
    pub cla_or_dco: bool,
    /// Public CI dashboard so contributors can see build / test status of
    /// every PR.
    pub public_ci_dashboard: bool,
}

impl SupportInfrastructure {
    /// The required support infrastructure for Phase Five.
    pub const REQUIRED: Self = Self {
        issue_tracker:       true,
        security_mailbox:    true,
        code_review_workflow: true,
        cla_or_dco:          true,
        public_ci_dashboard: true,
    };

    /// Return `true` when every required component is present.
    pub const fn complete(self) -> bool {
        self.issue_tracker
            && self.security_mailbox
            && self.code_review_workflow
            && self.cla_or_dco
            && self.public_ci_dashboard
    }

    /// Validate the support infrastructure.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.issue_tracker {
            return Err(Phase5Error::SupportMissing { component: "issue_tracker" });
        }
        if !self.security_mailbox {
            return Err(Phase5Error::SupportMissing { component: "security_mailbox" });
        }
        if !self.code_review_workflow {
            return Err(Phase5Error::SupportMissing { component: "code_review_workflow" });
        }
        if !self.cla_or_dco {
            return Err(Phase5Error::SupportMissing { component: "cla_or_dco" });
        }
        if !self.public_ci_dashboard {
            return Err(Phase5Error::SupportMissing { component: "public_ci_dashboard" });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrossPartitionInputSwitch — the input switching mechanism gate
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the cross-partition input switching mechanism.
///
/// Implementation is in ch16; Phase Five validates that the mechanism is
/// integrated into the release and configured securely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossPartitionInputSwitch {
    /// The hardware trigger is enabled and reachable from the EL2 HID
    /// boot-protocol path.
    pub hardware_trigger_active: bool,
    /// All software-trigger paths are rejected (`reject_software_switch`
    /// returns `SoftwareSwitchForbidden`).  Required.
    pub software_trigger_rejected: bool,
    /// xHCI reset is issued automatically on every controller reassignment.
    pub xhci_reset_on_reassignment: bool,
    /// The integrated input controller's SMMU STE is configured before any
    /// switch is permitted.
    pub smmu_required_for_switch: bool,
}

impl CrossPartitionInputSwitch {
    /// The production configuration: hardware-only, software rejected,
    /// xHCI reset + SMMU mandatory.
    pub const PRODUCTION: Self = Self {
        hardware_trigger_active:     true,
        software_trigger_rejected:   true,
        xhci_reset_on_reassignment:  true,
        smmu_required_for_switch:    true,
    };

    /// Validate the input-switch configuration.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.hardware_trigger_active {
            return Err(Phase5Error::InputSwitchHardwareTriggerInactive);
        }
        if !self.software_trigger_rejected {
            return Err(Phase5Error::InputSwitchSoftwareTriggerAllowed);
        }
        if !self.xhci_reset_on_reassignment {
            return Err(Phase5Error::InputSwitchXhciResetMissing);
        }
        if !self.smmu_required_for_switch {
            return Err(Phase5Error::InputSwitchSmmuNotRequired);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5Milestone
// ─────────────────────────────────────────────────────────────────────────────

/// A single milestone within Phase Five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase5Milestone {
    /// Phase Four complete on both tiers.  Entry gate.
    Phase4GateClosed,
    /// License assignment finalised and reflected in every source file
    /// header.
    LicenseAssigned,
    /// Installer feature-complete: tier auto-detection, NVMe partitioning,
    /// Secure Boot enrollment, UEFI boot-entry registration, Android flash,
    /// recovery image creation.
    InstallerFeatureComplete,
    /// Cross-partition input switch tested end-to-end with the production
    /// hardware-only trigger (ch16).
    InputSwitchValidated,
    /// Configuration tools (CLI + minimal GUI) shipped for Phone Bridge
    /// toggle, sensor model selection, Aurora account mode.
    ConfigurationToolsShipped,
    /// User manual + contributor guide + architecture doc + troubleshooting
    /// guide + Phase 6+ roadmap + coverage report + security disclosure
    /// policy all written and reviewed.
    DocumentationDelivered,
    /// Support infrastructure operational: issue tracker, security mailbox,
    /// code review workflow, CLA/DCO, public CI dashboard.
    SupportInfrastructureLive,
    /// Public release candidate published on a staging branch with a small
    /// beta cohort exercising it.
    ReleaseCandidatePublished,
    /// Final public release published with v1.0 tag.  Phase Five closes.
    PublicReleaseShipped,
}

impl Phase5Milestone {
    /// Strict prerequisite milestone, or `None` for the first.
    pub const fn prerequisite(self) -> Option<Phase5Milestone> {
        use Phase5Milestone::*;
        match self {
            Phase4GateClosed          => None,
            LicenseAssigned           => Some(Phase4GateClosed),
            InstallerFeatureComplete  => Some(LicenseAssigned),
            InputSwitchValidated      => Some(InstallerFeatureComplete),
            ConfigurationToolsShipped => Some(InputSwitchValidated),
            DocumentationDelivered    => Some(ConfigurationToolsShipped),
            SupportInfrastructureLive => Some(DocumentationDelivered),
            ReleaseCandidatePublished => Some(SupportInfrastructureLive),
            PublicReleaseShipped      => Some(ReleaseCandidatePublished),
        }
    }

    /// The development tier at which this milestone is first validated.
    pub const fn validation_tier(self) -> TestTier {
        use Phase5Milestone::*;
        match self {
            PublicReleaseShipped      => TestTier::RealHardware,
            InstallerFeatureComplete  => TestTier::RealHardware,
            InputSwitchValidated      => TestTier::RealHardware,
            ReleaseCandidatePublished => TestTier::RealHardware,
            _                          => TestTier::QemuLinuxGuest,
        }
    }

    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        use Phase5Milestone::*;
        match self {
            Phase4GateClosed          => "Phase 4 gate closed",
            LicenseAssigned           => "license assigned",
            InstallerFeatureComplete  => "installer feature complete",
            InputSwitchValidated      => "input switch validated",
            ConfigurationToolsShipped => "configuration tools shipped",
            DocumentationDelivered    => "documentation delivered",
            SupportInfrastructureLive => "support infrastructure live",
            ReleaseCandidatePublished => "release candidate published",
            PublicReleaseShipped      => "public release shipped",
        }
    }
}

/// The number of Phase Five milestones.
pub const PHASE5_MILESTONE_COUNT: usize = 9;

/// The complete ordered sequence of Phase Five milestones.
pub const PHASE5_MILESTONES: &[Phase5Milestone] = &[
    Phase5Milestone::Phase4GateClosed,
    Phase5Milestone::LicenseAssigned,
    Phase5Milestone::InstallerFeatureComplete,
    Phase5Milestone::InputSwitchValidated,
    Phase5Milestone::ConfigurationToolsShipped,
    Phase5Milestone::DocumentationDelivered,
    Phase5Milestone::SupportInfrastructureLive,
    Phase5Milestone::ReleaseCandidatePublished,
    Phase5Milestone::PublicReleaseShipped,
];

// ─────────────────────────────────────────────────────────────────────────────
// Phase5MilestoneState + Phase5Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// The lifecycle state of a single Phase Five milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase5MilestoneState {
    /// Work has not begun.
    NotStarted,
    /// Work is underway but validation has not passed cleanly.
    InProgress,
    /// Validation tier passed cleanly without workarounds.
    Validated,
    /// Previously `Validated` but later regressed.
    Regressed,
}

impl Phase5MilestoneState {
    /// Return `true` only when the milestone passes its validation today.
    pub const fn is_validated(self) -> bool {
        matches!(self, Phase5MilestoneState::Validated)
    }
}

/// Tracks the state of every Phase Five milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase5Tracker {
    states: [Phase5MilestoneState; PHASE5_MILESTONE_COUNT],
}

impl Phase5Tracker {
    /// Fresh tracker with every milestone `NotStarted`.
    pub const NEW: Self = Self {
        states: [Phase5MilestoneState::NotStarted; PHASE5_MILESTONE_COUNT],
    };

    /// Record a milestone state, enforcing prerequisite ordering.
    pub fn set_state(
        &mut self,
        milestone: Phase5Milestone,
        state: Phase5MilestoneState,
    ) -> Result<(), Phase5Error> {
        if matches!(state, Phase5MilestoneState::InProgress | Phase5MilestoneState::Validated) {
            if let Some(prereq) = milestone.prerequisite() {
                if !self.state(prereq).is_validated() {
                    return Err(Phase5Error::PrerequisiteIncomplete {
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
    pub const fn state(&self, milestone: Phase5Milestone) -> Phase5MilestoneState {
        self.states[milestone as usize]
    }

    /// Return `true` when every milestone is `Validated`.
    pub const fn all_validated(&self) -> bool {
        let mut i = 0;
        while i < PHASE5_MILESTONE_COUNT {
            if !matches!(self.states[i], Phase5MilestoneState::Validated) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// First not-yet-validated milestone.
    pub fn first_unvalidated(&self) -> Option<Phase5Milestone> {
        for m in PHASE5_MILESTONES {
            if !self.state(*m).is_validated() {
                return Some(*m);
            }
        }
        None
    }

    /// Return `true` when any milestone is in the `Regressed` state.
    pub const fn any_regressed(&self) -> bool {
        let mut i = 0;
        while i < PHASE5_MILESTONE_COUNT {
            if matches!(self.states[i], Phase5MilestoneState::Regressed) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5TimelineEstimate
// ─────────────────────────────────────────────────────────────────────────────

/// Three-point timeline estimate for Phase Five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase5TimelineEstimate {
    /// Optimistic months (README estimate).
    pub optimistic_months: u32,
    /// Realistic months = optimistic × REALISTIC_MULTIPLIER.
    pub realistic_months: u32,
    /// Pessimistic months = optimistic × PESSIMISTIC_MULTIPLIER.
    pub pessimistic_months: u32,
}

impl Phase5TimelineEstimate {
    /// README lower bound: 6 months for a dedicated team.
    pub const README_LOWER: Self = Self {
        optimistic_months:  6,
        realistic_months:   6 * REALISTIC_MULTIPLIER,
        pessimistic_months: 6 * PESSIMISTIC_MULTIPLIER,
    };

    /// README upper bound: 12 months for a dedicated team.
    pub const README_UPPER: Self = Self {
        optimistic_months:  12,
        realistic_months:   12 * REALISTIC_MULTIPLIER,
        pessimistic_months: 12 * PESSIMISTIC_MULTIPLIER,
    };

    /// Validate non-zero and monotonic.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if self.optimistic_months == 0 {
            return Err(Phase5Error::TimelineEstimateZero);
        }
        if self.realistic_months < self.optimistic_months
            || self.pessimistic_months < self.realistic_months
        {
            return Err(Phase5Error::TimelineEstimateMonotonicityViolated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SustainabilityPlan — how the project continues after release
// ─────────────────────────────────────────────────────────────────────────────

/// The project's plan for continued maintenance after the v1.0 release.
///
/// Per the SKILL.md guidance: "the project's long-term sustainability depends
/// on community adoption generating either commercial revenue (enterprise
/// licensing, OEM deals) or contributor volume sufficient to maintain the
/// codebase".  At least one of those two channels must exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SustainabilityPlan {
    /// Commercial revenue plan exists (enterprise licensing, OEM deals,
    /// support contracts).
    pub commercial_revenue_plan: bool,
    /// Community contributor base is large enough to sustain bug fixes and
    /// reviews (rough threshold: at least three active outside reviewers).
    pub contributor_base_sufficient: bool,
}

impl SustainabilityPlan {
    /// A plan where both channels exist (ideal for long-term survival).
    pub const BOTH_CHANNELS: Self = Self {
        commercial_revenue_plan:     true,
        contributor_base_sufficient: true,
    };

    /// A plan where only the commercial channel exists.
    pub const COMMERCIAL_ONLY: Self = Self {
        commercial_revenue_plan:     true,
        contributor_base_sufficient: false,
    };

    /// A plan where only the contributor channel exists.
    pub const CONTRIBUTORS_ONLY: Self = Self {
        commercial_revenue_plan:     false,
        contributor_base_sufficient: true,
    };

    /// Return `true` when at least one sustainability channel is in place.
    pub const fn is_viable(self) -> bool {
        self.commercial_revenue_plan || self.contributor_base_sufficient
    }

    /// Validate the sustainability plan.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.is_viable() {
            return Err(Phase5Error::NoSustainabilityChannel);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5GateCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// The Phase Five acceptance test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase5GateCriterion {
    /// Installer capability set is complete.
    pub installer_complete: bool,
    /// Documentation deliverables are complete.
    pub documentation_complete: bool,
    /// Support infrastructure is complete.
    pub support_complete: bool,
    /// Cross-partition input switch is configured for production.
    pub input_switch_production: bool,
    /// License assignment is valid (no proprietary components).
    pub license_assignment_valid: bool,
    /// Sustainability plan is viable.
    pub sustainability_viable: bool,
    /// No workaround compromise accepted at release.
    pub workaround_accepted: bool,
}

impl Phase5GateCriterion {
    /// The state required to pass Phase Five.
    pub const PASSING: Self = Self {
        installer_complete:        true,
        documentation_complete:    true,
        support_complete:          true,
        input_switch_production:   true,
        license_assignment_valid:  true,
        sustainability_viable:     true,
        workaround_accepted:       false,
    };

    /// Return `true` only when every check is met.
    pub const fn passes(self) -> bool {
        self.installer_complete
            && self.documentation_complete
            && self.support_complete
            && self.input_switch_production
            && self.license_assignment_valid
            && self.sustainability_viable
            && !self.workaround_accepted
    }

    /// Validate the gate criterion.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if self.workaround_accepted {
            return Err(Phase5Error::GateWorkaroundAccepted);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5Config — aggregate configuration + validation
// ─────────────────────────────────────────────────────────────────────────────

/// The aggregate configuration for Phase Five.
#[derive(Debug)]
pub struct Phase5Config {
    /// Phase Four readiness — entry gate.
    pub phase4: Phase4Summary,
    /// Three-point timeline estimate.
    pub timeline: Phase5TimelineEstimate,
    /// License assignment.
    pub licenses: LicenseAssignment,
    /// Installer capabilities.
    pub installer: InstallerCapabilities,
    /// Documentation deliverables.
    pub docs: DocumentationDeliverables,
    /// Support infrastructure.
    pub support: SupportInfrastructure,
    /// Cross-partition input switch configuration.
    pub input_switch: CrossPartitionInputSwitch,
    /// Sustainability plan.
    pub sustainability: SustainabilityPlan,
    /// Per-milestone progress state.
    pub tracker: Phase5Tracker,
    /// Phase Five gate criterion.
    pub gate: Phase5GateCriterion,
}

impl Phase5Config {
    /// Validate the complete Phase Five configuration.
    pub fn validate(&self) -> Result<(), Phase5Error> {
        if !self.phase4.phase4_complete() {
            return Err(Phase5Error::Phase4NotComplete);
        }
        self.timeline.validate()?;
        self.licenses.validate()?;
        self.installer.validate()?;
        self.docs.validate()?;
        self.support.validate()?;
        self.input_switch.validate()?;
        self.sustainability.validate()?;
        if self.tracker.any_regressed() {
            return Err(Phase5Error::MilestoneRegressed);
        }
        // Phase 4 gate state must mirror Phase 4 summary
        if self.phase4.phase4_complete()
            && !self.tracker.state(Phase5Milestone::Phase4GateClosed).is_validated()
        {
            return Err(Phase5Error::Phase4GateNotRecorded);
        }
        self.gate.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5Summary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Phase Five readiness gate.
#[derive(Debug)]
pub struct Phase5Summary {
    /// True when Phase Four is complete.
    pub phase4_complete: bool,
    /// True when the installer is complete and licenses are assigned.
    pub release_artifacts_ready: bool,
    /// True when documentation, support, and sustainability plan are in place.
    pub project_infrastructure_ready: bool,
    /// True when every Phase Five milestone is `Validated`.
    pub all_milestones_validated: bool,
    /// True when the gate criterion passes.
    pub gate_passes: bool,
}

impl Phase5Summary {
    /// Return `true` when Phase Five is complete and AETHER v1.0 is shipped.
    pub fn phase5_complete(&self) -> bool {
        self.phase4_complete
            && self.release_artifacts_ready
            && self.project_infrastructure_ready
            && self.all_milestones_validated
            && self.gate_passes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase5Error
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by Phase Five configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase5Error {
    /// Phase Four has not been completed.
    Phase4NotComplete,
    /// Phase Four is complete but the tracker does not reflect this.
    Phase4GateNotRecorded,
    /// A milestone was advanced before its prerequisite was `Validated`.
    PrerequisiteIncomplete {
        /// The milestone being advanced.
        milestone:    Phase5Milestone,
        /// The prerequisite that is not yet `Validated`.
        prerequisite: Phase5Milestone,
    },
    /// A timeline estimate is zero months.
    TimelineEstimateZero,
    /// Timeline estimates are not monotonically non-decreasing.
    TimelineEstimateMonotonicityViolated,
    /// A component is licensed as proprietary.
    ProprietaryLicense {
        /// The component with a proprietary license.
        component: &'static str,
    },
    /// AOSP overlays are not licensed under Apache 2.0.
    AospOverlayLicenseNotApache2 {
        /// The license that was set instead of Apache 2.0.
        actual: LicenseChoice,
    },
    /// The installer is missing a required capability.
    InstallerMissingCapability {
        /// The missing capability name.
        capability: &'static str,
    },
    /// A required documentation deliverable is missing.
    DocumentationMissing {
        /// The missing document name.
        document: &'static str,
    },
    /// A required support-infrastructure component is missing.
    SupportMissing {
        /// The missing component name.
        component: &'static str,
    },
    /// The input switch's hardware trigger is not active.
    InputSwitchHardwareTriggerInactive,
    /// The input switch allows a software trigger — security violation.
    InputSwitchSoftwareTriggerAllowed,
    /// The xHCI reset step is missing from the input-switch flow.
    InputSwitchXhciResetMissing,
    /// The SMMU is not required for the input switch — DMA isolation hole.
    InputSwitchSmmuNotRequired,
    /// No sustainability channel exists (neither commercial revenue nor a
    /// sufficient contributor base).
    NoSustainabilityChannel,
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

    fn complete_phase4_summary() -> Phase4Summary {
        Phase4Summary {
            phase3_complete:          true,
            perf_targets_met:         true,
            sensor_fidelity_ok:       true,
            app_compat_ok:            true,
            all_milestones_validated: true,
            gate_passes:              true,
        }
    }

    // ── LicenseChoice ─────────────────────────────────────────────────────────

    #[test]
    fn open_source_licenses_acceptable() {
        assert!(LicenseChoice::GplV2.is_acceptable());
        assert!(LicenseChoice::Mit.is_acceptable());
        assert!(LicenseChoice::Apache2.is_acceptable());
        assert!(LicenseChoice::CcBySa.is_acceptable());
    }

    #[test]
    fn proprietary_not_acceptable() {
        assert!(!LicenseChoice::Proprietary.is_acceptable());
    }

    #[test]
    fn permissive_split() {
        assert!(LicenseChoice::Mit.is_permissive());
        assert!(LicenseChoice::Apache2.is_permissive());
        assert!(!LicenseChoice::GplV2.is_permissive());
        assert!(!LicenseChoice::CcBySa.is_permissive());
        assert!(!LicenseChoice::Proprietary.is_permissive());
    }

    // ── LicenseAssignment ─────────────────────────────────────────────────────

    #[test]
    fn recommended_assignment_validates() {
        assert!(LicenseAssignment::RECOMMENDED.validate().is_ok());
    }

    #[test]
    fn proprietary_hypervisor_rejected() {
        let a = LicenseAssignment {
            hypervisor_core: LicenseChoice::Proprietary,
            ..LicenseAssignment::RECOMMENDED
        };
        assert_eq!(
            a.validate(),
            Err(Phase5Error::ProprietaryLicense { component: "hypervisor core" })
        );
    }

    #[test]
    fn proprietary_installer_rejected() {
        let a = LicenseAssignment {
            installer_and_tools: LicenseChoice::Proprietary,
            ..LicenseAssignment::RECOMMENDED
        };
        assert_eq!(
            a.validate(),
            Err(Phase5Error::ProprietaryLicense { component: "installer and tools" })
        );
    }

    #[test]
    fn aosp_overlay_must_be_apache2() {
        let a = LicenseAssignment {
            aosp_overlays: LicenseChoice::Mit,
            ..LicenseAssignment::RECOMMENDED
        };
        assert_eq!(
            a.validate(),
            Err(Phase5Error::AospOverlayLicenseNotApache2 { actual: LicenseChoice::Mit })
        );
    }

    // ── InstallerCapabilities ─────────────────────────────────────────────────

    #[test]
    fn required_installer_complete() {
        assert!(InstallerCapabilities::REQUIRED.complete());
        assert!(InstallerCapabilities::REQUIRED.validate().is_ok());
    }

    #[test]
    fn missing_secure_boot_rejected() {
        let i = InstallerCapabilities {
            enroll_secure_boot_keys: false,
            ..InstallerCapabilities::REQUIRED
        };
        assert!(!i.complete());
        assert_eq!(
            i.validate(),
            Err(Phase5Error::InstallerMissingCapability { capability: "enroll_secure_boot_keys" })
        );
    }

    #[test]
    fn missing_tier_detection_rejected() {
        let i = InstallerCapabilities {
            auto_detect_tier: false,
            ..InstallerCapabilities::REQUIRED
        };
        assert!(matches!(
            i.validate(),
            Err(Phase5Error::InstallerMissingCapability { capability: "auto_detect_tier" })
        ));
    }

    #[test]
    fn missing_recovery_rejected() {
        let i = InstallerCapabilities {
            recovery_image: false,
            ..InstallerCapabilities::REQUIRED
        };
        assert!(matches!(
            i.validate(),
            Err(Phase5Error::InstallerMissingCapability { capability: "recovery_image" })
        ));
    }

    // ── DocumentationDeliverables ─────────────────────────────────────────────

    #[test]
    fn required_docs_complete() {
        assert!(DocumentationDeliverables::REQUIRED.complete());
        assert!(DocumentationDeliverables::REQUIRED.validate().is_ok());
    }

    #[test]
    fn missing_user_manual_rejected() {
        let d = DocumentationDeliverables {
            user_manual: false,
            ..DocumentationDeliverables::REQUIRED
        };
        assert!(matches!(
            d.validate(),
            Err(Phase5Error::DocumentationMissing { document: "user_manual" })
        ));
    }

    #[test]
    fn missing_contributor_guide_rejected() {
        let d = DocumentationDeliverables {
            contributor_guide: false,
            ..DocumentationDeliverables::REQUIRED
        };
        assert!(matches!(
            d.validate(),
            Err(Phase5Error::DocumentationMissing { document: "contributor_guide" })
        ));
    }

    #[test]
    fn missing_phase6_roadmap_rejected() {
        let d = DocumentationDeliverables {
            phase6_roadmap: false,
            ..DocumentationDeliverables::REQUIRED
        };
        assert!(matches!(
            d.validate(),
            Err(Phase5Error::DocumentationMissing { document: "phase6_roadmap" })
        ));
    }

    #[test]
    fn missing_security_disclosure_rejected() {
        let d = DocumentationDeliverables {
            security_disclosure: false,
            ..DocumentationDeliverables::REQUIRED
        };
        assert!(matches!(
            d.validate(),
            Err(Phase5Error::DocumentationMissing { document: "security_disclosure" })
        ));
    }

    // ── SupportInfrastructure ─────────────────────────────────────────────────

    #[test]
    fn required_support_complete() {
        assert!(SupportInfrastructure::REQUIRED.complete());
        assert!(SupportInfrastructure::REQUIRED.validate().is_ok());
    }

    #[test]
    fn missing_security_mailbox_rejected() {
        let s = SupportInfrastructure {
            security_mailbox: false,
            ..SupportInfrastructure::REQUIRED
        };
        assert!(matches!(
            s.validate(),
            Err(Phase5Error::SupportMissing { component: "security_mailbox" })
        ));
    }

    #[test]
    fn missing_ci_dashboard_rejected() {
        let s = SupportInfrastructure {
            public_ci_dashboard: false,
            ..SupportInfrastructure::REQUIRED
        };
        assert!(matches!(
            s.validate(),
            Err(Phase5Error::SupportMissing { component: "public_ci_dashboard" })
        ));
    }

    // ── CrossPartitionInputSwitch ─────────────────────────────────────────────

    #[test]
    fn production_input_switch_validates() {
        assert!(CrossPartitionInputSwitch::PRODUCTION.validate().is_ok());
    }

    #[test]
    fn software_trigger_allowed_rejected() {
        let s = CrossPartitionInputSwitch {
            software_trigger_rejected: false,
            ..CrossPartitionInputSwitch::PRODUCTION
        };
        assert_eq!(
            s.validate(),
            Err(Phase5Error::InputSwitchSoftwareTriggerAllowed)
        );
    }

    #[test]
    fn missing_xhci_reset_rejected() {
        let s = CrossPartitionInputSwitch {
            xhci_reset_on_reassignment: false,
            ..CrossPartitionInputSwitch::PRODUCTION
        };
        assert_eq!(
            s.validate(),
            Err(Phase5Error::InputSwitchXhciResetMissing)
        );
    }

    #[test]
    fn smmu_not_required_rejected() {
        let s = CrossPartitionInputSwitch {
            smmu_required_for_switch: false,
            ..CrossPartitionInputSwitch::PRODUCTION
        };
        assert_eq!(
            s.validate(),
            Err(Phase5Error::InputSwitchSmmuNotRequired)
        );
    }

    #[test]
    fn hardware_trigger_inactive_rejected() {
        let s = CrossPartitionInputSwitch {
            hardware_trigger_active: false,
            ..CrossPartitionInputSwitch::PRODUCTION
        };
        assert_eq!(
            s.validate(),
            Err(Phase5Error::InputSwitchHardwareTriggerInactive)
        );
    }

    // ── Phase5Milestone ───────────────────────────────────────────────────────

    #[test]
    fn first_milestone_has_no_prerequisite() {
        assert_eq!(Phase5Milestone::Phase4GateClosed.prerequisite(), None);
    }

    #[test]
    fn milestone_chain_is_linear() {
        let mut visited = 0;
        let mut cur = Some(*PHASE5_MILESTONES.last().unwrap());
        while let Some(m) = cur {
            visited += 1;
            cur = m.prerequisite();
        }
        assert_eq!(visited, PHASE5_MILESTONE_COUNT);
    }

    #[test]
    fn public_release_requires_hardware() {
        assert_eq!(
            Phase5Milestone::PublicReleaseShipped.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn installer_requires_hardware() {
        assert_eq!(
            Phase5Milestone::InstallerFeatureComplete.validation_tier(),
            TestTier::RealHardware
        );
    }

    #[test]
    fn milestone_count_matches() {
        assert_eq!(PHASE5_MILESTONES.len(), PHASE5_MILESTONE_COUNT);
    }

    #[test]
    fn milestone_labels_are_nonempty() {
        for m in PHASE5_MILESTONES {
            assert!(!m.label().is_empty());
        }
    }

    // ── Phase5Tracker ─────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_all_not_started() {
        let t = Phase5Tracker::NEW;
        for m in PHASE5_MILESTONES {
            assert_eq!(t.state(*m), Phase5MilestoneState::NotStarted);
        }
    }

    #[test]
    fn cannot_advance_without_prerequisite() {
        let mut t = Phase5Tracker::NEW;
        let r = t.set_state(Phase5Milestone::LicenseAssigned, Phase5MilestoneState::Validated);
        assert_eq!(
            r,
            Err(Phase5Error::PrerequisiteIncomplete {
                milestone:    Phase5Milestone::LicenseAssigned,
                prerequisite: Phase5Milestone::Phase4GateClosed,
            })
        );
    }

    #[test]
    fn linear_progression_works() {
        let mut t = Phase5Tracker::NEW;
        for m in PHASE5_MILESTONES {
            t.set_state(*m, Phase5MilestoneState::Validated).expect("linear must succeed");
        }
        assert!(t.all_validated());
    }

    #[test]
    fn regression_detected() {
        let mut t = Phase5Tracker::NEW;
        t.set_state(Phase5Milestone::Phase4GateClosed, Phase5MilestoneState::Validated).unwrap();
        t.set_state(Phase5Milestone::Phase4GateClosed, Phase5MilestoneState::Regressed).unwrap();
        assert!(t.any_regressed());
    }

    // ── Phase5TimelineEstimate ────────────────────────────────────────────────

    #[test]
    fn readme_lower_validates() {
        assert!(Phase5TimelineEstimate::README_LOWER.validate().is_ok());
    }

    #[test]
    fn readme_upper_validates() {
        assert!(Phase5TimelineEstimate::README_UPPER.validate().is_ok());
    }

    #[test]
    fn readme_lower_realistic_12_months() {
        assert_eq!(Phase5TimelineEstimate::README_LOWER.realistic_months, 12);
    }

    #[test]
    fn readme_upper_pessimistic_36_months() {
        assert_eq!(Phase5TimelineEstimate::README_UPPER.pessimistic_months, 36);
    }

    #[test]
    fn zero_optimistic_rejected_p5() {
        let e = Phase5TimelineEstimate { optimistic_months: 0, realistic_months: 0, pessimistic_months: 0 };
        assert_eq!(e.validate(), Err(Phase5Error::TimelineEstimateZero));
    }

    #[test]
    fn nonmonotonic_rejected_p5() {
        let e = Phase5TimelineEstimate {
            optimistic_months:  12,
            realistic_months:   6,
            pessimistic_months: 36,
        };
        assert_eq!(e.validate(), Err(Phase5Error::TimelineEstimateMonotonicityViolated));
    }

    // ── SustainabilityPlan ────────────────────────────────────────────────────

    #[test]
    fn both_channels_viable() {
        assert!(SustainabilityPlan::BOTH_CHANNELS.is_viable());
        assert!(SustainabilityPlan::BOTH_CHANNELS.validate().is_ok());
    }

    #[test]
    fn commercial_only_viable() {
        assert!(SustainabilityPlan::COMMERCIAL_ONLY.is_viable());
    }

    #[test]
    fn contributors_only_viable() {
        assert!(SustainabilityPlan::CONTRIBUTORS_ONLY.is_viable());
    }

    #[test]
    fn neither_channel_rejected() {
        let p = SustainabilityPlan {
            commercial_revenue_plan:     false,
            contributor_base_sufficient: false,
        };
        assert!(!p.is_viable());
        assert_eq!(p.validate(), Err(Phase5Error::NoSustainabilityChannel));
    }

    // ── Phase5GateCriterion ───────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(Phase5GateCriterion::PASSING.passes());
        assert!(Phase5GateCriterion::PASSING.validate().is_ok());
    }

    #[test]
    fn workaround_fails() {
        let g = Phase5GateCriterion {
            workaround_accepted: true,
            ..Phase5GateCriterion::PASSING
        };
        assert!(!g.passes());
        assert_eq!(g.validate(), Err(Phase5Error::GateWorkaroundAccepted));
    }

    #[test]
    fn missing_installer_fails() {
        let g = Phase5GateCriterion {
            installer_complete: false,
            ..Phase5GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    #[test]
    fn missing_sustainability_fails() {
        let g = Phase5GateCriterion {
            sustainability_viable: false,
            ..Phase5GateCriterion::PASSING
        };
        assert!(!g.passes());
    }

    // ── Phase5Config ──────────────────────────────────────────────────────────

    fn fully_validated_phase5_tracker() -> Phase5Tracker {
        let mut t = Phase5Tracker::NEW;
        for m in PHASE5_MILESTONES {
            t.set_state(*m, Phase5MilestoneState::Validated).unwrap();
        }
        t
    }

    fn passing_phase5_config() -> Phase5Config {
        Phase5Config {
            phase4:         complete_phase4_summary(),
            timeline:       Phase5TimelineEstimate::README_LOWER,
            licenses:       LicenseAssignment::RECOMMENDED,
            installer:      InstallerCapabilities::REQUIRED,
            docs:           DocumentationDeliverables::REQUIRED,
            support:        SupportInfrastructure::REQUIRED,
            input_switch:   CrossPartitionInputSwitch::PRODUCTION,
            sustainability: SustainabilityPlan::BOTH_CHANNELS,
            tracker:        fully_validated_phase5_tracker(),
            gate:           Phase5GateCriterion::PASSING,
        }
    }

    #[test]
    fn passing_phase5_config_validates() {
        assert!(passing_phase5_config().validate().is_ok());
    }

    #[test]
    fn config_rejects_incomplete_phase4() {
        let mut p4 = complete_phase4_summary();
        p4.gate_passes = false;
        let cfg = Phase5Config {
            phase4: p4,
            ..passing_phase5_config()
        };
        assert_eq!(cfg.validate(), Err(Phase5Error::Phase4NotComplete));
    }

    #[test]
    fn config_rejects_proprietary_license() {
        let cfg = Phase5Config {
            licenses: LicenseAssignment {
                hypervisor_core: LicenseChoice::Proprietary,
                ..LicenseAssignment::RECOMMENDED
            },
            ..passing_phase5_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(Phase5Error::ProprietaryLicense { component: "hypervisor core" })
        ));
    }

    #[test]
    fn config_rejects_software_trigger_switch() {
        let cfg = Phase5Config {
            input_switch: CrossPartitionInputSwitch {
                software_trigger_rejected: false,
                ..CrossPartitionInputSwitch::PRODUCTION
            },
            ..passing_phase5_config()
        };
        assert_eq!(
            cfg.validate(),
            Err(Phase5Error::InputSwitchSoftwareTriggerAllowed)
        );
    }

    #[test]
    fn config_rejects_unsustainable_plan() {
        let cfg = Phase5Config {
            sustainability: SustainabilityPlan {
                commercial_revenue_plan:     false,
                contributor_base_sufficient: false,
            },
            ..passing_phase5_config()
        };
        assert_eq!(cfg.validate(), Err(Phase5Error::NoSustainabilityChannel));
    }

    #[test]
    fn config_rejects_regression() {
        let mut tracker = fully_validated_phase5_tracker();
        tracker.set_state(Phase5Milestone::InstallerFeatureComplete, Phase5MilestoneState::Regressed).unwrap();
        let cfg = Phase5Config {
            tracker,
            ..passing_phase5_config()
        };
        assert_eq!(cfg.validate(), Err(Phase5Error::MilestoneRegressed));
    }

    #[test]
    fn config_rejects_unrecorded_phase4_gate() {
        let mut tracker = fully_validated_phase5_tracker();
        tracker.states[Phase5Milestone::Phase4GateClosed as usize] = Phase5MilestoneState::InProgress;
        let cfg = Phase5Config {
            tracker,
            ..passing_phase5_config()
        };
        assert_eq!(cfg.validate(), Err(Phase5Error::Phase4GateNotRecorded));
    }

    // ── Phase5Summary ─────────────────────────────────────────────────────────

    #[test]
    fn phase5_summary_complete() {
        let s = Phase5Summary {
            phase4_complete:              true,
            release_artifacts_ready:      true,
            project_infrastructure_ready: true,
            all_milestones_validated:     true,
            gate_passes:                  true,
        };
        assert!(s.phase5_complete());
    }

    #[test]
    fn phase5_summary_partial_not_complete() {
        let mut base = Phase5Summary {
            phase4_complete:              true,
            release_artifacts_ready:      true,
            project_infrastructure_ready: true,
            all_milestones_validated:     true,
            gate_passes:                  true,
        };
        base.phase4_complete = false;              assert!(!base.phase5_complete());
        base.phase4_complete = true;
        base.release_artifacts_ready = false;      assert!(!base.phase5_complete());
        base.release_artifacts_ready = true;
        base.project_infrastructure_ready = false; assert!(!base.phase5_complete());
        base.project_infrastructure_ready = true;
        base.all_milestones_validated = false;     assert!(!base.phase5_complete());
        base.all_milestones_validated = true;
        base.gate_passes = false;                  assert!(!base.phase5_complete());
    }
}
