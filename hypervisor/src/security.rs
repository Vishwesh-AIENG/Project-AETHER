// ch25: Security
//
// AETHER's security model rests on hardware enforcement of partitioning.
//
//   SMMU        — enforces device DMA isolation.  A compromised Android device
//                 driver cannot program DMA to reach Windows memory.
//   Stage 2     — enforces CPU memory isolation.  Android kernel code executing
//                 at EL1 cannot read or write hypervisor or Windows memory.
//   GIC         — enforces interrupt isolation.  Interrupts assigned to Android
//                 cores are never delivered to Windows cores, and vice versa.
//
// None of these are software policies that can be bypassed by a buggy or
// malicious guest.  They are hardware mechanisms that the processor enforces
// unconditionally, below every software layer.
//
// ── Trusted Computing Base ───────────────────────────────────────────────────
//
// AETHER's TCB — the code that must not be compromised for the security
// guarantees to hold — consists of three layers:
//   1. The hardware (CPU, SMMU, GIC silicon).
//   2. The EL3 firmware (ARM Trusted Firmware; AETHER does not replace it).
//   3. AETHER itself running at EL2.
//
// Everything else — both guest operating systems and all their apps — is
// outside the TCB.  A compromised Android guest cannot affect the hypervisor
// or the Windows guest.
//
// ── Attack Surface ───────────────────────────────────────────────────────────
//
// AETHER's attack surface is the set of interfaces through which a guest can
// deliver attacker-controlled data to EL2 code:
//   1. HVC calls — hypercall arguments x0–x7 are guest-controlled.
//   2. Trapped system-register accesses — the value written via MSR.
//   3. SMMU faults — the faulting DMA address is guest-controlled indirectly.
//   4. Timer interrupts — trigger path only, no guest-controlled data.
//
// Every handler on these paths must validate all inputs before acting on them.
// A guest must not be able to supply a hypervisor-range address as an HVC
// argument and cause AETHER to dereference it.
//
// ── Spectre v2 Mitigations ───────────────────────────────────────────────────
//
// Spectre variant 2 (branch-target injection) allows a guest to influence the
// hypervisor's speculative execution through the indirect branch predictor.
// AETHER must flush the branch predictor on every EL1→EL2 entry and every
// EL2→EL1 exit.  The correct instruction depends on the CPU revision:
//   Armv8.5+ with FEAT_CLRBHB: `CLRBHB` (one-instruction BHB flush)
//   Armv8.0–8.4:               software BHB flush loop (CSV2 alternative)
//
// Reference: Linux arch/arm64/kernel/entry.S spectre_bhb_patch_loop /
//            spectre_bhb_patch_clearbhb.
//
// ── Unsafe Block Policy ──────────────────────────────────────────────────────
//
// Every `unsafe` block in AETHER must carry a comment of the form:
//   // SAFETY: <invariant that makes this block safe>
// Unsafe blocks that lack this comment are treated as audit failures and
// block the security sign-off.
//
// Primary references:
//   ARM ARM DDI0487 §D1.9 — Security Extensions
//   ARM ARM DDI0487 §D5.9 — Memory access control
//   Linux arch/arm64/kernel/entry.S — Spectre v2 entry/exit mitigations
//   ARM Security Advisory — Spectre-BHB (CVE-2022-23960)

// ─────────────────────────────────────────────────────────────────────────────
// TrustedComputingBase — components inside and outside AETHER's TCB
// ─────────────────────────────────────────────────────────────────────────────

/// A component layer in the system-wide trust hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbLayer {
    /// Silicon: CPU, SMMU, GIC.  AETHER trusts hardware to enforce its rules.
    Hardware,
    /// EL3 firmware (ARM Trusted Firmware).  AETHER does not replace it.
    El3Firmware,
    /// AETHER itself running at EL2.  The core of the software TCB.
    Hypervisor,
    /// Guest operating systems (Android, Windows) — outside the TCB.
    Guest,
    /// Guest applications — outside the TCB, below the guest OS.
    Application,
}

impl TcbLayer {
    /// Return `true` when this layer is inside the TCB (must not be
    /// compromised for isolation guarantees to hold).
    #[inline]
    pub const fn is_trusted(self) -> bool {
        matches!(self, TcbLayer::Hardware | TcbLayer::El3Firmware | TcbLayer::Hypervisor)
    }

    /// Return a short description of the layer's trust role.
    pub const fn description(self) -> &'static str {
        match self {
            TcbLayer::Hardware    => "Silicon enforcement — CPU/SMMU/GIC enforce isolation unconditionally",
            TcbLayer::El3Firmware => "EL3 firmware — sets up secure-world state before AETHER takes over",
            TcbLayer::Hypervisor  => "AETHER at EL2 — referee; partitions resources, enforces access rules",
            TcbLayer::Guest       => "Guest OS — untrusted; a compromised guest must not break isolation",
            TcbLayer::Application => "Guest app — untrusted; fully sandboxed by its guest OS and Stage 2",
        }
    }
}

/// The minimal set of layers that form AETHER's Trusted Computing Base.
///
/// The TCB is deliberately small.  Every line of hypervisor code is a
/// potential vulnerability; code that can run safely in a guest should run
/// there, not in the hypervisor.
pub const TCB_LAYERS: &[TcbLayer] = &[
    TcbLayer::Hardware,
    TcbLayer::El3Firmware,
    TcbLayer::Hypervisor,
];

// ─────────────────────────────────────────────────────────────────────────────
// SmmuSecurityState — SMMU as mandatory DMA isolation boundary
// ─────────────────────────────────────────────────────────────────────────────

/// The SMMU's current contribution to the isolation model.
///
/// The SMMU is a mandatory security component, not an optional performance
/// feature.  Without it a compromised Android device driver could program DMA
/// to read or write Windows memory — a complete isolation bypass that requires
/// no CPU-level privilege escalation.
///
/// AETHER must configure the SMMU before enabling any guest's device drivers
/// and must verify the configuration is active before considering the system
/// secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmmuSecurityState {
    /// SMMU is fully configured: every device DMA stream has a Stream Table
    /// Entry in translated mode.  DMA outside the owning guest's IPA range
    /// causes an SMMU fault.
    Active,
    /// SMMU configuration is in progress.  Guest device drivers must not be
    /// enabled yet; DMA isolation is not yet enforced.
    Pending,
    /// SMMU is absent or non-functional.  The system cannot proceed to
    /// production operation — this is a hard failure.
    Absent,
}

impl SmmuSecurityState {
    /// Return `true` when DMA isolation is enforced.
    #[inline]
    pub const fn is_enforcing(self) -> bool {
        matches!(self, SmmuSecurityState::Active)
    }
}

/// Policy applied when the SMMU raises a DMA isolation fault.
///
/// A fault means a guest device attempted to access memory outside its allowed
/// range — a security event, not a benign programming error.  The correct
/// response is to terminate the offending guest, not to log-and-retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmmuFaultPolicy {
    /// Terminate the guest that owns the faulting stream.  This is the only
    /// correct policy in a production system.
    TerminateGuest,
    /// Log the fault and continue.  FOR DEVELOPMENT ONLY — never use in
    /// production; silently retrying a DMA fault hides isolation violations.
    LogAndContinue,
}

impl SmmuFaultPolicy {
    /// Return `true` when the policy is production-safe.
    #[inline]
    pub const fn is_production_safe(self) -> bool {
        matches!(self, SmmuFaultPolicy::TerminateGuest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SpectreV2Mitigation — branch predictor flush on every EL1↔EL2 transition
// ─────────────────────────────────────────────────────────────────────────────

/// The Spectre variant 2 (branch-target injection) mitigation strategy in use.
///
/// Spectre v2 allows a guest to influence the hypervisor's speculative
/// execution through the shared indirect branch predictor.  AETHER must flush
/// the branch predictor on every EL1→EL2 entry and every EL2→EL1 exit.
///
/// The correct mechanism depends on CPU microarchitecture:
///   - CPUs with FEAT_CLRBHB (Armv8.5+): one `CLRBHB` instruction suffices.
///   - CPUs with FEAT_CSV2 but no CLRBHB: a software loop that fills the BHB
///     with known-safe entries (iteration count is CPU-specific).
///   - CPUs without CSV2: `IC IALLU` + DSB + ISB (instruction cache flush
///     forces predictor retraining on the clean code path).
///
/// Reference: ARM Security Advisory Spectre-BHB (CVE-2022-23960);
///            Linux `arch/arm64/kernel/entry.S` spectre_bhb_patch_*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreV2Mitigation {
    /// `CLRBHB` instruction (Armv8.5+ FEAT_CLRBHB).  One instruction on every
    /// EL1→EL2 entry and EL2→EL1 exit.  The most efficient mitigation.
    ClrBhb,
    /// Software BHB flush loop.  The loop executes `iterations` indirect
    /// branches targeting known-safe addresses to overwrite attacker-chosen
    /// predictor history.  `iterations` is CPU-family-specific (e.g., 32 for
    /// Cortex-X1, 38 for Neoverse-N2).
    BhbLoopFlush {
        /// Number of loop iterations (CPU-family specific, from ARM advisories).
        iterations: u32,
    },
    /// Instruction-cache flush (`IC IALLU` + DSB NSH + ISB).  Used on CPUs
    /// that lack FEAT_CSV2.  Slower but universally applicable.
    IcacheFlush,
    /// No mitigation.  Only valid when the hardware provides architectural
    /// isolation (e.g., FEAT_CSV2 + FEAT_CSV3 with no shared predictor state
    /// across ELs).  Must be explicitly validated against the CPU errata list.
    HardwareIsolated,
}

impl SpectreV2Mitigation {
    /// Return `true` when a software mitigation is applied on every transition.
    ///
    /// `HardwareIsolated` returns `false` because the hardware enforces
    /// isolation without a software instruction sequence.
    pub const fn has_software_flush(self) -> bool {
        !matches!(self, SpectreV2Mitigation::HardwareIsolated)
    }
}

/// Configuration for branch-predictor flushing on EL1↔EL2 transitions.
///
/// This struct encodes what instruction sequence is emitted in the EL2 vector
/// table entry and in the EL2→EL1 return path before `ERET`.
#[derive(Debug, Clone, Copy)]
pub struct BranchPredictorFlushConfig {
    /// Which mitigation is in effect for this CPU.
    pub mitigation: SpectreV2Mitigation,
    /// True when the flush is inserted on EL1→EL2 entry (exception vector).
    pub flush_on_entry: bool,
    /// True when the flush is inserted on EL2→EL1 exit (before ERET).
    pub flush_on_exit: bool,
}

impl BranchPredictorFlushConfig {
    /// Returns `Ok(())` when the configuration is sound.
    ///
    /// For `SpectreV2Mitigation::BhbLoopFlush`, the iteration count must be
    /// non-zero.  A zero-iteration loop provides no protection.
    pub fn validate(&self) -> Result<(), SecurityError> {
        if let SpectreV2Mitigation::BhbLoopFlush { iterations } = self.mitigation {
            if iterations == 0 {
                return Err(SecurityError::SpectreFlushIterationsZero);
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HvcAttackSurface — attack surface entry points that reach EL2
// ─────────────────────────────────────────────────────────────────────────────

/// A path through which a guest can deliver attacker-controlled data to EL2.
///
/// These are the only interfaces AETHER exposes to its guests.  Each handler
/// on these paths must validate all inputs before using them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackSurfaceEntry {
    /// HVC hypercall.  Registers x0–x7 are guest-controlled.  A guest may
    /// supply any bit pattern including addresses in the hypervisor's own
    /// memory range.  AETHER must reject out-of-range addresses before
    /// dereferencing them.
    HvcCall,
    /// Trapped system-register write (MSR to a trapped register).  The value
    /// being written is guest-controlled and may encode a malicious address or
    /// configuration.
    TrappedSysregWrite,
    /// SMMU fault notification.  The faulting DMA address is indirectly
    /// controlled by the guest that owns the faulting stream.
    SmmuFault,
    /// Timer interrupt.  The trigger path reaches EL2 but carries no
    /// guest-controlled data — this is the lowest-risk entry point.
    TimerInterrupt,
}

impl AttackSurfaceEntry {
    /// Return `true` when this entry point carries guest-controlled data that
    /// must be validated before use.
    #[inline]
    pub const fn carries_guest_data(self) -> bool {
        !matches!(self, AttackSurfaceEntry::TimerInterrupt)
    }

    /// Return the validation requirement description for this entry point.
    pub const fn validation_requirement(self) -> &'static str {
        match self {
            AttackSurfaceEntry::HvcCall =>
                "Validate that all address arguments fall within the calling guest's IPA range. \
                 Reject any argument that references hypervisor or peer-guest memory.",
            AttackSurfaceEntry::TrappedSysregWrite =>
                "Validate that the written value is a legal encoding for the register. \
                 Reject reserved-field values that could enable hidden hardware features.",
            AttackSurfaceEntry::SmmuFault =>
                "Log the faulting stream ID and terminate the owning guest. \
                 Never retry the faulting DMA transaction.",
            AttackSurfaceEntry::TimerInterrupt =>
                "No guest-controlled data; service the timer and return. \
                 No additional validation required.",
        }
    }
}

/// The full enumeration of AETHER's attack surface entry points.
pub const ATTACK_SURFACE: &[AttackSurfaceEntry] = &[
    AttackSurfaceEntry::HvcCall,
    AttackSurfaceEntry::TrappedSysregWrite,
    AttackSurfaceEntry::SmmuFault,
    AttackSurfaceEntry::TimerInterrupt,
];

// ─────────────────────────────────────────────────────────────────────────────
// HvcInputValidator — per-call input validation for HVC arguments
// ─────────────────────────────────────────────────────────────────────────────

/// IPA address range assigned to a single guest.
///
/// Used by `HvcInputValidator` to reject HVC arguments that reference
/// hypervisor or peer-guest memory.
#[derive(Debug, Clone, Copy)]
pub struct GuestIpaRange {
    /// Inclusive start of the guest's IPA region (must be page-aligned).
    pub base: u64,
    /// Exclusive end of the guest's IPA region (must be page-aligned).
    pub end: u64,
}

impl GuestIpaRange {
    /// Return `true` when `ipa` falls within this guest's assigned range.
    #[inline]
    pub const fn contains(self, ipa: u64) -> bool {
        ipa >= self.base && ipa < self.end
    }

    /// Return `true` when the range `[ipa, ipa + size)` is fully within this
    /// guest's assigned region.
    ///
    /// Returns `false` on overflow.
    #[inline]
    pub const fn contains_range(self, ipa: u64, size: u64) -> bool {
        if let Some(end) = ipa.checked_add(size) {
            ipa >= self.base && end <= self.end
        } else {
            false
        }
    }
}

/// Validates HVC call arguments against a guest's assigned IPA range.
///
/// Any HVC handler that takes a guest-supplied address must call
/// `validate_ipa_argument` before dereferencing or mapping the address.
/// Supplying a hypervisor-range address as an HVC argument must be rejected
/// with `SecurityError::HvcAddressOutOfGuestRange`.
#[derive(Debug, Clone, Copy)]
pub struct HvcInputValidator {
    /// The IPA range assigned to the calling guest.
    pub guest_range: GuestIpaRange,
}

impl HvcInputValidator {
    /// Check that `ipa` is within the calling guest's IPA range.
    ///
    /// Returns `Ok(())` when the address is in-range.
    /// Returns `Err(SecurityError::HvcAddressOutOfGuestRange)` otherwise.
    pub fn validate_ipa_argument(&self, ipa: u64) -> Result<(), SecurityError> {
        if self.guest_range.contains(ipa) {
            Ok(())
        } else {
            Err(SecurityError::HvcAddressOutOfGuestRange { ipa })
        }
    }

    /// Check that the range `[ipa, ipa + size)` is within the calling guest's
    /// IPA range.
    pub fn validate_ipa_range(&self, ipa: u64, size: u64) -> Result<(), SecurityError> {
        if self.guest_range.contains_range(ipa, size) {
            Ok(())
        } else {
            Err(SecurityError::HvcRangeOutOfGuestRange { ipa, size })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnsafeAuditRecord — tracking unsafe blocks awaiting sign-off
// ─────────────────────────────────────────────────────────────────────────────

/// The sign-off state of an `unsafe` block in the AETHER codebase.
///
/// Every `unsafe` block must carry a `// SAFETY:` comment explaining the
/// invariant that makes it safe.  The audit record tracks whether that comment
/// has been reviewed and accepted.
///
/// Blocks without a SAFETY comment are in `Unannotated` state and block the
/// security sign-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeAuditStatus {
    /// `// SAFETY:` comment present and reviewed by a second engineer.
    Reviewed,
    /// `// SAFETY:` comment present but not yet reviewed.
    PendingReview,
    /// No `// SAFETY:` comment.  This is an audit failure.
    Unannotated,
}

impl UnsafeAuditStatus {
    /// Return `true` when this block is acceptable for a production build.
    #[inline]
    pub const fn is_acceptable(self) -> bool {
        matches!(self, UnsafeAuditStatus::Reviewed)
    }
}

/// An unsafe block record referencing its source location and justification.
#[derive(Debug, Clone, Copy)]
pub struct UnsafeAuditRecord {
    /// File path relative to the workspace root.
    pub file: &'static str,
    /// Line number of the `unsafe` keyword.
    pub line: u32,
    /// One-sentence description of the invariant from the SAFETY comment.
    pub safety_rationale: &'static str,
    /// Audit state.
    pub status: UnsafeAuditStatus,
}

impl UnsafeAuditRecord {
    /// Return `true` when this record passes the audit gate.
    #[inline]
    pub const fn passes(self) -> bool {
        self.status.is_acceptable()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityError — errors returned by security validation functions
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by security configuration and validation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    /// SMMU is absent or non-functional.  DMA isolation is not enforced.
    SmmuAbsent,
    /// The SMMU fault policy is not production-safe (log-and-continue set).
    SmmuFaultPolicyUnsafe,
    /// A BHB flush loop was configured with zero iterations.
    SpectreFlushIterationsZero,
    /// An HVC call supplied an IPA address outside the calling guest's range.
    HvcAddressOutOfGuestRange {
        /// The address that was rejected.
        ipa: u64,
    },
    /// An HVC call supplied a range that extends outside the guest's IPA space.
    HvcRangeOutOfGuestRange {
        /// Base address of the range.
        ipa: u64,
        /// Size of the range in bytes.
        size: u64,
    },
    /// At least one `unsafe` block has no SAFETY comment or is unreviewed.
    UnsafeBlockAuditFailure,
    /// An unsafe block's iteration count or size parameter overflows.
    ParameterOverflow,
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityConfiguration — aggregate security posture
// ─────────────────────────────────────────────────────────────────────────────

/// The complete security configuration for an AETHER deployment.
///
/// `validate()` checks that every security mechanism is active and correctly
/// configured before the system is considered production-ready.
#[derive(Debug)]
pub struct SecurityConfiguration {
    /// SMMU DMA isolation state.
    pub smmu_state: SmmuSecurityState,
    /// SMMU fault handling policy.
    pub fault_policy: SmmuFaultPolicy,
    /// Spectre v2 branch-predictor flush configuration.
    pub spectre_config: BranchPredictorFlushConfig,
}

impl SecurityConfiguration {
    /// Validate the complete security configuration.
    ///
    /// Returns `Ok(())` when all security mechanisms are active and correctly
    /// configured.  Returns the first detected error otherwise.
    ///
    /// Checks (in order):
    ///   1. SMMU is active (DMA isolation enforced).
    ///   2. SMMU fault policy terminates offending guest.
    ///   3. Spectre v2 flush configuration is valid (non-zero loop iterations).
    pub fn validate(&self) -> Result<(), SecurityError> {
        if !self.smmu_state.is_enforcing() {
            return Err(SecurityError::SmmuAbsent);
        }
        if !self.fault_policy.is_production_safe() {
            return Err(SecurityError::SmmuFaultPolicyUnsafe);
        }
        self.spectre_config.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecuritySummary — final security readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level security readiness summary.
///
/// `all_secure()` returns `true` only when every hardware isolation mechanism
/// is active and the Spectre mitigation is in place.  Use this as the final
/// gate before transitioning to guest execution.
#[derive(Debug)]
pub struct SecuritySummary {
    /// True when Stage 2 translation is active (CPU memory isolation).
    pub stage2_active: bool,
    /// True when the SMMU is enforcing DMA isolation.
    pub smmu_enforcing: bool,
    /// True when GIC interrupt routing is exclusively partitioned per guest.
    pub gic_partitioned: bool,
    /// True when Spectre v2 branch-predictor flushes are installed in the
    /// exception vector entry and EL2→EL1 return path.
    pub spectre_mitigated: bool,
}

impl SecuritySummary {
    /// Return `true` when all hardware isolation mechanisms are active.
    ///
    /// A `false` result means at least one isolation mechanism is missing and
    /// the system must not proceed to guest execution.
    pub fn all_secure(&self) -> bool {
        self.stage2_active
            && self.smmu_enforcing
            && self.gic_partitioned
            && self.spectre_mitigated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TcbLayer ─────────────────────────────────────────────────────────────

    #[test]
    fn tcb_layers_trusted() {
        assert!(TcbLayer::Hardware.is_trusted());
        assert!(TcbLayer::El3Firmware.is_trusted());
        assert!(TcbLayer::Hypervisor.is_trusted());
        assert!(!TcbLayer::Guest.is_trusted());
        assert!(!TcbLayer::Application.is_trusted());
    }

    #[test]
    fn tcb_const_contains_all_trusted_layers() {
        for &layer in TCB_LAYERS {
            assert!(layer.is_trusted(), "{:?} must be trusted", layer);
        }
    }

    #[test]
    fn tcb_descriptions_non_empty() {
        for &layer in &[
            TcbLayer::Hardware,
            TcbLayer::El3Firmware,
            TcbLayer::Hypervisor,
            TcbLayer::Guest,
            TcbLayer::Application,
        ] {
            assert!(!layer.description().is_empty());
        }
    }

    // ── SmmuSecurityState ─────────────────────────────────────────────────────

    #[test]
    fn smmu_active_is_enforcing() {
        assert!(SmmuSecurityState::Active.is_enforcing());
        assert!(!SmmuSecurityState::Pending.is_enforcing());
        assert!(!SmmuSecurityState::Absent.is_enforcing());
    }

    #[test]
    fn smmu_fault_policy_production_safety() {
        assert!(SmmuFaultPolicy::TerminateGuest.is_production_safe());
        assert!(!SmmuFaultPolicy::LogAndContinue.is_production_safe());
    }

    // ── SpectreV2Mitigation ───────────────────────────────────────────────────

    #[test]
    fn spectre_software_flush_variants() {
        assert!(SpectreV2Mitigation::ClrBhb.has_software_flush());
        assert!(SpectreV2Mitigation::BhbLoopFlush { iterations: 32 }.has_software_flush());
        assert!(SpectreV2Mitigation::IcacheFlush.has_software_flush());
        assert!(!SpectreV2Mitigation::HardwareIsolated.has_software_flush());
    }

    #[test]
    fn bhb_loop_zero_iterations_is_error() {
        let cfg = BranchPredictorFlushConfig {
            mitigation: SpectreV2Mitigation::BhbLoopFlush { iterations: 0 },
            flush_on_entry: true,
            flush_on_exit: true,
        };
        assert_eq!(cfg.validate(), Err(SecurityError::SpectreFlushIterationsZero));
    }

    #[test]
    fn bhb_loop_nonzero_iterations_ok() {
        let cfg = BranchPredictorFlushConfig {
            mitigation: SpectreV2Mitigation::BhbLoopFlush { iterations: 32 },
            flush_on_entry: true,
            flush_on_exit: true,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn clrbhb_config_ok() {
        let cfg = BranchPredictorFlushConfig {
            mitigation: SpectreV2Mitigation::ClrBhb,
            flush_on_entry: true,
            flush_on_exit: true,
        };
        assert!(cfg.validate().is_ok());
    }

    // ── GuestIpaRange / HvcInputValidator ────────────────────────────────────

    #[test]
    fn guest_ipa_range_contains() {
        let range = GuestIpaRange { base: 0x4000_0000, end: 0x8000_0000 };
        assert!(range.contains(0x4000_0000));
        assert!(range.contains(0x7FFF_FFFF));
        assert!(!range.contains(0x8000_0000)); // exclusive end
        assert!(!range.contains(0x3FFF_FFFF)); // before base
    }

    #[test]
    fn guest_ipa_range_contains_range() {
        let range = GuestIpaRange { base: 0x4000_0000, end: 0x8000_0000 };
        assert!(range.contains_range(0x4000_0000, 0x1000));
        assert!(range.contains_range(0x7FFF_F000, 0x1000)); // last page
        assert!(!range.contains_range(0x7FFF_F000, 0x2000)); // straddles end
        assert!(!range.contains_range(0x3FFF_F000, 0x1000)); // before base
    }

    #[test]
    fn guest_ipa_range_overflow_safe() {
        let range = GuestIpaRange { base: 0x0, end: 0xFFFF_FFFF_FFFF_FFFF };
        // u64 overflow in ipa + size must not succeed
        assert!(!range.contains_range(0xFFFF_FFFF_FFFF_F000, 0x2000));
    }

    #[test]
    fn hvc_validator_in_range_ok() {
        let v = HvcInputValidator {
            guest_range: GuestIpaRange { base: 0x4000_0000, end: 0x8000_0000 },
        };
        assert!(v.validate_ipa_argument(0x5000_0000).is_ok());
        assert!(v.validate_ipa_range(0x5000_0000, 0x1000).is_ok());
    }

    #[test]
    fn hvc_validator_out_of_range_error() {
        let v = HvcInputValidator {
            guest_range: GuestIpaRange { base: 0x4000_0000, end: 0x8000_0000 },
        };
        assert_eq!(
            v.validate_ipa_argument(0xC000_0000),
            Err(SecurityError::HvcAddressOutOfGuestRange { ipa: 0xC000_0000 })
        );
        assert_eq!(
            v.validate_ipa_range(0x7FFF_0000, 0x10000 + 0x1000),
            Err(SecurityError::HvcRangeOutOfGuestRange { ipa: 0x7FFF_0000, size: 0x10000 + 0x1000 })
        );
    }

    // ── AttackSurface ─────────────────────────────────────────────────────────

    #[test]
    fn attack_surface_entries_carry_data_correctly() {
        assert!(AttackSurfaceEntry::HvcCall.carries_guest_data());
        assert!(AttackSurfaceEntry::TrappedSysregWrite.carries_guest_data());
        assert!(AttackSurfaceEntry::SmmuFault.carries_guest_data());
        assert!(!AttackSurfaceEntry::TimerInterrupt.carries_guest_data());
    }

    #[test]
    fn attack_surface_table_non_empty() {
        assert!(!ATTACK_SURFACE.is_empty());
        for entry in ATTACK_SURFACE {
            assert!(!entry.validation_requirement().is_empty());
        }
    }

    // ── UnsafeAuditRecord ────────────────────────────────────────────────────

    #[test]
    fn unsafe_audit_status_acceptable() {
        assert!(UnsafeAuditStatus::Reviewed.is_acceptable());
        assert!(!UnsafeAuditStatus::PendingReview.is_acceptable());
        assert!(!UnsafeAuditStatus::Unannotated.is_acceptable());
    }

    #[test]
    fn unsafe_audit_record_passes() {
        let reviewed = UnsafeAuditRecord {
            file: "hypervisor/src/memory.rs",
            line: 42,
            safety_rationale: "pointer derived from hardware-documented address in SMMU MMIO range",
            status: UnsafeAuditStatus::Reviewed,
        };
        assert!(reviewed.passes());

        let pending = UnsafeAuditRecord {
            file: "hypervisor/src/gic.rs",
            line: 100,
            safety_rationale: "ICH_LR write to hardware MMIO via documented GICv3 register offset",
            status: UnsafeAuditStatus::PendingReview,
        };
        assert!(!pending.passes());
    }

    // ── SecurityConfiguration ─────────────────────────────────────────────────

    #[test]
    fn security_configuration_valid() {
        let cfg = SecurityConfiguration {
            smmu_state: SmmuSecurityState::Active,
            fault_policy: SmmuFaultPolicy::TerminateGuest,
            spectre_config: BranchPredictorFlushConfig {
                mitigation: SpectreV2Mitigation::ClrBhb,
                flush_on_entry: true,
                flush_on_exit: true,
            },
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn security_configuration_smmu_absent_fails() {
        let cfg = SecurityConfiguration {
            smmu_state: SmmuSecurityState::Absent,
            fault_policy: SmmuFaultPolicy::TerminateGuest,
            spectre_config: BranchPredictorFlushConfig {
                mitigation: SpectreV2Mitigation::ClrBhb,
                flush_on_entry: true,
                flush_on_exit: true,
            },
        };
        assert_eq!(cfg.validate(), Err(SecurityError::SmmuAbsent));
    }

    #[test]
    fn security_configuration_log_and_continue_fails() {
        let cfg = SecurityConfiguration {
            smmu_state: SmmuSecurityState::Active,
            fault_policy: SmmuFaultPolicy::LogAndContinue,
            spectre_config: BranchPredictorFlushConfig {
                mitigation: SpectreV2Mitigation::ClrBhb,
                flush_on_entry: true,
                flush_on_exit: true,
            },
        };
        assert_eq!(cfg.validate(), Err(SecurityError::SmmuFaultPolicyUnsafe));
    }

    #[test]
    fn security_configuration_smmu_pending_fails() {
        let cfg = SecurityConfiguration {
            smmu_state: SmmuSecurityState::Pending,
            fault_policy: SmmuFaultPolicy::TerminateGuest,
            spectre_config: BranchPredictorFlushConfig {
                mitigation: SpectreV2Mitigation::ClrBhb,
                flush_on_entry: true,
                flush_on_exit: true,
            },
        };
        assert_eq!(cfg.validate(), Err(SecurityError::SmmuAbsent));
    }

    // ── SecuritySummary ───────────────────────────────────────────────────────

    #[test]
    fn security_summary_all_secure() {
        let s = SecuritySummary {
            stage2_active: true,
            smmu_enforcing: true,
            gic_partitioned: true,
            spectre_mitigated: true,
        };
        assert!(s.all_secure());
    }

    #[test]
    fn security_summary_partial_fails() {
        let cases = [
            SecuritySummary { stage2_active: false, smmu_enforcing: true,  gic_partitioned: true,  spectre_mitigated: true },
            SecuritySummary { stage2_active: true,  smmu_enforcing: false, gic_partitioned: true,  spectre_mitigated: true },
            SecuritySummary { stage2_active: true,  smmu_enforcing: true,  gic_partitioned: false, spectre_mitigated: true },
            SecuritySummary { stage2_active: true,  smmu_enforcing: true,  gic_partitioned: true,  spectre_mitigated: false },
        ];
        for s in &cases {
            assert!(!s.all_secure(), "expected not-all-secure for {:?}", s);
        }
    }
}
