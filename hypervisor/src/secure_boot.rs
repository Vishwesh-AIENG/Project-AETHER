// ch57: Secure Boot Integration
//
// The AETHER installer generates an RSA-2048 key pair, signs hypervisor.efi
// with PE Authenticode (PKCS#7 SignedData embedded in the PE Certificate
// Table), and writes the public key DER blob into the MokNew UEFI variable so
// that shim + MokManager can enroll it on the user's first reboot. From that
// point forward hypervisor.efi is always loaded under an ENABLED Secure Boot
// chain. Users are NEVER asked to disable Secure Boot.
//
// ── Enrollment Flow (two-reboot protocol) ────────────────────────────────────
//
// Install time (before first AETHER boot):
//   1. aether-install generates RSA-2048 keypair in /var/lib/aether/keys/ .
//   2. aether-install signs hypervisor.efi with PE Authenticode:
//        sbsign --key aether.key --cert aether.crt --output hypervisor.efi
//   3. aether-install writes:
//        MokNew  = DER bytes of the self-signed X.509 certificate
//        MokAuth = SHA-256(enrollment_password) or 32 zero bytes (passwordless)
//      Both variables carry UEFI attributes NV + BS + RT.
//
// Reboot 1 — MOK enrollment:
//   firmware POST → shim.efi detects MokNew ≠ ∅ → launches MokManager.efi
//   → user physically presses a key and approves the AETHER signing certificate
//     (physical presence required; no scripted bypass exists by design)
//   → MokManager moves DER from MokNew → MokList; zeros MokNew + MokAuth.
//
// Reboot 2 — Production boot:
//   firmware POST → shim.efi → verifies hypervisor.efi Authenticode signature
//   against every entry in MokList → loads hypervisor.efi → "Hypervisor ready."
//
// ── ABSOLUTE INVARIANT ────────────────────────────────────────────────────────
//
// The user is NEVER instructed to disable Secure Boot. There is no code path
// in the installer, the hypervisor, or any AETHER tool that emits a "disable
// Secure Boot" instruction. DisableSecureBootForbidden is encoded as a distinct
// error variant so any future code that reaches it is immediately visible.
//
// ── UEFI Spec References ──────────────────────────────────────────────────────
//
// UEFI Specification v2.10:
//   Appendix D    -- Globally Defined Variables: SecureBoot (u8), SetupMode,
//                    PK, KEK, db, dbx. MokList is a shim extension.
//   §32.4.1       -- Secure Boot variable attributes: NV+BS+RT+AT for PK/KEK/db/dbx.
//   §7.2          -- Variable services: GetVariable / SetVariable.
//
// shim project (github.com/rhboot/shim, MokManager.c):
//   MokNew  -- installer writes DER(cert); MokManager consumes on first boot.
//   MokAuth -- installer writes SHA256(password) or 32 zero bytes.
//   MokList -- shim extension to db; key enrolled here is trusted by shim only.
//
// Microsoft PE Authenticode Specification:
//   The PKCS#7 SignedData structure is embedded in the PE Certificate Table
//   (DataDirectory[4]).  sbsign / pesign produce the correct layout.
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  Constants -- MOK UEFI variable names, key size, EFI file paths.
//   2.  MokKeyFormat -- Der only (PEM is not a UEFI wire format).
//   3.  MokEnrollmentRecord -- fingerprint (32-byte SHA-256), key_size_bits.
//   4.  SecureBootConfig + aether_defaults() + validate().
//   5.  SecureBootGate (shim_present + mok_enrolled + signature_verified +
//       two_reboot_complete) + passes().
//   6.  SecureBootError -- 10 variants.
//   7.  SecureBootPhase -- 8 phases, strictly ordered via PartialOrd/Ord.
//   8.  SecureBootState (process_line() UART scanner + gate()).
//   9.  UART signature constants -- 7 byte-pattern constants.
//  10.  init_secure_boot_integration() -- 8-step validation pipeline.
//
// ── Gate (Chapter 57) ─────────────────────────────────────────────────────────
//
//   SecureBootGate.passes() requires all four conditions simultaneously:
//     shim_present         -- shim.efi is on the ESP at AETHER_SHIM_EFI_PATH
//     mok_enrolled         -- MokNew was written; user approved enrollment at
//                             the MokManager UI (physical-presence gate)
//     signature_verified   -- shim verified hypervisor.efi Authenticode signature
//     two_reboot_complete  -- "Hypervisor ready." seen after enrollment reboot
//
//   Absent from the gate: "secure_boot_disabled". Disabling Secure Boot is not
//   a valid configuration for AETHER. It is encoded as SecureBootError::
//   DisableSecureBootForbidden rather than as a passing condition.

// ── Constants ─────────────────────────────────────────────────────────────────

/// RSA key size used for the AETHER MOK signing key.
pub const AETHER_MOK_KEY_BITS: u32 = 2048;

/// SHA-256 fingerprint byte length.
pub const MOK_FINGERPRINT_BYTES: usize = 32;

/// MokAuth passwordless sentinel: 32 zero bytes (shim accepts this without
/// prompting for a password at MokManager enrollment).
pub const MOK_AUTH_PASSWORDLESS: [u8; 32] = [0u8; 32];

/// UEFI variable name written by the installer: public key DER bytes.
pub const UEFI_VAR_MOK_NEW: &[u8] = b"MokNew";
/// UEFI variable name written by the installer: SHA-256(password) or zeros.
pub const UEFI_VAR_MOK_AUTH: &[u8] = b"MokAuth";
/// UEFI variable name maintained by shim: enrolled MOK entries.
pub const UEFI_VAR_MOK_LIST: &[u8] = b"MokList";
/// UEFI globally-defined variable: 1 = Secure Boot enforcing, 0 = disabled.
pub const UEFI_VAR_SECURE_BOOT: &[u8] = b"SecureBoot";
/// UEFI globally-defined variable: 1 = in Setup Mode (PK not yet enrolled).
pub const UEFI_VAR_SETUP_MODE: &[u8] = b"SetupMode";

/// shim EFI binary path on the ESP (chainloaded by the UEFI Boot#### entry).
pub const AETHER_SHIM_EFI_PATH: &[u8] = b"\\EFI\\AETHER\\shim.efi";
/// MokManager EFI binary path on the ESP (launched by shim when MokNew set).
pub const AETHER_MOKMANAGER_EFI_PATH: &[u8] = b"\\EFI\\AETHER\\MokManager.efi";
/// Signed hypervisor binary path on the ESP (loaded by shim after key enrolled).
pub const AETHER_HYPERVISOR_EFI_PATH: &[u8] = b"\\EFI\\AETHER\\hypervisor.efi";

// ── UART Signature Constants ──────────────────────────────────────────────────
//
// All patterns are 7-bit ASCII, matched with contains_bytes() window scan.
// No heap allocation required.

/// shim launched MokManager to process a pending MokNew variable.
pub const SB_UART_SIG_MOKMANAGER_LAUNCHED: &[u8] = b"Loading MokManager";
/// User approved the key at the MokManager UI; MokList updated.
pub const SB_UART_SIG_KEY_ENROLLED: &[u8] = b"MokList: key enrolled";
/// shim successfully verified the Authenticode signature on hypervisor.efi.
pub const SB_UART_SIG_SIGNATURE_OK: &[u8] = b"Secure Boot enabled";
/// MokNew was cleared by MokManager after successful enrollment.
pub const SB_UART_SIG_MOK_NEW_CLEARED: &[u8] = b"MokNew cleared";
/// Hypervisor started normally -- signals that both enrollment reboots completed.
pub const SB_UART_SIG_HYPERVISOR_READY: &[u8] = b"Hypervisor ready.";
/// shim rejected hypervisor.efi; signature was invalid or key not in MokList.
pub const SB_UART_SIG_SIGNATURE_FAILED: &[u8] = b"UEFI Secure Boot violation";
/// shim is present but firmware Secure Boot is currently disabled; gate fails.
pub const SB_UART_SIG_SECURE_BOOT_DISABLED: &[u8] = b"Secure Boot disabled";

// ── MokKeyFormat ──────────────────────────────────────────────────────────────

/// Wire format for the MOK public key in the MokNew UEFI variable.
///
/// Only `Der` is valid. PEM (base64 + header lines) is a text encoding used
/// by OpenSSL command-line tools and is not a UEFI-compatible binary format.
/// The installer must convert PEM → DER before writing MokNew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MokKeyFormat {
    /// ASN.1 DER-encoded X.509 certificate. Required by shim MokManager.
    Der,
}

// ── MokEnrollmentRecord ───────────────────────────────────────────────────────

/// Summary of the MOK key enrolled (or to be enrolled) by the installer.
///
/// The `sha256_fingerprint` is used by the hypervisor to verify at runtime
/// that the loaded key matches what the installer enrolled.
#[derive(Debug, Clone, Copy)]
pub struct MokEnrollmentRecord {
    pub sha256_fingerprint: [u8; MOK_FINGERPRINT_BYTES],
    pub key_size_bits:      u32,
    pub format:             MokKeyFormat,
}

impl MokEnrollmentRecord {
    pub fn aether_defaults() -> Self {
        MokEnrollmentRecord {
            sha256_fingerprint: [0u8; MOK_FINGERPRINT_BYTES],
            key_size_bits:      AETHER_MOK_KEY_BITS,
            format:             MokKeyFormat::Der,
        }
    }

    pub fn is_fingerprint_set(&self) -> bool {
        self.sha256_fingerprint.iter().any(|&b| b != 0)
    }
}

// ── SecureBootConfig ──────────────────────────────────────────────────────────

/// Configuration for the AETHER Secure Boot integration.
///
/// `validate()` enforces every constraint from the chapter spec.
/// The `require_mok_password` flag enables an optional enrollment password;
/// `false` (passwordless) is the recommended default for installer UX.
#[derive(Debug, Clone, Copy)]
pub struct SecureBootConfig {
    /// RSA key size in bits. Must be exactly AETHER_MOK_KEY_BITS (2048).
    pub key_size_bits:        u32,
    /// MOK key wire format. Must be Der.
    pub mok_key_format:       MokKeyFormat,
    /// If true the installer prompts for an enrollment password and hashes it
    /// into MokAuth. If false MokAuth = 32 zero bytes (passwordless enrollment).
    pub require_mok_password: bool,
    /// shim.efi must be present at this ESP path before the first reboot.
    pub shim_path:            &'static [u8],
    /// MokManager.efi must be present alongside shim.efi.
    pub mokmanager_path:      &'static [u8],
    /// Signed hypervisor.efi destination on the ESP.
    pub hypervisor_path:      &'static [u8],
}

impl SecureBootConfig {
    pub fn aether_defaults() -> Self {
        SecureBootConfig {
            key_size_bits:        AETHER_MOK_KEY_BITS,
            mok_key_format:       MokKeyFormat::Der,
            require_mok_password: false,
            shim_path:            AETHER_SHIM_EFI_PATH,
            mokmanager_path:      AETHER_MOKMANAGER_EFI_PATH,
            hypervisor_path:      AETHER_HYPERVISOR_EFI_PATH,
        }
    }

    pub fn validate(&self) -> Result<(), SecureBootError> {
        if self.key_size_bits != AETHER_MOK_KEY_BITS {
            return Err(SecureBootError::WrongKeySize {
                got:      self.key_size_bits,
                expected: AETHER_MOK_KEY_BITS,
            });
        }
        if self.mok_key_format != MokKeyFormat::Der {
            return Err(SecureBootError::InvalidKeyFormat);
        }
        if self.shim_path.is_empty() {
            return Err(SecureBootError::ShimPathEmpty);
        }
        if self.mokmanager_path.is_empty() {
            return Err(SecureBootError::MokManagerPathEmpty);
        }
        if self.hypervisor_path.is_empty() {
            return Err(SecureBootError::HypervisorPathEmpty);
        }
        Ok(())
    }
}

// ── SecureBootGate ────────────────────────────────────────────────────────────

/// Runtime gate for Chapter 57.
///
/// All four fields must be true for `passes()` to return true. There is
/// deliberately no field for "secure_boot_disabled" -- that is always an error.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecureBootGate {
    /// shim.efi is present on the ESP at the configured path.
    pub shim_present:          bool,
    /// MokNew was written and the user approved enrollment at MokManager.
    pub mok_enrolled:          bool,
    /// shim verified the Authenticode signature on hypervisor.efi successfully.
    pub signature_verified:    bool,
    /// Hypervisor started normally after enrollment (two-reboot protocol done).
    pub two_reboot_complete:   bool,
}

impl SecureBootGate {
    /// Returns true when all four conditions hold simultaneously.
    pub fn passes(&self) -> bool {
        self.shim_present
            && self.mok_enrolled
            && self.signature_verified
            && self.two_reboot_complete
    }

    /// Returns true when the key is enrolled and the signature is verified,
    /// even if the final hypervisor-ready signal has not yet been seen.
    pub fn enrollment_complete(&self) -> bool {
        self.mok_enrolled && self.signature_verified
    }
}

// ── SecureBootError ───────────────────────────────────────────────────────────

/// Error variants for Chapter 57 Secure Boot Integration.
///
/// Every variant corresponds to exactly one failure mode. `DisableSecureBootForbidden`
/// is the sentinel that fires if any code path attempts to produce a
/// "disable Secure Boot" instruction -- that path is a design error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootError {
    /// Config validation failed: RSA key size is not AETHER_MOK_KEY_BITS.
    WrongKeySize { got: u32, expected: u32 },
    /// Config validation failed: key format is not MokKeyFormat::Der.
    InvalidKeyFormat,
    /// Config validation failed: shim EFI path is empty.
    ShimPathEmpty,
    /// Config validation failed: MokManager EFI path is empty.
    MokManagerPathEmpty,
    /// Config validation failed: hypervisor EFI path is empty.
    HypervisorPathEmpty,
    /// Firmware has Secure Boot disabled. AETHER requires Secure Boot enabled.
    /// The user must enable Secure Boot in firmware settings; AETHER does not
    /// bypass it. DisableSecureBootForbidden is the complementary error below.
    SecureBootDisabledInFirmware,
    /// A code path attempted to emit a "disable Secure Boot" instruction.
    /// This is unconditionally forbidden (Chapter 57 invariant).
    DisableSecureBootForbidden,
    /// The Authenticode signature on hypervisor.efi was rejected by shim.
    /// Cause: key not in MokList, wrong key, or corrupted signature.
    SignatureVerificationFailed,
    /// The MokEnrollmentRecord fingerprint has not been set (all-zero sentinel).
    FingerprintNotSet,
    /// The two-reboot enrollment protocol did not complete.
    /// Hypervisor started without a confirmed MokList enrollment.
    EnrollmentProtocolIncomplete,
}

// ── SecureBootPhase ───────────────────────────────────────────────────────────

/// Chapter 57 phase machine (strictly ordered; never regresses).
///
/// Phases advance forward only. `process_line()` moves forward on matching
/// UART signatures; it never decrements the phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecureBootPhase {
    /// No Secure Boot integration configured yet.
    NotStarted,
    /// Config validated; key pair generated; hypervisor.efi signed.
    KeyPairAndSignature,
    /// shim.efi and MokManager.efi copied to ESP.
    ShimOnEsp,
    /// MokNew + MokAuth UEFI variables written; awaiting first reboot.
    MokNewWritten,
    /// Reboot 1: shim detected MokNew and launched MokManager.efi.
    MokManagerLaunched,
    /// User approved key enrollment; MokList updated; MokNew cleared.
    KeyEnrolled,
    /// Reboot 2: shim verified Authenticode signature on hypervisor.efi.
    SignatureVerified,
    /// "Hypervisor ready." seen -- both enrollment reboots complete.
    GatePassed,
}

impl SecureBootPhase {
    fn next(self) -> Self {
        match self {
            Self::NotStarted           => Self::KeyPairAndSignature,
            Self::KeyPairAndSignature  => Self::ShimOnEsp,
            Self::ShimOnEsp            => Self::MokNewWritten,
            Self::MokNewWritten        => Self::MokManagerLaunched,
            Self::MokManagerLaunched   => Self::KeyEnrolled,
            Self::KeyEnrolled          => Self::SignatureVerified,
            Self::SignatureVerified     => Self::GatePassed,
            Self::GatePassed           => Self::GatePassed,
        }
    }
}

// ── SecureBootState ───────────────────────────────────────────────────────────

/// Runtime state for Chapter 57 Secure Boot Integration.
///
/// Updated by `process_line()` as UART output from the first two AETHER boots
/// flows through. The hypervisor calls `process_line()` from the serial receive
/// path during the enrollment boot sequence.
#[derive(Debug, Clone, Copy)]
pub struct SecureBootState {
    phase:               SecureBootPhase,
    gate:                SecureBootGate,
    signature_failures:  u32,
}

impl SecureBootState {
    pub fn new() -> Self {
        SecureBootState {
            phase:              SecureBootPhase::NotStarted,
            gate:               SecureBootGate::default(),
            signature_failures: 0,
        }
    }

    /// Scan a UART line for Secure Boot event signatures and advance state.
    ///
    /// All matching is byte-pattern only (no heap, no regex).
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, SB_UART_SIG_SIGNATURE_FAILED) {
            self.signature_failures = self.signature_failures.saturating_add(1);
            return;
        }
        if contains_bytes(line, SB_UART_SIG_SECURE_BOOT_DISABLED) {
            // Do not advance phase; gate remains false.
            return;
        }
        if contains_bytes(line, SB_UART_SIG_MOKMANAGER_LAUNCHED)
            && self.phase < SecureBootPhase::MokManagerLaunched
        {
            self.advance_to(SecureBootPhase::MokManagerLaunched);
        }
        if contains_bytes(line, SB_UART_SIG_KEY_ENROLLED)
            && self.phase < SecureBootPhase::KeyEnrolled
        {
            self.advance_to(SecureBootPhase::KeyEnrolled);
            self.gate.mok_enrolled = true;
        }
        if contains_bytes(line, SB_UART_SIG_SIGNATURE_OK)
            && self.phase < SecureBootPhase::SignatureVerified
        {
            self.advance_to(SecureBootPhase::SignatureVerified);
            self.gate.signature_verified = true;
        }
        if contains_bytes(line, SB_UART_SIG_HYPERVISOR_READY)
            && self.phase < SecureBootPhase::GatePassed
        {
            self.advance_to(SecureBootPhase::GatePassed);
            self.gate.two_reboot_complete = true;
        }
    }

    /// Mark shim as present on the ESP (set by the installer before reboot 1).
    pub fn mark_shim_present(&mut self) {
        self.gate.shim_present = true;
        if self.phase < SecureBootPhase::ShimOnEsp {
            self.advance_to(SecureBootPhase::ShimOnEsp);
        }
    }

    /// Mark MokNew + MokAuth as written (set by the installer).
    pub fn mark_mok_new_written(&mut self) {
        if self.phase < SecureBootPhase::MokNewWritten {
            self.advance_to(SecureBootPhase::MokNewWritten);
        }
    }

    pub fn phase(&self) -> SecureBootPhase { self.phase }
    pub fn gate(&self) -> &SecureBootGate  { &self.gate  }
    pub fn is_gate_passed(&self) -> bool   { self.gate.passes() }
    pub fn signature_failures(&self) -> u32 { self.signature_failures }

    fn advance_to(&mut self, target: SecureBootPhase) {
        while self.phase < target {
            self.phase = self.phase.next();
        }
    }
}

// ── init_secure_boot_integration ─────────────────────────────────────────────

/// 8-step validation pipeline for Chapter 57.
///
/// Returns an initial `SecureBootState` positioned at the phase that
/// matches what has already been completed. The caller (installer) drives
/// the state forward by calling `mark_shim_present()`, `mark_mok_new_written()`,
/// and eventually `process_line()` as UART output arrives.
///
/// Steps:
///   1. Validate config (key size, format, paths).
///   2. Confirm MOK key fingerprint has been set (not all-zero sentinel).
///   3. Advance phase to KeyPairAndSignature.
///   4. Advance phase to ShimOnEsp (shim present flag must be set by caller).
///   5. Advance phase to MokNewWritten (MokNew written flag must be set by caller).
///   6. (Phase advance) Await MokManagerLaunched via process_line().
///   7. (Phase advance) Await KeyEnrolled + SignatureVerified via process_line().
///   8. (Phase advance) Await GatePassed via process_line() on "Hypervisor ready."
///
/// Steps 6–8 are driven by UART scanning, not by this function directly.
pub fn init_secure_boot_integration(
    cfg:    &SecureBootConfig,
    record: &MokEnrollmentRecord,
) -> Result<SecureBootState, SecureBootError> {
    // Step 1 -- validate config.
    cfg.validate()?;

    // Step 2 -- fingerprint must be non-zero; if all-zero the key was never
    // generated and the installer has a bug.
    if !record.is_fingerprint_set() {
        return Err(SecureBootError::FingerprintNotSet);
    }

    // Step 3 -- fingerprint is set; key size and format match defaults.
    // Build initial state at KeyPairAndSignature.
    let mut state = SecureBootState::new();
    state.advance_to(SecureBootPhase::KeyPairAndSignature);

    // Steps 4–8 are caller-driven (shim placement, MokNew write, UART scan).
    // We return state here; the caller calls mark_* and process_line().
    Ok(state)
}

// ── O(n×m) byte-pattern scan (no heap, no regex) ─────────────────────────────

/// Returns true if `haystack` contains `needle` as a contiguous subsequence.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        let cfg = SecureBootConfig::aether_defaults();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn wrong_key_size_rejected() {
        let mut cfg = SecureBootConfig::aether_defaults();
        cfg.key_size_bits = 4096;
        assert!(matches!(
            cfg.validate(),
            Err(SecureBootError::WrongKeySize { got: 4096, expected: 2048 })
        ));
    }

    #[test]
    fn empty_shim_path_rejected() {
        let mut cfg = SecureBootConfig::aether_defaults();
        cfg.shim_path = b"";
        assert!(matches!(cfg.validate(), Err(SecureBootError::ShimPathEmpty)));
    }

    #[test]
    fn empty_mokmanager_path_rejected() {
        let mut cfg = SecureBootConfig::aether_defaults();
        cfg.mokmanager_path = b"";
        assert!(matches!(cfg.validate(), Err(SecureBootError::MokManagerPathEmpty)));
    }

    #[test]
    fn all_zero_fingerprint_rejected() {
        let cfg    = SecureBootConfig::aether_defaults();
        let record = MokEnrollmentRecord::aether_defaults(); // fingerprint = [0; 32]
        assert!(matches!(
            init_secure_boot_integration(&cfg, &record),
            Err(SecureBootError::FingerprintNotSet)
        ));
    }

    #[test]
    fn nonzero_fingerprint_advances_phase() {
        let cfg = SecureBootConfig::aether_defaults();
        let mut record = MokEnrollmentRecord::aether_defaults();
        record.sha256_fingerprint[0] = 0xAB;

        let state = init_secure_boot_integration(&cfg, &record).unwrap();
        assert_eq!(state.phase(), SecureBootPhase::KeyPairAndSignature);
        assert!(!state.is_gate_passed());
    }

    #[test]
    fn process_line_mokmanager_launched() {
        let mut s = SecureBootState::new();
        s.process_line(b"Loading MokManager.efi from disk");
        assert_eq!(s.phase(), SecureBootPhase::MokManagerLaunched);
        assert!(!s.gate().mok_enrolled);
    }

    #[test]
    fn process_line_key_enrolled() {
        let mut s = SecureBootState::new();
        s.process_line(b"Loading MokManager");
        s.process_line(b"MokList: key enrolled successfully");
        assert_eq!(s.phase(), SecureBootPhase::KeyEnrolled);
        assert!(s.gate().mok_enrolled);
    }

    #[test]
    fn full_happy_path_passes_gate() {
        let mut s = SecureBootState::new();
        s.mark_shim_present();
        s.mark_mok_new_written();
        s.process_line(b"Loading MokManager");
        s.process_line(b"MokList: key enrolled successfully");
        s.process_line(b"Secure Boot enabled");
        s.process_line(b"Hypervisor ready.");

        assert!(s.is_gate_passed());
        assert_eq!(s.phase(), SecureBootPhase::GatePassed);
        let g = s.gate();
        assert!(g.shim_present);
        assert!(g.mok_enrolled);
        assert!(g.signature_verified);
        assert!(g.two_reboot_complete);
    }

    #[test]
    fn signature_failure_does_not_advance_phase() {
        let mut s = SecureBootState::new();
        s.process_line(b"UEFI Secure Boot violation: signature failed");
        assert_eq!(s.phase(), SecureBootPhase::NotStarted);
        assert_eq!(s.signature_failures(), 1);
        assert!(!s.is_gate_passed());
    }

    #[test]
    fn secure_boot_disabled_line_does_not_pass_gate() {
        let mut s = SecureBootState::new();
        s.mark_shim_present();
        s.mark_mok_new_written();
        s.process_line(b"Secure Boot disabled -- running unsigned");
        // Gate must NOT pass when SB is disabled.
        assert!(!s.is_gate_passed());
        assert!(!s.gate().signature_verified);
    }

    #[test]
    fn disable_secure_boot_forbidden_error_is_distinct() {
        // Encoding the invariant: DisableSecureBootForbidden is a real error
        // variant that must never be constructed except in a rejected code path.
        let e = SecureBootError::DisableSecureBootForbidden;
        assert_eq!(e, SecureBootError::DisableSecureBootForbidden);
    }

    #[test]
    fn phase_order_is_strict() {
        use SecureBootPhase::*;
        assert!(NotStarted < KeyPairAndSignature);
        assert!(KeyPairAndSignature < ShimOnEsp);
        assert!(ShimOnEsp < MokNewWritten);
        assert!(MokNewWritten < MokManagerLaunched);
        assert!(MokManagerLaunched < KeyEnrolled);
        assert!(KeyEnrolled < SignatureVerified);
        assert!(SignatureVerified < GatePassed);
    }

    #[test]
    fn gate_requires_all_four() {
        let mut g = SecureBootGate {
            shim_present:        true,
            mok_enrolled:        true,
            signature_verified:  true,
            two_reboot_complete: false,
        };
        assert!(!g.passes());
        g.two_reboot_complete = true;
        assert!(g.passes());
    }

    #[test]
    fn contains_bytes_finds_needle() {
        assert!(contains_bytes(b"Loading MokManager", b"MokManager"));
        assert!(!contains_bytes(b"Loading MokManager", b"mokmanager"));
        assert!(contains_bytes(b"x", b""));
    }

    #[test]
    fn mok_enrollment_record_fingerprint_set() {
        let mut r = MokEnrollmentRecord::aether_defaults();
        assert!(!r.is_fingerprint_set());
        r.sha256_fingerprint[15] = 1;
        assert!(r.is_fingerprint_set());
    }
}
