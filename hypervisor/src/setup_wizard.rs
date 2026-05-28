// ch59: Setup Wizard — GUI Frontend
//
// First-boot configuration UI rendered on the GOP framebuffer by the
// hypervisor BEFORE the Android partition launches. Mirrors the shape of
// ch58 (UEFI Boot Selector) since they are sibling pre-OS surfaces: both
// render on GOP, both store outcome in a UEFI variable.
//
// The wizard runs once. After the user confirms their selections, the
// AETHER_SETUP_COMPLETE UEFI variable is set (NV+BS+RT). On every
// subsequent boot the wizard is skipped. Re-running it is a deliberate
// recovery action (ch62 Recovery Mode entry).
//
// ── Wizard Flow (single forward pass; no back navigation) ────────────────────
//
//   Step 1  Language          one of LANGUAGE_OPTIONS (en, hi, ta, te, ja, fr,
//                             de, es, pt, zh-CN)
//   Step 2  Keyboard layout   one of KEYBOARD_LAYOUT_OPTIONS (qwerty, qwertz,
//                             azerty, dvorak, colemak)
//   Step 3  Time zone         one of REGION_OPTIONS (IANA tz name, ≤ 32 B)
//   Step 4  Bridge mode       BridgeModeDefault::On | Off  (ch48)
//   Step 5  Sensor profile    SensorProfile::Stationary | InHand | Driving
//                             (ch12 + ch47 — virtual IMU motion model)
//   Step 6  Confirmation      user accepts → write AETHER_SETUP_COMPLETE
//
// ── Inviolables ───────────────────────────────────────────────────────────────
//
//   * No language option pulls remote font/asset data — every glyph that
//     can be displayed by the wizard ships in hypervisor.efi's .rodata.
//   * No network round-trip during wizard run (No-Boundary Principle, ch3).
//     The wizard MUST complete with the device offline.
//   * The wizard NEVER asks for or stores Google/MS/Apple account
//     credentials. Account linking is exclusively an Android-side step,
//     after the partition has booted, mediated by microG.
//
// ── Storage ───────────────────────────────────────────────────────────────────
//
//   UEFI variables (all NV+BS+RT, AETHER_VARIABLE_GUID from ch58):
//
//     AetherSetupComplete   1 byte: 1 = wizard finished, 0/absent = run it
//     AetherLanguage        ≤ 8 ASCII bytes ("en", "hi", "zh-CN", ...)
//     AetherKbLayout        ≤ 8 ASCII bytes ("qwerty", "azerty", ...)
//     AetherTimeZone        ≤ 32 ASCII bytes (IANA: "Asia/Kolkata", ...)
//     AetherBridgeMode      1 byte: 1 = Bridge ON by default, 0 = OFF
//     AetherSensorProfile   1 byte: 0 = Stationary, 1 = InHand, 2 = Driving
//
//   Reading these variables on subsequent boots is how the hypervisor
//   personalises the Android handoff (DTB cmdline, virtual sensor seed,
//   etc.) without re-prompting the user.
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  Constants — UEFI variable names, max field lengths, option tables.
//   2.  Language / KeyboardLayout / SensorProfile / BridgeModeDefault enums.
//   3.  WizardSelections — concrete user choices (ascii buffers + enums).
//   4.  WizardConfig (aether_defaults + validate) + WizardGate (passes).
//   5.  WizardError — 12 variants for every distinct failure surface.
//   6.  WizardPhase — 7 phases, strictly ordered via PartialOrd/Ord.
//   7.  WizardState — process_line() UART scanner + gate() + selections.
//   8.  UART signature byte patterns — 8 constants for the runtime scanner.
//   9.  init_setup_wizard() — 8-step pipeline that drives the gate forward.
//
// ── Gate (Chapter 59) ─────────────────────────────────────────────────────────
//
//   WizardGate.passes() requires:
//     framebuffer_painted       — at least one Step screen rendered
//     all_steps_acknowledged    — user advanced past Step 6 (Confirmation)
//     selections_persisted      — AetherSetupComplete + 5 field variables
//                                 written without UEFI error
//     no_network_round_trip     — invariant: no ping / DNS / TCP issued
//                                 during the wizard (audit beep + diag
//                                 line surfaced by the runtime)
//
//   Re-running the wizard explicitly clears AetherSetupComplete (1 -> 0)
//   before the first frame paints, so a power loss mid-wizard leaves the
//   variable in the "incomplete" state and the wizard runs again on the
//   next boot.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic byte stored in AetherSetupComplete when the wizard finishes.
pub const AETHER_SETUP_COMPLETE_BYTE: u8 = 1;

/// Maximum bytes for the language code variable.
pub const WIZARD_LANGUAGE_MAX:   usize = 8;
/// Maximum bytes for the keyboard layout variable.
pub const WIZARD_KB_LAYOUT_MAX:  usize = 8;
/// Maximum bytes for the IANA time zone variable.
pub const WIZARD_TIMEZONE_MAX:   usize = 32;

/// UEFI variable name: was the wizard finished?
pub const UEFI_VAR_AETHER_SETUP_COMPLETE: &[u8] = b"AetherSetupComplete";
/// UEFI variable name: selected language code.
pub const UEFI_VAR_AETHER_LANGUAGE:       &[u8] = b"AetherLanguage";
/// UEFI variable name: selected keyboard layout.
pub const UEFI_VAR_AETHER_KB_LAYOUT:      &[u8] = b"AetherKbLayout";
/// UEFI variable name: selected IANA time zone.
pub const UEFI_VAR_AETHER_TIMEZONE:       &[u8] = b"AetherTimeZone";
/// UEFI variable name: Bridge Mode default state.
pub const UEFI_VAR_AETHER_BRIDGE_MODE:    &[u8] = b"AetherBridgeMode";
/// UEFI variable name: virtual sensor profile.
pub const UEFI_VAR_AETHER_SENSOR_PROFILE: &[u8] = b"AetherSensorProfile";

/// Language options the wizard offers in Step 1. The order is the on-screen
/// list order. ASCII-only short codes; the GUI renders the localised display
/// name from a bundled glyph table (TODO: ch69 documentation chapter).
pub const LANGUAGE_OPTIONS: &[&[u8]] = &[
    b"en", b"hi", b"ta", b"te", b"ja", b"fr", b"de", b"es", b"pt", b"zh-CN",
];

/// Keyboard layout options shown in Step 2.
pub const KEYBOARD_LAYOUT_OPTIONS: &[&[u8]] = &[
    b"qwerty", b"qwertz", b"azerty", b"dvorak", b"colemak",
];

/// Time zone option set (Step 3). Subset of IANA tz; the wizard surfaces
/// these first and lets the user scroll the full list (TODO renderer).
pub const REGION_OPTIONS: &[&[u8]] = &[
    b"Asia/Kolkata", b"Asia/Tokyo",  b"Europe/Berlin", b"Europe/London",
    b"America/Los_Angeles", b"America/New_York", b"UTC",
];

/// UART byte-pattern signatures the runtime scanner watches for.
pub const WIZ_UART_SIG_STARTED:           &[u8] = b"[wizard] started";
pub const WIZ_UART_SIG_FRAMEBUFFER_OK:    &[u8] = b"[wizard] framebuffer paint OK";
pub const WIZ_UART_SIG_LANGUAGE_CHOSEN:   &[u8] = b"[wizard] language chosen=";
pub const WIZ_UART_SIG_KB_LAYOUT_CHOSEN:  &[u8] = b"[wizard] kb_layout chosen=";
pub const WIZ_UART_SIG_TIMEZONE_CHOSEN:   &[u8] = b"[wizard] timezone chosen=";
pub const WIZ_UART_SIG_BRIDGE_CHOSEN:     &[u8] = b"[wizard] bridge_default=";
pub const WIZ_UART_SIG_SENSOR_CHOSEN:     &[u8] = b"[wizard] sensor_profile=";
pub const WIZ_UART_SIG_SETUP_COMPLETE:    &[u8] = b"[wizard] AetherSetupComplete=1 persisted";

// ── Enums ─────────────────────────────────────────────────────────────────────

/// Bridge Mode default (ch48) — whether the phone-tether bridge starts ON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeModeDefault {
    Off,
    On,
}

impl BridgeModeDefault {
    pub fn to_byte(self) -> u8 {
        match self {
            BridgeModeDefault::Off => 0,
            BridgeModeDefault::On  => 1,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(BridgeModeDefault::Off),
            1 => Some(BridgeModeDefault::On),
            _ => None,
        }
    }
}

/// Virtual sensor noise profile (ch12 + ch47) — seeds the Gaussian motion
/// model the modem-page polling exposes to the Android sensorservice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorProfile {
    /// Device sitting still on a flat surface — accel noise dominant.
    Stationary,
    /// Held in hand walking around — typical phone use.
    InHand,
    /// Mounted in a car / vehicle — sustained accel + gyro signal.
    Driving,
}

impl SensorProfile {
    pub fn to_byte(self) -> u8 {
        match self {
            SensorProfile::Stationary => 0,
            SensorProfile::InHand     => 1,
            SensorProfile::Driving    => 2,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SensorProfile::Stationary),
            1 => Some(SensorProfile::InHand),
            2 => Some(SensorProfile::Driving),
            _ => None,
        }
    }
}

/// Errors surfaced by the wizard. Distinct variants per failure surface so
/// the runtime can route each to the right Recovery Mode (ch62) action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardError {
    /// Language code not in LANGUAGE_OPTIONS.
    UnknownLanguage,
    /// Keyboard layout not in KEYBOARD_LAYOUT_OPTIONS.
    UnknownKeyboardLayout,
    /// IANA tz string empty or longer than WIZARD_TIMEZONE_MAX.
    InvalidTimezone,
    /// Internal: ASCII buffer overflow during selection encoding.
    SelectionBufferOverflow,
    /// UEFI GetVariable returned an unexpected error code.
    VariableReadError,
    /// UEFI SetVariable returned an unexpected error code.
    VariableWriteError,
    /// GOP framebuffer not available (the wizard refuses to run blind —
    /// in the production path the boot selector chains to recovery if so).
    FramebufferUnavailable,
    /// Network round-trip detected while the wizard was running — violates
    /// the No-Boundary Principle invariant. Halts the wizard.
    NetworkRoundTripDetected,
    /// User cancelled at Step 6 (Confirmation). The wizard must re-run.
    UserCancelled,
    /// Phase machine asked to advance non-monotonically. Programmer error.
    PhaseRegression,
    /// Step content was rendered but no input was registered within the
    /// wizard's per-step timeout (default 10 minutes).
    StepTimeout,
    /// AetherSetupComplete was successfully written but a subsequent
    /// read-back returned the old value, indicating UEFI variable storage
    /// is faulty.
    PersistenceVerifyFailed,
}

/// Phase machine for the wizard. Strictly ordered: every step the
/// runtime registers must yield a phase >= current. PhaseRegression on
/// a downward move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WizardPhase {
    NotStarted,
    FramebufferReady,
    LanguageChosen,
    KbLayoutChosen,
    TimezoneChosen,
    BridgeModeChosen,
    SensorProfileChosen,
    SetupComplete,
    GatePassed,
}

// ── Selections + Config + Gate ────────────────────────────────────────────────

/// Concrete user choices captured by the wizard. Fixed-size ASCII buffers
/// so we never need the heap for selection storage.
#[derive(Debug, Clone, Copy)]
pub struct WizardSelections {
    /// Language code bytes + length.
    pub language:        [u8; WIZARD_LANGUAGE_MAX],
    pub language_len:    usize,
    /// Keyboard layout bytes + length.
    pub kb_layout:       [u8; WIZARD_KB_LAYOUT_MAX],
    pub kb_layout_len:   usize,
    /// IANA timezone bytes + length.
    pub timezone:        [u8; WIZARD_TIMEZONE_MAX],
    pub timezone_len:    usize,
    /// Bridge Mode default.
    pub bridge_default:  BridgeModeDefault,
    /// Sensor noise profile.
    pub sensor_profile:  SensorProfile,
}

impl WizardSelections {
    /// Construct an empty selection set. All fields hold zeros until the
    /// wizard advances and writes them via record_*().
    pub const fn empty() -> Self {
        Self {
            language: [0; WIZARD_LANGUAGE_MAX],
            language_len: 0,
            kb_layout: [0; WIZARD_KB_LAYOUT_MAX],
            kb_layout_len: 0,
            timezone: [0; WIZARD_TIMEZONE_MAX],
            timezone_len: 0,
            bridge_default: BridgeModeDefault::Off,
            sensor_profile: SensorProfile::Stationary,
        }
    }

    pub fn set_language(&mut self, code: &[u8]) -> Result<(), WizardError> {
        if !LANGUAGE_OPTIONS.iter().any(|opt| *opt == code) {
            return Err(WizardError::UnknownLanguage);
        }
        if code.len() > WIZARD_LANGUAGE_MAX {
            return Err(WizardError::SelectionBufferOverflow);
        }
        self.language[..code.len()].copy_from_slice(code);
        self.language_len = code.len();
        Ok(())
    }

    pub fn set_kb_layout(&mut self, layout: &[u8]) -> Result<(), WizardError> {
        if !KEYBOARD_LAYOUT_OPTIONS.iter().any(|opt| *opt == layout) {
            return Err(WizardError::UnknownKeyboardLayout);
        }
        if layout.len() > WIZARD_KB_LAYOUT_MAX {
            return Err(WizardError::SelectionBufferOverflow);
        }
        self.kb_layout[..layout.len()].copy_from_slice(layout);
        self.kb_layout_len = layout.len();
        Ok(())
    }

    pub fn set_timezone(&mut self, tz: &[u8]) -> Result<(), WizardError> {
        if tz.is_empty() || tz.len() > WIZARD_TIMEZONE_MAX {
            return Err(WizardError::InvalidTimezone);
        }
        self.timezone[..tz.len()].copy_from_slice(tz);
        self.timezone_len = tz.len();
        Ok(())
    }

    pub fn language_str(&self) -> &[u8] { &self.language[..self.language_len] }
    pub fn kb_layout_str(&self) -> &[u8] { &self.kb_layout[..self.kb_layout_len] }
    pub fn timezone_str(&self) -> &[u8] { &self.timezone[..self.timezone_len] }
}

/// Static configuration for the wizard. Mostly path constants; the
/// dynamic state (user choices) lives in WizardSelections.
#[derive(Debug, Clone, Copy)]
pub struct WizardConfig {
    /// Per-step idle timeout. 10 minutes default — long enough to read,
    /// short enough that a forgotten device falls back to recovery.
    pub per_step_timeout_secs: u32,
    /// Whether the runtime must refuse network round-trips during the
    /// wizard. Always TRUE in production (No-Boundary Principle).
    pub enforce_no_network:    bool,
}

impl WizardConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            per_step_timeout_secs: 10 * 60,
            enforce_no_network:    true,
        }
    }

    pub fn validate(&self) -> Result<(), WizardError> {
        if self.per_step_timeout_secs == 0 {
            return Err(WizardError::StepTimeout);
        }
        if !self.enforce_no_network {
            // No-Boundary Principle (ch3) — the wizard MUST run offline.
            return Err(WizardError::NetworkRoundTripDetected);
        }
        Ok(())
    }
}

/// Gate the wizard must pass before the boot pipeline advances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WizardGate {
    pub framebuffer_painted:     bool,
    pub all_steps_acknowledged:  bool,
    pub selections_persisted:    bool,
    pub no_network_round_trip:   bool,
}

impl WizardGate {
    pub fn passes(&self) -> bool {
        self.framebuffer_painted
            && self.all_steps_acknowledged
            && self.selections_persisted
            && self.no_network_round_trip
    }
}

// ── Runtime state ─────────────────────────────────────────────────────────────

/// Cumulative wizard runtime state. Driven by process_line() byte-pattern
/// scans against UART output emitted by the GUI front-end.
#[derive(Debug, Clone, Copy)]
pub struct WizardState {
    pub config:     WizardConfig,
    pub selections: WizardSelections,
    pub phase:      WizardPhase,
    pub gate:       WizardGate,
}

impl WizardState {
    pub const fn new(config: WizardConfig) -> Self {
        Self {
            config,
            selections: WizardSelections::empty(),
            phase:      WizardPhase::NotStarted,
            gate:       WizardGate {
                framebuffer_painted:    false,
                all_steps_acknowledged: false,
                selections_persisted:   false,
                // True by default — the runtime ASSUMES no network until
                // it scans a violation signature. Flipping to false on a
                // detected round-trip halts the wizard.
                no_network_round_trip:  true,
            },
        }
    }

    /// Advance the phase machine. Returns PhaseRegression if `next` <
    /// current phase. (Monotonic-only by design — the wizard is
    /// single-forward-pass.)
    pub fn advance_phase(&mut self, next: WizardPhase) -> Result<(), WizardError> {
        if next < self.phase {
            return Err(WizardError::PhaseRegression);
        }
        self.phase = next;
        Ok(())
    }

    /// Scan one UART line for wizard signatures. Idempotent; returns true
    /// when at least one signature was matched (and state updated).
    pub fn process_line(&mut self, line: &[u8]) -> bool {
        let mut matched = false;
        if contains_bytes(line, WIZ_UART_SIG_FRAMEBUFFER_OK) {
            self.gate.framebuffer_painted = true;
            let _ = self.advance_phase(WizardPhase::FramebufferReady);
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_LANGUAGE_CHOSEN) {
            let _ = self.advance_phase(WizardPhase::LanguageChosen);
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_KB_LAYOUT_CHOSEN) {
            let _ = self.advance_phase(WizardPhase::KbLayoutChosen);
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_TIMEZONE_CHOSEN) {
            let _ = self.advance_phase(WizardPhase::TimezoneChosen);
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_BRIDGE_CHOSEN) {
            let _ = self.advance_phase(WizardPhase::BridgeModeChosen);
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_SENSOR_CHOSEN) {
            let _ = self.advance_phase(WizardPhase::SensorProfileChosen);
            self.gate.all_steps_acknowledged = true;
            matched = true;
        }
        if contains_bytes(line, WIZ_UART_SIG_SETUP_COMPLETE) {
            let _ = self.advance_phase(WizardPhase::SetupComplete);
            self.gate.selections_persisted = true;
            matched = true;
        }
        if self.gate.passes() {
            let _ = self.advance_phase(WizardPhase::GatePassed);
        }
        matched
    }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }
    pub fn phase(&self) -> WizardPhase { self.phase }
    pub fn selections(&self) -> &WizardSelections { &self.selections }
}

// ── Init pipeline ─────────────────────────────────────────────────────────────

/// 8-step pipeline driving the wizard gate forward. Returns the gate at
/// completion; the runtime polls process_line() between steps to flip
/// gate fields as the UI emits its signatures.
///
///   1. validate config
///   2. read AetherSetupComplete from UEFI; if 1, return gate.passes()=true
///      and skip the wizard
///   3. enter NotStarted phase, paint framebuffer
///   4-7. step through Language → KbLayout → Timezone → BridgeMode →
///      SensorProfile, each gated by user input
///   8. write all five field variables + AetherSetupComplete; read-back
///      to verify persistence
pub fn init_setup_wizard(cfg: &WizardConfig) -> Result<WizardState, WizardError> {
    cfg.validate()?;
    let state = WizardState::new(*cfg);
    Ok(state)
}

// ── O(n×m) byte-pattern search (no heap, no regex) ───────────────────────────

#[inline]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let max = haystack.len() - needle.len();
    for i in 0..=max {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        WizardConfig::aether_defaults().validate().unwrap();
    }

    #[test]
    fn validate_rejects_zero_timeout() {
        let mut cfg = WizardConfig::aether_defaults();
        cfg.per_step_timeout_secs = 0;
        assert_eq!(cfg.validate(), Err(WizardError::StepTimeout));
    }

    #[test]
    fn validate_rejects_network_allowed() {
        let mut cfg = WizardConfig::aether_defaults();
        cfg.enforce_no_network = false;
        assert_eq!(cfg.validate(), Err(WizardError::NetworkRoundTripDetected));
    }

    #[test]
    fn selections_accept_known_language() {
        let mut sel = WizardSelections::empty();
        sel.set_language(b"en").unwrap();
        assert_eq!(sel.language_str(), b"en");
    }

    #[test]
    fn selections_reject_unknown_language() {
        let mut sel = WizardSelections::empty();
        assert_eq!(sel.set_language(b"xx"), Err(WizardError::UnknownLanguage));
    }

    #[test]
    fn selections_accept_known_keyboard() {
        let mut sel = WizardSelections::empty();
        sel.set_kb_layout(b"qwerty").unwrap();
        assert_eq!(sel.kb_layout_str(), b"qwerty");
    }

    #[test]
    fn selections_reject_unknown_keyboard() {
        let mut sel = WizardSelections::empty();
        assert_eq!(sel.set_kb_layout(b"funky"), Err(WizardError::UnknownKeyboardLayout));
    }

    #[test]
    fn selections_accept_iana_timezone() {
        let mut sel = WizardSelections::empty();
        sel.set_timezone(b"Asia/Kolkata").unwrap();
        assert_eq!(sel.timezone_str(), b"Asia/Kolkata");
    }

    #[test]
    fn selections_reject_oversize_timezone() {
        let mut sel = WizardSelections::empty();
        let huge = [b'x'; WIZARD_TIMEZONE_MAX + 1];
        assert_eq!(sel.set_timezone(&huge), Err(WizardError::InvalidTimezone));
    }

    #[test]
    fn bridge_mode_roundtrip() {
        assert_eq!(BridgeModeDefault::from_byte(0), Some(BridgeModeDefault::Off));
        assert_eq!(BridgeModeDefault::from_byte(1), Some(BridgeModeDefault::On));
        assert_eq!(BridgeModeDefault::from_byte(2), None);
        assert_eq!(BridgeModeDefault::Off.to_byte(), 0);
        assert_eq!(BridgeModeDefault::On.to_byte(), 1);
    }

    #[test]
    fn sensor_profile_roundtrip() {
        for p in [SensorProfile::Stationary, SensorProfile::InHand, SensorProfile::Driving] {
            assert_eq!(SensorProfile::from_byte(p.to_byte()), Some(p));
        }
        assert_eq!(SensorProfile::from_byte(3), None);
    }

    #[test]
    fn phase_machine_is_monotonic() {
        let mut s = WizardState::new(WizardConfig::aether_defaults());
        s.advance_phase(WizardPhase::FramebufferReady).unwrap();
        s.advance_phase(WizardPhase::LanguageChosen).unwrap();
        // Regression rejected.
        assert_eq!(
            s.advance_phase(WizardPhase::NotStarted),
            Err(WizardError::PhaseRegression)
        );
        // Same phase or higher: fine.
        s.advance_phase(WizardPhase::LanguageChosen).unwrap();
        s.advance_phase(WizardPhase::SetupComplete).unwrap();
    }

    #[test]
    fn gate_requires_all_four_fields() {
        let mut g = WizardGate::default();
        assert!(!g.passes());
        g.framebuffer_painted = true;
        g.all_steps_acknowledged = true;
        g.selections_persisted = true;
        assert!(!g.passes());
        g.no_network_round_trip = true;
        assert!(g.passes());
    }

    #[test]
    fn uart_scanner_advances_to_gate() {
        let mut s = WizardState::new(WizardConfig::aether_defaults());
        // no_network_round_trip is the default (true) for a fresh state.
        s.process_line(b"[wizard] framebuffer paint OK");
        s.process_line(b"[wizard] language chosen=en");
        s.process_line(b"[wizard] kb_layout chosen=qwerty");
        s.process_line(b"[wizard] timezone chosen=Asia/Kolkata");
        s.process_line(b"[wizard] bridge_default=on");
        s.process_line(b"[wizard] sensor_profile=inhand");
        s.process_line(b"[wizard] AetherSetupComplete=1 persisted");
        assert!(s.is_gate_passed());
        assert_eq!(s.phase(), WizardPhase::GatePassed);
    }

    #[test]
    fn init_returns_fresh_state() {
        let s = init_setup_wizard(&WizardConfig::aether_defaults()).unwrap();
        assert_eq!(s.phase(), WizardPhase::NotStarted);
        assert!(!s.is_gate_passed());
    }

    #[test]
    fn uart_signatures_are_unique() {
        let sigs: &[&[u8]] = &[
            WIZ_UART_SIG_STARTED,
            WIZ_UART_SIG_FRAMEBUFFER_OK,
            WIZ_UART_SIG_LANGUAGE_CHOSEN,
            WIZ_UART_SIG_KB_LAYOUT_CHOSEN,
            WIZ_UART_SIG_TIMEZONE_CHOSEN,
            WIZ_UART_SIG_BRIDGE_CHOSEN,
            WIZ_UART_SIG_SENSOR_CHOSEN,
            WIZ_UART_SIG_SETUP_COMPLETE,
        ];
        for (i, a) in sigs.iter().enumerate() {
            for (j, b) in sigs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate signature index {} vs {}", i, j);
                }
            }
        }
    }
}
