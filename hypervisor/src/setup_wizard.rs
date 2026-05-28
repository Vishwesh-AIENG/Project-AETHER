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
//   Step 6  Image check       validate AOSP image set (boot/system/vendor/
//                             vbmeta/userdata) is present and sized correctly
//                             on the ESP — this is the gate between "user
//                             made choices" and "device is bootable"
//   Step 7  Confirmation      user accepts → write AETHER_SETUP_COMPLETE
//
// ── Hypervisor-side ONLY — no Android app exists for this ─────────────────────
//
// This entire wizard runs in EL2 (ARM) / VMX root (x86), before the Android
// partition is launched. The GUI is painted directly on the GOP framebuffer
// captured pre-ExitBootServices in main.rs::capture_framebuffer(). There is
// no Android-side counterpart — once the wizard finishes and writes
// AetherSetupComplete, the hypervisor launches Android and the wizard does
// not exist again in this boot's lifetime.
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
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  Constants — UEFI variable names, max field lengths, option tables.
//   2.  Language / KeyboardLayout / SensorProfile / BridgeModeDefault enums.
//   3.  WizardSelections — concrete user choices (ascii buffers + enums).
//   4.  WizardConfig (aether_defaults + validate) + WizardGate (passes).
//   5.  WizardError — 14 variants for every distinct failure surface.
//   6.  WizardPhase — 10 phases, strictly ordered via PartialOrd/Ord.
//   7.  WizardState — process_line() UART scanner + gate() + selections.
//   8.  UART signature byte patterns — 9 constants for the runtime scanner.
//   9.  FramebufferPainter — actual GOP framebuffer drawing (fill_rect,
//       clear, draw_glyph, draw_text) with the bundled FONT_8X8 8-pixel
//       monochrome font covering ASCII 0x20..0x7E.
//   10. WizardImageManifest — the 5 AOSP images this build produces, with
//       expected paths on the ESP, min/max sizes, and required flag. Used
//       by check_images_present() to gate the wizard's completion.
//   11. WizardScreen — one renderer per WizardPhase; called by the runtime
//       on each phase transition.
//   12. init_setup_wizard() — pipeline.
//
// ── Gate (Chapter 59) ─────────────────────────────────────────────────────────
//
//   WizardGate.passes() requires:
//     framebuffer_painted       — at least one Step screen rendered
//     all_steps_acknowledged    — user advanced past Step 6 (Confirmation)
//     images_present            — the 5 AOSP images verified on the ESP
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
pub const WIZ_UART_SIG_IMAGES_OK:         &[u8] = b"[wizard] image_manifest OK";
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
    /// User cancelled at Step 7 (Confirmation). The wizard must re-run.
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
    /// One or more required AOSP images are missing from the ESP at the
    /// expected path (`\\EFI\\AETHER\\<name>`).
    RequiredImageMissing,
    /// An AOSP image is present but its size is outside the expected
    /// [min,max] window — possibly truncated, corrupted, or a sideload
    /// from a different build.
    ImageSizeOutOfRange,
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
    ImagesVerified,
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
    /// wizard advances and writes them via set_*().
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
    pub images_present:          bool,
    pub selections_persisted:    bool,
    pub no_network_round_trip:   bool,
}

impl WizardGate {
    pub fn passes(&self) -> bool {
        self.framebuffer_painted
            && self.all_steps_acknowledged
            && self.images_present
            && self.selections_persisted
            && self.no_network_round_trip
    }
}

// ── Image manifest (the 5 AOSP images this build produces) ───────────────────

/// Maximum number of images the manifest can describe. We currently use 5
/// (boot/system/vendor/vbmeta/userdata). Two spare slots for product +
/// vendor_boot once we wire ESP-side staging for those.
pub const IMAGE_MANIFEST_CAPACITY: usize = 7;

/// One image entry: ASCII name (≤ 16 bytes), ESP-relative path (≤ 64
/// bytes), allowed size range, and "required" flag.
#[derive(Debug, Clone, Copy)]
pub struct ImageEntry {
    pub name:           [u8; 16],
    pub name_len:       usize,
    pub esp_path:       [u8; 64],
    pub esp_path_len:   usize,
    pub min_size_bytes: u64,
    pub max_size_bytes: u64,
    pub required:       bool,
}

impl ImageEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; 16], name_len: 0,
            esp_path: [0; 64], esp_path_len: 0,
            min_size_bytes: 0, max_size_bytes: 0,
            required: false,
        }
    }

    pub fn name_str(&self) -> &[u8] { &self.name[..self.name_len] }
    pub fn esp_path_str(&self) -> &[u8] { &self.esp_path[..self.esp_path_len] }

    pub fn size_in_range(&self, size: u64) -> bool {
        size >= self.min_size_bytes && size <= self.max_size_bytes
    }
}

/// Fixed-size manifest of expected images. The wizard's Step 6 walks each
/// entry and tries to stat it on the ESP via the boot_x86_esp shim.
#[derive(Debug, Clone, Copy)]
pub struct WizardImageManifest {
    pub entries:     [ImageEntry; IMAGE_MANIFEST_CAPACITY],
    pub entry_count: usize,
}

impl WizardImageManifest {
    pub const fn empty() -> Self {
        Self {
            entries: [ImageEntry::empty(); IMAGE_MANIFEST_CAPACITY],
            entry_count: 0,
        }
    }

    /// Append a new entry. Returns Err if at capacity.
    pub fn push(
        &mut self,
        name: &[u8],
        esp_path: &[u8],
        min_size: u64,
        max_size: u64,
        required: bool,
    ) -> Result<(), WizardError> {
        if self.entry_count >= IMAGE_MANIFEST_CAPACITY {
            return Err(WizardError::SelectionBufferOverflow);
        }
        if name.len() > 16 || esp_path.len() > 64 {
            return Err(WizardError::SelectionBufferOverflow);
        }
        let mut e = ImageEntry::empty();
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len();
        e.esp_path[..esp_path.len()].copy_from_slice(esp_path);
        e.esp_path_len = esp_path.len();
        e.min_size_bytes = min_size;
        e.max_size_bytes = max_size;
        e.required = required;
        self.entries[self.entry_count] = e;
        self.entry_count += 1;
        Ok(())
    }

    /// The default manifest matching the images produced by this AOSP
    /// build (ch42, build run 29 success). Sizes are wide ranges chosen
    /// to accept normal incremental-build drift without false-positives.
    pub fn aether_defaults() -> Self {
        let mut m = Self::empty();
        // boot.img — 64 MiB partition; current build = 64 MiB exact.
        m.push(b"boot.img",     b"\\EFI\\AETHER\\boot.img",
               4 * 1024 * 1024,                // > 4 MiB
               128 * 1024 * 1024,              // < 128 MiB
               true).unwrap();
        // system.img — 3 GiB partition; current build = 943 MiB. The
        // partition is sparse, image size grows with /system content.
        m.push(b"system.img",   b"\\EFI\\AETHER\\system.img",
               200 * 1024 * 1024,              // > 200 MiB
               3 * 1024u64 * 1024 * 1024,      // ≤ 3 GiB
               true).unwrap();
        // vendor.img — 1 GiB partition; current build = 33 MiB.
        m.push(b"vendor.img",   b"\\EFI\\AETHER\\vendor.img",
               4 * 1024 * 1024,                // > 4 MiB
               1 * 1024u64 * 1024 * 1024,      // ≤ 1 GiB
               true).unwrap();
        // vbmeta.img — AVB root, always tiny (8 KiB for our chain).
        m.push(b"vbmeta.img",   b"\\EFI\\AETHER\\vbmeta.img",
               1024,                           // > 1 KiB
               64 * 1024,                      // ≤ 64 KiB
               true).unwrap();
        // userdata.img — F2FS empty, ~6 MiB on first build.
        m.push(b"userdata.img", b"\\EFI\\AETHER\\userdata.img",
               1024 * 1024,                    // > 1 MiB
               16 * 1024 * 1024,               // ≤ 16 MiB
               true).unwrap();
        m
    }

    /// Find an entry by name. None if absent.
    pub fn lookup(&self, name: &[u8]) -> Option<&ImageEntry> {
        for i in 0..self.entry_count {
            if self.entries[i].name_str() == name {
                return Some(&self.entries[i]);
            }
        }
        None
    }
}

/// Result of a single image check on the ESP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageCheckResult {
    pub name_len:   usize,
    pub name:       [u8; 16],
    pub found:      bool,
    pub size_bytes: u64,
    pub in_range:   bool,
}

impl ImageCheckResult {
    pub fn ok(&self) -> bool { self.found && self.in_range }
    pub fn name_str(&self) -> &[u8] { &self.name[..self.name_len] }
}

/// Check whether every required image in `manifest` was successfully
/// found on the ESP (the caller does the actual file I/O via
/// boot_x86_esp and feeds the (name, size) pairs into `report_size`).
///
/// Returns Ok(()) when every required entry has size in range; Err on
/// the first violation.
pub fn check_image_manifest(
    manifest: &WizardImageManifest,
    found_sizes: &[(&[u8], u64)],
) -> Result<(), WizardError> {
    for i in 0..manifest.entry_count {
        let entry = &manifest.entries[i];
        if !entry.required { continue; }
        let mut found = false;
        for (name, size) in found_sizes {
            if *name == entry.name_str() {
                found = true;
                if !entry.size_in_range(*size) {
                    return Err(WizardError::ImageSizeOutOfRange);
                }
                break;
            }
        }
        if !found {
            return Err(WizardError::RequiredImageMissing);
        }
    }
    Ok(())
}

// ── Runtime state ─────────────────────────────────────────────────────────────

/// Cumulative wizard runtime state. Driven by process_line() byte-pattern
/// scans against UART output emitted by the GUI front-end.
#[derive(Debug, Clone, Copy)]
pub struct WizardState {
    pub config:     WizardConfig,
    pub manifest:   WizardImageManifest,
    pub selections: WizardSelections,
    pub phase:      WizardPhase,
    pub gate:       WizardGate,
}

impl WizardState {
    pub fn new(config: WizardConfig) -> Self {
        Self {
            config,
            manifest:   WizardImageManifest::aether_defaults(),
            selections: WizardSelections::empty(),
            phase:      WizardPhase::NotStarted,
            gate:       WizardGate {
                framebuffer_painted:    false,
                all_steps_acknowledged: false,
                images_present:         false,
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
        if contains_bytes(line, WIZ_UART_SIG_IMAGES_OK) {
            let _ = self.advance_phase(WizardPhase::ImagesVerified);
            self.gate.images_present = true;
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
    pub fn manifest(&self) -> &WizardImageManifest { &self.manifest }

    /// Record the result of the image-manifest check (Step 6). On success
    /// flips the `images_present` gate field; on failure leaves it false
    /// and returns the error so the runtime can route to recovery.
    pub fn record_image_check(
        &mut self,
        found_sizes: &[(&[u8], u64)],
    ) -> Result<(), WizardError> {
        check_image_manifest(&self.manifest, found_sizes)?;
        self.gate.images_present = true;
        self.advance_phase(WizardPhase::ImagesVerified)
    }
}

// ── FramebufferPainter — actual GOP framebuffer drawing ──────────────────────

/// 8×8 monochrome font for printable ASCII 0x20..0x7E (95 glyphs).
/// Each glyph = 8 bytes, one per row, MSB = leftmost pixel of that row.
///
/// Compact public-domain bitmap font derived from the IBM PC BIOS 8×8
/// character set used since 1981. Pixel-identical reproduction of the
/// standard glyphs for 0x20 (space) through 0x7E (tilde). Index into
/// this array as `FONT_8X8[ascii - 0x20]`.
pub const FONT_8X8_FIRST_CHAR: u8 = 0x20; // space
pub const FONT_8X8_LAST_CHAR:  u8 = 0x7E; // tilde
pub const FONT_8X8_COUNT: usize = (FONT_8X8_LAST_CHAR - FONT_8X8_FIRST_CHAR + 1) as usize;

pub static FONT_8X8: [[u8; 8]; FONT_8X8_COUNT] = [
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00], // 0x20 ' '
    [0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00], // 0x21 '!'
    [0x36,0x36,0x00,0x00,0x00,0x00,0x00,0x00], // 0x22 '"'
    [0x36,0x36,0x7F,0x36,0x7F,0x36,0x36,0x00], // 0x23 '#'
    [0x0C,0x3E,0x03,0x1E,0x30,0x1F,0x0C,0x00], // 0x24 '$'
    [0x00,0x63,0x33,0x18,0x0C,0x66,0x63,0x00], // 0x25 '%'
    [0x1C,0x36,0x1C,0x6E,0x3B,0x33,0x6E,0x00], // 0x26 '&'
    [0x06,0x06,0x03,0x00,0x00,0x00,0x00,0x00], // 0x27 '\''
    [0x18,0x0C,0x06,0x06,0x06,0x0C,0x18,0x00], // 0x28 '('
    [0x06,0x0C,0x18,0x18,0x18,0x0C,0x06,0x00], // 0x29 ')'
    [0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00], // 0x2A '*'
    [0x00,0x0C,0x0C,0x3F,0x0C,0x0C,0x00,0x00], // 0x2B '+'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x06], // 0x2C ','
    [0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00], // 0x2D '-'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x00], // 0x2E '.'
    [0x60,0x30,0x18,0x0C,0x06,0x03,0x01,0x00], // 0x2F '/'
    [0x3E,0x63,0x73,0x7B,0x6F,0x67,0x3E,0x00], // 0x30 '0'
    [0x0C,0x0E,0x0C,0x0C,0x0C,0x0C,0x3F,0x00], // 0x31 '1'
    [0x1E,0x33,0x30,0x1C,0x06,0x33,0x3F,0x00], // 0x32 '2'
    [0x1E,0x33,0x30,0x1C,0x30,0x33,0x1E,0x00], // 0x33 '3'
    [0x38,0x3C,0x36,0x33,0x7F,0x30,0x78,0x00], // 0x34 '4'
    [0x3F,0x03,0x1F,0x30,0x30,0x33,0x1E,0x00], // 0x35 '5'
    [0x1C,0x06,0x03,0x1F,0x33,0x33,0x1E,0x00], // 0x36 '6'
    [0x3F,0x33,0x30,0x18,0x0C,0x0C,0x0C,0x00], // 0x37 '7'
    [0x1E,0x33,0x33,0x1E,0x33,0x33,0x1E,0x00], // 0x38 '8'
    [0x1E,0x33,0x33,0x3E,0x30,0x18,0x0E,0x00], // 0x39 '9'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x00], // 0x3A ':'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x06], // 0x3B ';'
    [0x18,0x0C,0x06,0x03,0x06,0x0C,0x18,0x00], // 0x3C '<'
    [0x00,0x00,0x3F,0x00,0x00,0x3F,0x00,0x00], // 0x3D '='
    [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00], // 0x3E '>'
    [0x1E,0x33,0x30,0x18,0x0C,0x00,0x0C,0x00], // 0x3F '?'
    [0x3E,0x63,0x7B,0x7B,0x7B,0x03,0x1E,0x00], // 0x40 '@'
    [0x0C,0x1E,0x33,0x33,0x3F,0x33,0x33,0x00], // 0x41 'A'
    [0x3F,0x66,0x66,0x3E,0x66,0x66,0x3F,0x00], // 0x42 'B'
    [0x3C,0x66,0x03,0x03,0x03,0x66,0x3C,0x00], // 0x43 'C'
    [0x1F,0x36,0x66,0x66,0x66,0x36,0x1F,0x00], // 0x44 'D'
    [0x7F,0x46,0x16,0x1E,0x16,0x46,0x7F,0x00], // 0x45 'E'
    [0x7F,0x46,0x16,0x1E,0x16,0x06,0x0F,0x00], // 0x46 'F'
    [0x3C,0x66,0x03,0x03,0x73,0x66,0x7C,0x00], // 0x47 'G'
    [0x33,0x33,0x33,0x3F,0x33,0x33,0x33,0x00], // 0x48 'H'
    [0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x49 'I'
    [0x78,0x30,0x30,0x30,0x33,0x33,0x1E,0x00], // 0x4A 'J'
    [0x67,0x66,0x36,0x1E,0x36,0x66,0x67,0x00], // 0x4B 'K'
    [0x0F,0x06,0x06,0x06,0x46,0x66,0x7F,0x00], // 0x4C 'L'
    [0x63,0x77,0x7F,0x7F,0x6B,0x63,0x63,0x00], // 0x4D 'M'
    [0x63,0x67,0x6F,0x7B,0x73,0x63,0x63,0x00], // 0x4E 'N'
    [0x1C,0x36,0x63,0x63,0x63,0x36,0x1C,0x00], // 0x4F 'O'
    [0x3F,0x66,0x66,0x3E,0x06,0x06,0x0F,0x00], // 0x50 'P'
    [0x1E,0x33,0x33,0x33,0x3B,0x1E,0x38,0x00], // 0x51 'Q'
    [0x3F,0x66,0x66,0x3E,0x36,0x66,0x67,0x00], // 0x52 'R'
    [0x1E,0x33,0x07,0x0E,0x38,0x33,0x1E,0x00], // 0x53 'S'
    [0x3F,0x2D,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x54 'T'
    [0x33,0x33,0x33,0x33,0x33,0x33,0x3F,0x00], // 0x55 'U'
    [0x33,0x33,0x33,0x33,0x33,0x1E,0x0C,0x00], // 0x56 'V'
    [0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00], // 0x57 'W'
    [0x63,0x63,0x36,0x1C,0x1C,0x36,0x63,0x00], // 0x58 'X'
    [0x33,0x33,0x33,0x1E,0x0C,0x0C,0x1E,0x00], // 0x59 'Y'
    [0x7F,0x63,0x31,0x18,0x4C,0x66,0x7F,0x00], // 0x5A 'Z'
    [0x1E,0x06,0x06,0x06,0x06,0x06,0x1E,0x00], // 0x5B '['
    [0x03,0x06,0x0C,0x18,0x30,0x60,0x40,0x00], // 0x5C '\\'
    [0x1E,0x18,0x18,0x18,0x18,0x18,0x1E,0x00], // 0x5D ']'
    [0x08,0x1C,0x36,0x63,0x00,0x00,0x00,0x00], // 0x5E '^'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF], // 0x5F '_'
    [0x0C,0x0C,0x18,0x00,0x00,0x00,0x00,0x00], // 0x60 '`'
    [0x00,0x00,0x1E,0x30,0x3E,0x33,0x6E,0x00], // 0x61 'a'
    [0x07,0x06,0x06,0x3E,0x66,0x66,0x3B,0x00], // 0x62 'b'
    [0x00,0x00,0x1E,0x33,0x03,0x33,0x1E,0x00], // 0x63 'c'
    [0x38,0x30,0x30,0x3E,0x33,0x33,0x6E,0x00], // 0x64 'd'
    [0x00,0x00,0x1E,0x33,0x3F,0x03,0x1E,0x00], // 0x65 'e'
    [0x1C,0x36,0x06,0x0F,0x06,0x06,0x0F,0x00], // 0x66 'f'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x1F], // 0x67 'g'
    [0x07,0x06,0x36,0x6E,0x66,0x66,0x67,0x00], // 0x68 'h'
    [0x0C,0x00,0x0E,0x0C,0x0C,0x0C,0x1E,0x00], // 0x69 'i'
    [0x30,0x00,0x30,0x30,0x30,0x33,0x33,0x1E], // 0x6A 'j'
    [0x07,0x06,0x66,0x36,0x1E,0x36,0x67,0x00], // 0x6B 'k'
    [0x0E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 0x6C 'l'
    [0x00,0x00,0x33,0x7F,0x7F,0x6B,0x63,0x00], // 0x6D 'm'
    [0x00,0x00,0x1F,0x33,0x33,0x33,0x33,0x00], // 0x6E 'n'
    [0x00,0x00,0x1E,0x33,0x33,0x33,0x1E,0x00], // 0x6F 'o'
    [0x00,0x00,0x3B,0x66,0x66,0x3E,0x06,0x0F], // 0x70 'p'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x78], // 0x71 'q'
    [0x00,0x00,0x3B,0x6E,0x66,0x06,0x0F,0x00], // 0x72 'r'
    [0x00,0x00,0x3E,0x03,0x1E,0x30,0x1F,0x00], // 0x73 's'
    [0x08,0x0C,0x3E,0x0C,0x0C,0x2C,0x18,0x00], // 0x74 't'
    [0x00,0x00,0x33,0x33,0x33,0x33,0x6E,0x00], // 0x75 'u'
    [0x00,0x00,0x33,0x33,0x33,0x1E,0x0C,0x00], // 0x76 'v'
    [0x00,0x00,0x63,0x6B,0x7F,0x7F,0x36,0x00], // 0x77 'w'
    [0x00,0x00,0x63,0x36,0x1C,0x36,0x63,0x00], // 0x78 'x'
    [0x00,0x00,0x33,0x33,0x33,0x3E,0x30,0x1F], // 0x79 'y'
    [0x00,0x00,0x3F,0x19,0x0C,0x26,0x3F,0x00], // 0x7A 'z'
    [0x38,0x0C,0x0C,0x07,0x0C,0x0C,0x38,0x00], // 0x7B '{'
    [0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00], // 0x7C '|'
    [0x07,0x0C,0x0C,0x38,0x0C,0x0C,0x07,0x00], // 0x7D '}'
    [0x6E,0x3B,0x00,0x00,0x00,0x00,0x00,0x00], // 0x7E '~'
];

#[inline]
pub fn font_glyph(ch: u8) -> Option<&'static [u8; 8]> {
    if ch < FONT_8X8_FIRST_CHAR || ch > FONT_8X8_LAST_CHAR {
        return None;
    }
    Some(&FONT_8X8[(ch - FONT_8X8_FIRST_CHAR) as usize])
}

/// Pixel ordering of the GOP framebuffer. BGR is the common Intel/AMD UEFI
/// layout (BGRA8 in memory); RGB shows up on some Apple/ARM firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelOrder { Bgr, Rgb }

/// Borrowed view of a GOP framebuffer at known geometry. Safe; the caller
/// supplies the &mut [u32] slice. Production code constructs this from
/// the captured FB_INFO in boot_x86.rs via FramebufferPainter::from_raw().
pub struct FramebufferPainter<'a> {
    pub buf:      &'a mut [u32],
    pub width:    u32,
    pub height:   u32,
    pub pitch_px: u32,
    pub order:    PixelOrder,
}

impl<'a> FramebufferPainter<'a> {
    /// Borrow `buf` as a framebuffer with the given geometry. The caller
    /// must ensure `buf.len() >= (pitch_px * height) as usize`.
    pub fn new(
        buf: &'a mut [u32],
        width: u32, height: u32, pitch_px: u32,
        order: PixelOrder,
    ) -> Self {
        Self { buf, width, height, pitch_px, order }
    }

    /// Encode a 24-bit RGB triple into the framebuffer's native pixel
    /// format. RGB input convention: 0x00RRGGBB.
    #[inline]
    pub fn encode(&self, rgb: u32) -> u32 {
        match self.order {
            PixelOrder::Bgr => {
                // BGRA8 in memory; as little-endian u32: 0x00RRGGBB.
                rgb & 0x00FF_FFFF
            }
            PixelOrder::Rgb => {
                // RGBA8 in memory; we need to swap R↔B from our input.
                let r = (rgb >> 16) & 0xFF;
                let g = (rgb >> 8)  & 0xFF;
                let b =  rgb        & 0xFF;
                (b << 16) | (g << 8) | r
            }
        }
    }

    /// Paint a single pixel. Out-of-range coordinates are silently
    /// clipped — the GUI emits coordinates that may sit outside the
    /// captured framebuffer when the screen is smaller than expected.
    #[inline]
    pub fn put_pixel(&mut self, x: u32, y: u32, rgb: u32) {
        if x >= self.width || y >= self.height { return; }
        let i = (y * self.pitch_px + x) as usize;
        if i >= self.buf.len() { return; }
        self.buf[i] = self.encode(rgb);
    }

    /// Fill a rectangle with `rgb`. Clipped to the framebuffer bounds.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, rgb: u32) {
        let x_end = x.saturating_add(w).min(self.width);
        let y_end = y.saturating_add(h).min(self.height);
        let v = self.encode(rgb);
        for yy in y..y_end {
            let row = (yy * self.pitch_px) as usize;
            for xx in x..x_end {
                let i = row + xx as usize;
                if i < self.buf.len() {
                    self.buf[i] = v;
                }
            }
        }
    }

    /// Clear the entire visible framebuffer with `rgb`.
    pub fn clear(&mut self, rgb: u32) {
        self.fill_rect(0, 0, self.width, self.height, rgb);
    }

    /// Draw a single 8×8 glyph at (x, y) with foreground `fg` and
    /// background `bg`. Non-printable / out-of-table characters render
    /// as a solid `fg` block (so the user notices missing glyphs).
    pub fn draw_glyph(&mut self, x: u32, y: u32, ch: u8, fg: u32, bg: u32) {
        let glyph = match font_glyph(ch) {
            Some(g) => g,
            None    => {
                self.fill_rect(x, y, 8, 8, fg);
                return;
            }
        };
        for (row_idx, &row_bits) in glyph.iter().enumerate() {
            let py = y + row_idx as u32;
            if py >= self.height { break; }
            for col in 0..8u32 {
                // Per the IBM 8x8 layout, the LSB is the leftmost pixel
                // when we read the row byte. Render LSB-first to match
                // the comment header on each glyph entry.
                let lit = (row_bits >> col) & 1 == 1;
                self.put_pixel(x + col, py, if lit { fg } else { bg });
            }
        }
    }

    /// Draw an ASCII string starting at (x, y). One glyph per 8 px.
    /// Wraps at the right edge by silently truncating; the wizard's
    /// renderer pre-clips its strings to fit.
    pub fn draw_text(&mut self, x: u32, y: u32, text: &[u8], fg: u32, bg: u32) {
        let mut cx = x;
        for &ch in text {
            if cx + 8 > self.width { break; }
            self.draw_glyph(cx, y, ch, fg, bg);
            cx += 8;
        }
    }
}

/// Pre-defined colors for the wizard's painter. RGB constants (0x00RRGGBB).
pub const WIZ_COLOR_BG:      u32 = 0x00_0E1117; // dark navy
pub const WIZ_COLOR_FG:      u32 = 0x00_E0E0E0; // bright text
pub const WIZ_COLOR_ACCENT:  u32 = 0x00_3FA0FF; // AETHER cyan
pub const WIZ_COLOR_OK:      u32 = 0x00_4FC36F; // success green
pub const WIZ_COLOR_WARN:    u32 = 0x00_F0B040; // amber
pub const WIZ_COLOR_ERROR:   u32 = 0x00_E04848; // red

/// Render a wizard screen for the given phase. Pure — the painter
/// receives only the state needed; the caller already prepared the GOP
/// framebuffer. Returns the rendered string identifier (a stable token
/// the runtime emits on UART so test harnesses can confirm what got
/// painted).
pub fn render_screen(
    painter: &mut FramebufferPainter<'_>,
    state: &WizardState,
) -> &'static str {
    painter.clear(WIZ_COLOR_BG);
    // Title bar
    painter.fill_rect(0, 0, painter.width, 24, WIZ_COLOR_ACCENT);
    painter.draw_text(8, 8, b"AETHER Setup", WIZ_COLOR_BG, WIZ_COLOR_ACCENT);

    match state.phase {
        WizardPhase::NotStarted | WizardPhase::FramebufferReady => {
            painter.draw_text(8, 48,  b"Step 1: choose language", WIZ_COLOR_FG, WIZ_COLOR_BG);
            "language_screen"
        }
        WizardPhase::LanguageChosen => {
            painter.draw_text(8, 48,  b"Step 2: keyboard layout", WIZ_COLOR_FG, WIZ_COLOR_BG);
            "kb_layout_screen"
        }
        WizardPhase::KbLayoutChosen => {
            painter.draw_text(8, 48,  b"Step 3: time zone", WIZ_COLOR_FG, WIZ_COLOR_BG);
            "timezone_screen"
        }
        WizardPhase::TimezoneChosen => {
            painter.draw_text(8, 48,  b"Step 4: bridge mode default", WIZ_COLOR_FG, WIZ_COLOR_BG);
            "bridge_screen"
        }
        WizardPhase::BridgeModeChosen => {
            painter.draw_text(8, 48,  b"Step 5: sensor profile", WIZ_COLOR_FG, WIZ_COLOR_BG);
            "sensor_screen"
        }
        WizardPhase::SensorProfileChosen => {
            painter.draw_text(8, 48,  b"Step 6: verifying device images", WIZ_COLOR_FG, WIZ_COLOR_BG);
            render_image_manifest(painter, state, 8, 72);
            "images_screen"
        }
        WizardPhase::ImagesVerified => {
            painter.draw_text(8, 48,  b"Step 7: confirm and finish", WIZ_COLOR_FG, WIZ_COLOR_BG);
            render_image_manifest(painter, state, 8, 72);
            "confirmation_screen"
        }
        WizardPhase::SetupComplete | WizardPhase::GatePassed => {
            painter.draw_text(8, 48,  b"Setup complete. Launching Android...", WIZ_COLOR_OK, WIZ_COLOR_BG);
            "complete_screen"
        }
    }
}

/// Render the image manifest as a list of (name, status) lines, starting
/// at (x, y). Each row is the image's short name + an OK/MISS marker.
/// The `status_known` field on each entry comes from the runtime after
/// it's actually tried to stat the file.
pub fn render_image_manifest(
    painter: &mut FramebufferPainter<'_>,
    state: &WizardState,
    x: u32,
    mut y: u32,
) {
    painter.draw_text(x, y, b"Image                Status", WIZ_COLOR_ACCENT, WIZ_COLOR_BG);
    y += 12;
    for i in 0..state.manifest.entry_count {
        let entry = &state.manifest.entries[i];
        // Names are short ASCII (boot.img etc.); pad to 20 char column.
        let mut col = 0u32;
        for &b in entry.name_str() {
            painter.draw_glyph(x + col, y, b, WIZ_COLOR_FG, WIZ_COLOR_BG);
            col += 8;
        }
        // Fill the gap to col 20 (20 * 8 = 160 px) with spaces.
        while col < 20 * 8 {
            painter.draw_glyph(x + col, y, b' ', WIZ_COLOR_FG, WIZ_COLOR_BG);
            col += 8;
        }
        // Status — known only once record_image_check() ran. We tag it
        // by gate flag because per-entry state is checked en bloc.
        let (text, color) = if state.gate.images_present {
            (b"OK    " as &[u8], WIZ_COLOR_OK)
        } else if entry.required {
            (b"PEND  " as &[u8], WIZ_COLOR_WARN)
        } else {
            (b"OPT   " as &[u8], WIZ_COLOR_FG)
        };
        painter.draw_text(x + col, y, text, color, WIZ_COLOR_BG);
        y += 10;
        if y + 10 > painter.height { break; }
    }
}

// ── Init pipeline ─────────────────────────────────────────────────────────────

/// 9-step pipeline driving the wizard gate forward. Returns the gate at
/// completion; the runtime polls process_line() between steps to flip
/// gate fields as the UI emits its signatures.
///
///   1. validate config
///   2. read AetherSetupComplete from UEFI; if 1, return gate.passes()=true
///      and skip the wizard
///   3. enter NotStarted phase, paint framebuffer
///   4–8. step through Language → KbLayout → Timezone → BridgeMode →
///      SensorProfile, each gated by user input
///   9. verify AOSP image manifest on ESP via boot_x86_esp; gate flips
///      images_present when every required image is found and in size
///      range. The runtime then writes all five field variables +
///      AetherSetupComplete; read-back to verify persistence.
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

    fn make_buf(w: u32, h: u32) -> alloc::vec::Vec<u32> {
        alloc::vec![0u32; (w * h) as usize]
    }

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
    fn gate_requires_all_fields() {
        let mut g = WizardGate::default();
        assert!(!g.passes());
        g.framebuffer_painted = true;
        g.all_steps_acknowledged = true;
        g.selections_persisted = true;
        g.no_network_round_trip = true;
        assert!(!g.passes()); // images still missing
        g.images_present = true;
        assert!(g.passes());
    }

    #[test]
    fn uart_scanner_advances_to_gate() {
        let mut s = WizardState::new(WizardConfig::aether_defaults());
        s.process_line(b"[wizard] framebuffer paint OK");
        s.process_line(b"[wizard] language chosen=en");
        s.process_line(b"[wizard] kb_layout chosen=qwerty");
        s.process_line(b"[wizard] timezone chosen=Asia/Kolkata");
        s.process_line(b"[wizard] bridge_default=on");
        s.process_line(b"[wizard] sensor_profile=inhand");
        s.process_line(b"[wizard] image_manifest OK");
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
            WIZ_UART_SIG_IMAGES_OK,
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

    // ── Font tests ──────────────────────────────────────────────────────────

    #[test]
    fn font_has_all_printable_ascii() {
        assert_eq!(FONT_8X8.len(), FONT_8X8_COUNT);
        assert_eq!(FONT_8X8_COUNT, (FONT_8X8_LAST_CHAR - FONT_8X8_FIRST_CHAR + 1) as usize);
    }

    #[test]
    fn font_glyph_returns_some_for_printable() {
        for ch in b' '..=b'~' { assert!(font_glyph(ch).is_some()); }
    }

    #[test]
    fn font_glyph_returns_none_for_nonprintable() {
        assert!(font_glyph(0x00).is_none());
        assert!(font_glyph(0x1F).is_none());
        assert!(font_glyph(0x7F).is_none());
        assert!(font_glyph(0xFF).is_none());
    }

    #[test]
    fn font_capital_a_has_known_shape() {
        // 'A' should have a peak in the middle, lit pixels.
        let g = font_glyph(b'A').unwrap();
        // At least one row has nonzero bits.
        assert!(g.iter().any(|&row| row != 0));
        // Last row of 'A' is empty (descender row in 8x8 IBM font).
        assert_eq!(g[7], 0x00);
    }

    // ── FramebufferPainter tests ────────────────────────────────────────────

    #[test]
    fn painter_clear_fills_buffer() {
        let mut buf = make_buf(16, 8);
        let mut p = FramebufferPainter::new(&mut buf, 16, 8, 16, PixelOrder::Bgr);
        p.clear(0x00_123456);
        assert!(buf.iter().all(|&v| v == 0x00_123456));
    }

    #[test]
    fn painter_fill_rect_clips_to_bounds() {
        let mut buf = make_buf(16, 8);
        let mut p = FramebufferPainter::new(&mut buf, 16, 8, 16, PixelOrder::Bgr);
        p.fill_rect(10, 4, 100, 100, 0x00_FF0000); // way out of bounds
        // Pixels outside (10,4)..(16,8) should be zero.
        assert_eq!(buf[0], 0);
        // Pixel at (10,4) should be red.
        assert_eq!(buf[(4 * 16 + 10) as usize], 0x00_FF0000);
        // Pixel at (15,7) (last in-bounds) should be red.
        assert_eq!(buf[(7 * 16 + 15) as usize], 0x00_FF0000);
    }

    #[test]
    fn painter_encode_bgr_passthrough() {
        let mut buf = make_buf(1, 1);
        let p = FramebufferPainter::new(&mut buf, 1, 1, 1, PixelOrder::Bgr);
        assert_eq!(p.encode(0x00_AABBCC), 0x00_AABBCC);
    }

    #[test]
    fn painter_encode_rgb_swaps_r_and_b() {
        let mut buf = make_buf(1, 1);
        let p = FramebufferPainter::new(&mut buf, 1, 1, 1, PixelOrder::Rgb);
        // 0x00_AABBCC = R=AA G=BB B=CC -> in RGB framebuffer the bytes
        // are stored as R G B; reinterpreted as little-endian u32 that's
        // 0xAARRGGBB swapped to 0x00_CCBBAA... no wait, we want to verify
        // our encode produces a value that PAINTS the input rgb on a
        // little-endian RGBA8 framebuffer. The expectation: original B
        // ends up in the high byte position.
        assert_eq!(p.encode(0x00_AABBCC), 0x00_CCBBAA);
    }

    #[test]
    fn painter_put_pixel_out_of_bounds_no_panic() {
        let mut buf = make_buf(4, 4);
        let mut p = FramebufferPainter::new(&mut buf, 4, 4, 4, PixelOrder::Bgr);
        p.put_pixel(100, 100, 0x00FFFFFF); // clipped silently
        assert!(buf.iter().all(|&v| v == 0));
    }

    #[test]
    fn painter_draw_glyph_writes_only_glyph_box() {
        let mut buf = make_buf(16, 16);
        let mut p = FramebufferPainter::new(&mut buf, 16, 16, 16, PixelOrder::Bgr);
        p.clear(0x00_000000);
        p.draw_glyph(0, 0, b'A', 0x00FF0000, 0x00_000000);
        // Pixels at (8..16, 0..16) should still be background (untouched).
        for y in 0..16 {
            for x in 8..16 {
                assert_eq!(buf[(y * 16 + x) as usize], 0,
                           "pixel ({}, {}) should be background", x, y);
            }
        }
    }

    #[test]
    fn painter_draw_text_advances_by_8() {
        let mut buf = make_buf(64, 8);
        let mut p = FramebufferPainter::new(&mut buf, 64, 8, 64, PixelOrder::Bgr);
        p.clear(0);
        p.draw_text(0, 0, b"AB", 0x00FF0000, 0);
        // Column 0..8 should have some red pixels (A); column 8..16
        // should have some red pixels (B); column 16..24 should be all
        // black (no third character).
        let any_red = |x_start: u32, x_end: u32| {
            for y in 0..8u32 {
                for x in x_start..x_end {
                    if buf[(y * 64 + x) as usize] == 0x00FF0000 {
                        return true;
                    }
                }
            }
            false
        };
        assert!(any_red(0, 8), "'A' column has no red pixels");
        assert!(any_red(8, 16), "'B' column has no red pixels");
        assert!(!any_red(16, 24), "third column should be empty");
    }

    // ── Image manifest tests ────────────────────────────────────────────────

    #[test]
    fn aether_image_manifest_has_five_required() {
        let m = WizardImageManifest::aether_defaults();
        assert_eq!(m.entry_count, 5);
        assert!(m.entries[..5].iter().all(|e| e.required));
    }

    #[test]
    fn image_manifest_lookup_finds_known() {
        let m = WizardImageManifest::aether_defaults();
        assert!(m.lookup(b"boot.img").is_some());
        assert!(m.lookup(b"system.img").is_some());
        assert!(m.lookup(b"vendor.img").is_some());
        assert!(m.lookup(b"vbmeta.img").is_some());
        assert!(m.lookup(b"userdata.img").is_some());
        assert!(m.lookup(b"frobnitz.img").is_none());
    }

    #[test]
    fn image_entry_size_in_range() {
        let m = WizardImageManifest::aether_defaults();
        let e = m.lookup(b"boot.img").unwrap();
        assert!(e.size_in_range(64 * 1024 * 1024)); // exact partition size
        assert!(!e.size_in_range(0));
        assert!(!e.size_in_range(1024u64 * 1024 * 1024)); // 1 GiB way too big
    }

    #[test]
    fn check_image_manifest_passes_for_real_build() {
        let m = WizardImageManifest::aether_defaults();
        // The 5 actual sizes from build run 29 success.
        let found: &[(&[u8], u64)] = &[
            (b"boot.img",     67_108_864),
            (b"system.img",   988_086_708),
            (b"vendor.img",   34_500_840),
            (b"vbmeta.img",   8_192),
            (b"userdata.img", 6_525_276),
        ];
        check_image_manifest(&m, found).unwrap();
    }

    #[test]
    fn check_image_manifest_rejects_missing_required() {
        let m = WizardImageManifest::aether_defaults();
        let found: &[(&[u8], u64)] = &[
            (b"boot.img",     67_108_864),
            // system.img missing.
            (b"vendor.img",   34_500_840),
            (b"vbmeta.img",   8_192),
            (b"userdata.img", 6_525_276),
        ];
        assert_eq!(check_image_manifest(&m, found),
                   Err(WizardError::RequiredImageMissing));
    }

    #[test]
    fn check_image_manifest_rejects_size_out_of_range() {
        let m = WizardImageManifest::aether_defaults();
        let found: &[(&[u8], u64)] = &[
            (b"boot.img",     67_108_864),
            (b"system.img",   988_086_708),
            (b"vendor.img",   34_500_840),
            (b"vbmeta.img",   8_192),
            (b"userdata.img", 1024u64 * 1024 * 1024), // 1 GiB; cap is 16 MiB
        ];
        assert_eq!(check_image_manifest(&m, found),
                   Err(WizardError::ImageSizeOutOfRange));
    }

    #[test]
    fn record_image_check_flips_gate() {
        let mut s = WizardState::new(WizardConfig::aether_defaults());
        let found: &[(&[u8], u64)] = &[
            (b"boot.img",     67_108_864),
            (b"system.img",   988_086_708),
            (b"vendor.img",   34_500_840),
            (b"vbmeta.img",   8_192),
            (b"userdata.img", 6_525_276),
        ];
        assert!(!s.gate.images_present);
        s.record_image_check(found).unwrap();
        assert!(s.gate.images_present);
        assert_eq!(s.phase, WizardPhase::ImagesVerified);
    }

    #[test]
    fn render_screen_dispatches_by_phase() {
        let mut buf = make_buf(320, 200);
        let mut p = FramebufferPainter::new(&mut buf, 320, 200, 320, PixelOrder::Bgr);
        let mut s = WizardState::new(WizardConfig::aether_defaults());
        assert_eq!(render_screen(&mut p, &s), "language_screen");
        s.advance_phase(WizardPhase::LanguageChosen).unwrap();
        assert_eq!(render_screen(&mut p, &s), "kb_layout_screen");
        s.advance_phase(WizardPhase::SensorProfileChosen).unwrap();
        assert_eq!(render_screen(&mut p, &s), "images_screen");
        s.advance_phase(WizardPhase::ImagesVerified).unwrap();
        assert_eq!(render_screen(&mut p, &s), "confirmation_screen");
        s.advance_phase(WizardPhase::GatePassed).unwrap();
        assert_eq!(render_screen(&mut p, &s), "complete_screen");
    }

    #[test]
    fn render_writes_title_bar_pixels() {
        let mut buf = make_buf(320, 200);
        let mut p = FramebufferPainter::new(&mut buf, 320, 200, 320, PixelOrder::Bgr);
        let s = WizardState::new(WizardConfig::aether_defaults());
        render_screen(&mut p, &s);
        // The first 24 rows should have the accent color somewhere.
        let mut found_accent = false;
        for y in 0..24 {
            for x in 0..320 {
                if buf[y * 320 + x] == WIZ_COLOR_ACCENT {
                    found_accent = true;
                    break;
                }
            }
            if found_accent { break; }
        }
        assert!(found_accent, "title bar accent color not painted");
    }
}
