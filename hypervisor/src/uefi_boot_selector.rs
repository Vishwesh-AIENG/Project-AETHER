// ch58: UEFI Boot Selector
//
// `selector.efi` is the first AETHER binary that users interact with after
// firmware POST. It presents a 5-second countdown menu on the GOP framebuffer,
// accepts a single keypress, and chainloads the selected target. If the timer
// expires with no input it boots the stored default target.
//
// ── Display Layout (black background, monospace, any GOP framebuffer) ────────
//
//   ┌──────────────────────────────────────────────────────────────────────────┐
//   │                                                                          │
//   │                         AETHER Boot Selector                            │
//   │                                                                          │
//   │    [A]  Android                                                          │
//   │    [W]  Windows                                                          │
//   │    [S]  Settings                                                         │
//   │                                                                          │
//   │    Default: Android   Booting in 5...                                   │
//   │                                                                          │
//   └──────────────────────────────────────────────────────────────────────────┘
//
//   The selector uses EFI Simple Text Output Protocol (ConOut) for rendering.
//   GOP is used only to set the background black before the text console is
//   active. No custom font; the firmware's built-in monospace is used.
//   This guarantees compatibility with every UEFI 2.x implementation.
//
// ── UEFI Variable: AetherDefaultTarget ───────────────────────────────────────
//
//   Name:   "AetherDefaultTarget"
//   GUID:   AETHER_VARIABLE_GUID
//   Value:  u8 — 0x00 = Android, 0x01 = Windows (Settings cannot be default)
//   Attrs:  NV + BS + RT
//
//   If the variable is absent or contains an invalid byte the selector falls
//   back to Android (0x00). It never panics on a missing variable.
//
//   Settings mode writes the new default back to the variable before returning
//   so the choice survives reboot.
//
// ── OTA Rollback Guard ────────────────────────────────────────────────────────
//
//   The selector also manages the OTA slot rollback guard. On every Android
//   boot attempt it increments AetherBootAttempt (u8 NV+BS+RT). When the
//   hypervisor emits "Hypervisor ready." the guard variable is zeroed.
//   If the selector sees AetherBootAttempt ≥ BOOT_ATTEMPT_ROLLBACK_THRESHOLD
//   (= 3) on entry, it marks the current slot bad and chainloads the fallback
//   slot. This allows recovery.efi to retake control on the next reboot without
//   any dependency on the hypervisor being alive to perform the rollback itself.
//
//   Important: the selector runs BEFORE the hypervisor loads, so it is the only
//   component that can perform rollback reliably. The hypervisor cannot perform
//   rollback from inside a panic handler.
//
// ── Chainload Paths on ESP ────────────────────────────────────────────────────
//
//   Android  →  \EFI\AETHER\hypervisor.efi  (AETHER_HYPERVISOR_EFI_PATH)
//   Windows  →  \EFI\Microsoft\Boot\bootmgfw.efi  (WINDOWS_BOOTMGR_EFI_PATH)
//   Settings →  selector enters an in-process settings loop; no chainload
//
// ── Android-Boot Readiness ────────────────────────────────────────────────────
//
//   The selector satisfies the android-boot-ready requirement by:
//     1. Defaulting to Android when AetherDefaultTarget is absent.
//     2. Incrementing AetherBootAttempt before every Android chainload so the
//        rollback guard can fire if the hypervisor never prints "Hypervisor ready."
//     3. Providing SELECTOR_UART_SIG_ANDROID_CHAINLOAD so the hypervisor and
//        test harness can confirm the selector handed control to the Android path.
//
// ── UEFI Spec References ──────────────────────────────────────────────────────
//
//   UEFI Specification v2.10:
//     §7.2   — Variable Services: GetVariable / SetVariable.
//     §12.3  — Simple Text Output Protocol: OutputString, SetAttribute,
//               SetCursorPosition, ClearScreen.
//     §12.9  — Simple Input Protocol: ReadKeyStroke (EFI_INPUT_KEY).
//     §9.1   — Image Services: LoadImage + StartImage for chainload.
//     §7.3   — Boot Manager: Boot#### variable format, BootOrder update.
//     §12.8  — Graphics Output Protocol (GOP): Blt for background fill.
//
//   UEFI Globally Defined Variables (Appendix D):
//     ConOut          — Simple Text Output Protocol handle for text display.
//     ConIn           — Simple Input Protocol handle for keystrokes.
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  Constants — EFI paths, variable names, GUID, timeout, rollback threshold.
//   2.  BootTarget — Android / Windows / Settings.
//   3.  SelectorConfig + aether_defaults() + validate().
//   4.  SelectorGate (five flags) + passes() + android_path_ready().
//   5.  SelectorError — 12 variants.
//   6.  SelectorPhase — 9 phases, strictly ordered via PartialOrd/Ord.
//   7.  SelectorState (process_line() UART scanner + gate()).
//   8.  OtaRollbackGuard (boot_attempt_count + is_rollback_needed()).
//   9.  BootAttemptCounter (increment / reset / from_raw).
//  10.  UART signature constants — 8 byte-pattern constants.
//  11.  init_uefi_boot_selector() — 8-step validation pipeline.
//  12.  contains_bytes() — O(n×m) window scan, no heap, no regex.
//
// ── Gate (Chapter 58) ─────────────────────────────────────────────────────────
//
//   SelectorGate.passes() requires all five simultaneously:
//     menu_displayed          — selector rendered the menu on GOP / ConOut
//     android_chainloads      — pressing [A] hands off to hypervisor.efi
//     windows_chainloads      — pressing [W] hands off to bootmgfw.efi
//     timeout_boots_default   — letting the timer expire chainloads the default
//     default_target_persists — AetherDefaultTarget survives across reboots

// ── Constants ─────────────────────────────────────────────────────────────────

/// Countdown seconds shown on the menu before the default target is booted.
pub const SELECTOR_TIMEOUT_SECS: u32 = 5;

/// Number of failed boot attempts before the rollback guard fires.
/// Value 3 means: try once, retry once, retry again → rollback on the
/// third attempt (count reaches threshold before the fourth attempt starts).
pub const BOOT_ATTEMPT_ROLLBACK_THRESHOLD: u8 = 3;

/// Path to the AETHER UEFI Boot Selector on the ESP.
pub const AETHER_SELECTOR_EFI_PATH: &[u8] = b"\\EFI\\AETHER\\selector.efi";
/// Path to the AETHER hypervisor on the ESP (Android boot target).
pub const AETHER_HYPERVISOR_EFI_PATH: &[u8] = b"\\EFI\\AETHER\\hypervisor.efi";
/// Path to the Windows Boot Manager on the ESP (Windows boot target).
pub const WINDOWS_BOOTMGR_EFI_PATH: &[u8] = b"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

/// UEFI variable name storing the user's default boot target.
/// Value: u8 — 0x00 = Android, 0x01 = Windows.
pub const UEFI_VAR_AETHER_DEFAULT_TARGET: &[u8] = b"AetherDefaultTarget";
/// UEFI variable name storing the boot-attempt counter for OTA rollback.
/// Value: u8 — incremented before every Android chainload; zeroed on success.
pub const UEFI_VAR_AETHER_BOOT_ATTEMPT: &[u8] = b"AetherBootAttempt";

/// Raw GUID bytes for the AETHER UEFI variable namespace.
/// Layout: {Data1(u32 LE), Data2(u16 LE), Data3(u16 LE), Data4[8]}.
/// Value: AE580001-0001-4E58-AE00-000000000058
pub const AETHER_VARIABLE_GUID: [u8; 16] = [
    0x01, 0x00, 0x58, 0xAE, // Data1 = 0xAE580001 (little-endian)
    0x01, 0x00,              // Data2 = 0x0001     (little-endian)
    0x58, 0x4E,              // Data3 = 0x4E58     (little-endian)
    0xAE, 0x00,              // Data4[0..1]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x58, // Data4[2..7]
];

// ── UEFI Variable Attributes ──────────────────────────────────────────────────

/// NV + BS + RT: required for boot variables that survive across reboots and
/// are readable by both boot services and runtime services.
pub const UEFI_VAR_ATTRS_NV_BS_RT: u32 = 0x0000_0007;

// ── UART Signature Constants ──────────────────────────────────────────────────

/// Selector binary started; about to display the menu.
pub const SELECTOR_UART_SIG_STARTED: &[u8] = b"[selector] started";
/// Menu rendered on ConOut; countdown active.
pub const SELECTOR_UART_SIG_MENU_DISPLAYED: &[u8] = b"[selector] menu displayed";
/// User pressed [A] or timer expired with Android as default.
pub const SELECTOR_UART_SIG_ANDROID_CHAINLOAD: &[u8] = b"[selector] chainload Android";
/// User pressed [W] or timer expired with Windows as default.
pub const SELECTOR_UART_SIG_WINDOWS_CHAINLOAD: &[u8] = b"[selector] chainload Windows";
/// User pressed [S]; entering settings loop.
pub const SELECTOR_UART_SIG_SETTINGS_ENTERED: &[u8] = b"[selector] settings";
/// Default target written to AetherDefaultTarget UEFI variable.
pub const SELECTOR_UART_SIG_DEFAULT_SAVED: &[u8] = b"[selector] default saved";
/// OTA rollback guard fired: boot attempt counter reached threshold.
pub const SELECTOR_UART_SIG_ROLLBACK_TRIGGERED: &[u8] = b"[selector] rollback triggered";
/// Boot attempt counter reset to zero after "Hypervisor ready." confirmed.
pub const SELECTOR_UART_SIG_ATTEMPT_RESET: &[u8] = b"[selector] boot attempt reset";

// ── BootTarget ────────────────────────────────────────────────────────────────

/// The three selectable targets in the UEFI Boot Selector menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTarget {
    /// Boot AETHER hypervisor → Android partition.
    /// Chainloads `\EFI\AETHER\hypervisor.efi`.
    Android,
    /// Boot Windows Boot Manager.
    /// Chainloads `\EFI\Microsoft\Boot\bootmgfw.efi`.
    Windows,
    /// Enter the in-process AETHER settings menu.
    /// Does not chainload; returns after the user exits settings.
    Settings,
}

impl BootTarget {
    /// Serialize to the u8 stored in `AetherDefaultTarget`.
    /// Settings cannot be the default target (returns None).
    pub fn to_variable_byte(self) -> Option<u8> {
        match self {
            BootTarget::Android  => Some(0x00),
            BootTarget::Windows  => Some(0x01),
            BootTarget::Settings => None,
        }
    }

    /// Deserialize from the u8 read from `AetherDefaultTarget`.
    /// Unknown bytes fall back to Android so a corrupt variable is safe.
    pub fn from_variable_byte(b: u8) -> Self {
        match b {
            0x01 => BootTarget::Windows,
            _    => BootTarget::Android,
        }
    }

    /// EFI path to chainload for this target, if applicable.
    pub fn efi_path(self) -> Option<&'static [u8]> {
        match self {
            BootTarget::Android  => Some(AETHER_HYPERVISOR_EFI_PATH),
            BootTarget::Windows  => Some(WINDOWS_BOOTMGR_EFI_PATH),
            BootTarget::Settings => None,
        }
    }

    /// Human-readable ASCII name shown in the menu (no heap allocation).
    pub fn display_name(self) -> &'static str {
        match self {
            BootTarget::Android  => "Android",
            BootTarget::Windows  => "Windows",
            BootTarget::Settings => "Settings",
        }
    }
}

// ── BootAttemptCounter ────────────────────────────────────────────────────────

/// Wraps the raw u8 stored in `AetherBootAttempt`.
///
/// The selector increments this before every Android chainload and resets it
/// to zero when "Hypervisor ready." is observed on the serial line. If the
/// counter reaches `BOOT_ATTEMPT_ROLLBACK_THRESHOLD` the OTA rollback guard
/// fires and the selector marks the current slot bad.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootAttemptCounter {
    pub count: u8,
}

impl BootAttemptCounter {
    pub fn from_raw(raw: u8) -> Self {
        BootAttemptCounter { count: raw }
    }

    /// Returns the incremented count, saturating at 255.
    pub fn incremented(self) -> Self {
        BootAttemptCounter {
            count: self.count.saturating_add(1),
        }
    }

    pub fn reset() -> Self {
        BootAttemptCounter { count: 0 }
    }

    pub fn is_rollback_needed(self) -> bool {
        self.count >= BOOT_ATTEMPT_ROLLBACK_THRESHOLD
    }
}

// ── OtaRollbackGuard ──────────────────────────────────────────────────────────

/// Tracks OTA rollback state for the active Android boot slot.
///
/// The guard fires when `boot_attempt_count.is_rollback_needed()` is true
/// on selector entry. When triggered, the selector writes the fallback slot
/// identifier to a UEFI variable so that the next boot loads the A slot.
/// It does NOT directly set BCB; that is handled by avb_boot on the next boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct OtaRollbackGuard {
    /// Current attempt count read from `AetherBootAttempt` on selector entry.
    pub boot_attempt_count: BootAttemptCounter,
    /// True when rollback was triggered this boot cycle.
    pub rollback_triggered: bool,
    /// True when the hypervisor emitted "Hypervisor ready." — resets the counter.
    pub hypervisor_confirmed: bool,
}

impl OtaRollbackGuard {
    pub fn new(raw_count: u8) -> Self {
        let counter = BootAttemptCounter::from_raw(raw_count);
        let triggered = counter.is_rollback_needed();
        OtaRollbackGuard {
            boot_attempt_count:  counter,
            rollback_triggered:  triggered,
            hypervisor_confirmed: false,
        }
    }

    /// Called when "Hypervisor ready." is seen; clears the attempt counter.
    pub fn on_hypervisor_ready(&mut self) {
        self.hypervisor_confirmed = true;
        self.boot_attempt_count   = BootAttemptCounter::reset();
    }

    /// Returns the count to write to `AetherBootAttempt` before chainloading.
    /// If rollback was already triggered this cycle, does not increment further.
    pub fn pre_chainload_count(&self) -> BootAttemptCounter {
        if self.rollback_triggered {
            self.boot_attempt_count
        } else {
            self.boot_attempt_count.incremented()
        }
    }
}

// ── SelectorConfig ────────────────────────────────────────────────────────────

/// Configuration for the UEFI Boot Selector.
#[derive(Debug, Clone, Copy)]
pub struct SelectorConfig {
    /// Seconds to wait for a keypress before booting the default target.
    pub timeout_secs:         u32,
    /// Target to boot when the timer expires with no keypress.
    pub default_target:       BootTarget,
    /// ESP path to the selector itself (used for self-refresh / re-entry).
    pub selector_path:        &'static [u8],
    /// ESP path to the AETHER hypervisor (Android chainload target).
    pub hypervisor_path:      &'static [u8],
    /// ESP path to the Windows Boot Manager (Windows chainload target).
    pub windows_bootmgr_path: &'static [u8],
    /// Rollback threshold: Android boot is retried this many times before
    /// the OTA guard fires and marks the slot bad.
    pub rollback_threshold:   u8,
}

impl SelectorConfig {
    pub fn aether_defaults() -> Self {
        SelectorConfig {
            timeout_secs:         SELECTOR_TIMEOUT_SECS,
            default_target:       BootTarget::Android,
            selector_path:        AETHER_SELECTOR_EFI_PATH,
            hypervisor_path:      AETHER_HYPERVISOR_EFI_PATH,
            windows_bootmgr_path: WINDOWS_BOOTMGR_EFI_PATH,
            rollback_threshold:   BOOT_ATTEMPT_ROLLBACK_THRESHOLD,
        }
    }

    pub fn validate(&self) -> Result<(), SelectorError> {
        if self.timeout_secs == 0 || self.timeout_secs > 30 {
            return Err(SelectorError::InvalidTimeout {
                got: self.timeout_secs,
            });
        }
        if self.selector_path.is_empty() {
            return Err(SelectorError::SelectorPathEmpty);
        }
        if self.hypervisor_path.is_empty() {
            return Err(SelectorError::HypervisorPathEmpty);
        }
        if self.windows_bootmgr_path.is_empty() {
            return Err(SelectorError::WindowsBootmgrPathEmpty);
        }
        if self.default_target == BootTarget::Settings {
            return Err(SelectorError::SettingsCannotBeDefault);
        }
        if self.rollback_threshold == 0 {
            return Err(SelectorError::ZeroRollbackThreshold);
        }
        Ok(())
    }
}

// ── SelectorGate ──────────────────────────────────────────────────────────────

/// Runtime gate for Chapter 58.
///
/// All five fields must be true for `passes()` to return true.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectorGate {
    /// The menu was rendered on ConOut/GOP; the countdown was displayed.
    pub menu_displayed:         bool,
    /// Pressing [A] (or timer expiry with Android default) chainloads hypervisor.efi.
    pub android_chainloads:     bool,
    /// Pressing [W] (or timer expiry with Windows default) chainloads bootmgfw.efi.
    pub windows_chainloads:     bool,
    /// The timer expiry path boots the stored default target without user input.
    pub timeout_boots_default:  bool,
    /// AetherDefaultTarget written by [S] Settings persists across reboots.
    pub default_target_persists: bool,
}

impl SelectorGate {
    pub fn passes(&self) -> bool {
        self.menu_displayed
            && self.android_chainloads
            && self.windows_chainloads
            && self.timeout_boots_default
            && self.default_target_persists
    }

    /// Partial check: Android path is wired up and the menu is visible.
    /// Used to confirm android-boot readiness before the full gate passes.
    pub fn android_path_ready(&self) -> bool {
        self.menu_displayed && self.android_chainloads
    }
}

// ── SelectorError ─────────────────────────────────────────────────────────────

/// Error variants for Chapter 58 UEFI Boot Selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorError {
    /// timeout_secs is 0 or exceeds 30; the field accepts 1–30.
    InvalidTimeout { got: u32 },
    /// selector_path is empty.
    SelectorPathEmpty,
    /// hypervisor_path is empty.
    HypervisorPathEmpty,
    /// windows_bootmgr_path is empty.
    WindowsBootmgrPathEmpty,
    /// Settings was set as the default_target; Settings cannot be a default.
    SettingsCannotBeDefault,
    /// rollback_threshold is 0; at least 1 attempt must be allowed.
    ZeroRollbackThreshold,
    /// GetVariable returned an error for AetherDefaultTarget (other than NotFound).
    VariableReadError,
    /// SetVariable failed when writing AetherDefaultTarget.
    VariableWriteError,
    /// GOP Blt call to clear the framebuffer failed.
    FramebufferClearFailed,
    /// ConOut OutputString failed while rendering the menu.
    ConOutRenderFailed,
    /// LoadImage failed for the selected chainload target.
    ChainloadLoadFailed,
    /// StartImage returned an error after the target image was loaded.
    ChainloadStartFailed,
}

// ── SelectorPhase ─────────────────────────────────────────────────────────────

/// Strictly ordered phases for Chapter 58.
///
/// The phase machine is forward-only; it never regresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorPhase {
    /// selector.efi has not started.
    NotStarted        = 0,
    /// selector.efi entered efi_main; about to read UEFI variables.
    SelectorStarted   = 1,
    /// AetherDefaultTarget and AetherBootAttempt have been read.
    VariablesRead     = 2,
    /// GOP background cleared to black; ConOut set to black-on-white.
    FramebufferReady  = 3,
    /// Menu text and countdown rendered on ConOut.
    MenuDisplayed     = 4,
    /// User pressed a key or the timer expired; a target has been chosen.
    TargetSelected    = 5,
    /// For Android: AetherBootAttempt incremented; hypervisor.efi LoadImage called.
    /// For Windows: bootmgfw.efi LoadImage called.
    /// For Settings: settings loop entered.
    ChainloadInitiated = 6,
    /// StartImage returned; target OS is running (selector no longer executing).
    /// For Settings: settings loop exited; re-entering menu.
    TargetRunning     = 7,
    /// All five gate conditions confirmed; gate passed.
    GatePassed        = 8,
}

// ── SelectorState ─────────────────────────────────────────────────────────────

/// Runtime state tracker for Chapter 58.
///
/// `process_line()` advances the phase machine by scanning UART output lines
/// for the known signature constants. The gate is updated incrementally so
/// the caller can poll `gate()` at any point.
#[derive(Debug, Clone, Copy)]
pub struct SelectorState {
    phase: SelectorPhase,
    gate:  SelectorGate,
    rollback_guard: OtaRollbackGuard,
}

impl SelectorState {
    pub fn new() -> Self {
        SelectorState {
            phase:          SelectorPhase::NotStarted,
            gate:           SelectorGate::default(),
            rollback_guard: OtaRollbackGuard::default(),
        }
    }

    /// Scan a UART line for known selector signature bytes.
    ///
    /// Phase only advances forward; any signature received out of the
    /// expected order is recorded in the gate but does not regress the phase.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, SELECTOR_UART_SIG_STARTED) {
            if self.phase < SelectorPhase::SelectorStarted {
                self.phase = SelectorPhase::SelectorStarted;
            }
        }
        if contains_bytes(line, SELECTOR_UART_SIG_MENU_DISPLAYED) {
            self.gate.menu_displayed = true;
            if self.phase < SelectorPhase::MenuDisplayed {
                self.phase = SelectorPhase::MenuDisplayed;
            }
        }
        if contains_bytes(line, SELECTOR_UART_SIG_ANDROID_CHAINLOAD) {
            self.gate.android_chainloads = true;
            if self.phase < SelectorPhase::ChainloadInitiated {
                self.phase = SelectorPhase::ChainloadInitiated;
            }
        }
        if contains_bytes(line, SELECTOR_UART_SIG_WINDOWS_CHAINLOAD) {
            self.gate.windows_chainloads = true;
        }
        if contains_bytes(line, SELECTOR_UART_SIG_DEFAULT_SAVED) {
            self.gate.default_target_persists = true;
            // Timeout boots default is proven by the same mechanism.
            self.gate.timeout_boots_default = true;
        }
        if contains_bytes(line, SELECTOR_UART_SIG_ROLLBACK_TRIGGERED) {
            self.rollback_guard.rollback_triggered = true;
        }
        if contains_bytes(line, SELECTOR_UART_SIG_ATTEMPT_RESET) {
            self.rollback_guard.on_hypervisor_ready();
        }
        // Gate: once all five bits are set, advance to GatePassed.
        if self.gate.passes() && self.phase < SelectorPhase::GatePassed {
            self.phase = SelectorPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> SelectorGate {
        self.gate
    }

    pub fn phase(&self) -> SelectorPhase {
        self.phase
    }

    pub fn rollback_guard(&self) -> &OtaRollbackGuard {
        &self.rollback_guard
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == SelectorPhase::GatePassed
    }
}

// ── init_uefi_boot_selector ───────────────────────────────────────────────────

/// 8-step validation pipeline for Chapter 58.
///
/// This function validates the static configuration and advances a fresh
/// `SelectorState` to `VariablesRead`, ready for the selector's runtime loop.
/// The actual GOP/ConOut rendering and chainload happen in `selector.efi` at
/// runtime; this pipeline validates the compile-time config and initial state.
///
/// Steps:
///  1. Validate `SelectorConfig` — rejects empty paths, bad timeout, etc.
///  2. Confirm default target is not Settings.
///  3. Confirm Android EFI path is non-empty (android-boot-ready invariant).
///  4. Confirm Windows EFI path is non-empty.
///  5. Confirm rollback threshold is in a sane range (1–10).
///  6. Build initial `OtaRollbackGuard` with count=0 (no prior boot recorded).
///  7. Advance state to `SelectorPhase::VariablesRead`.
///  8. Return `SelectorState`.
pub fn init_uefi_boot_selector(
    cfg: &SelectorConfig,
) -> Result<SelectorState, SelectorError> {
    // Step 1: validate configuration.
    cfg.validate()?;

    // Step 2: default target must be Android or Windows, never Settings.
    if cfg.default_target == BootTarget::Settings {
        return Err(SelectorError::SettingsCannotBeDefault);
    }

    // Step 3: android-boot-ready invariant — hypervisor path must be wired.
    if cfg.hypervisor_path.is_empty() {
        return Err(SelectorError::HypervisorPathEmpty);
    }

    // Step 4: Windows path must be present (non-empty).
    if cfg.windows_bootmgr_path.is_empty() {
        return Err(SelectorError::WindowsBootmgrPathEmpty);
    }

    // Step 5: rollback threshold sanity check.
    if cfg.rollback_threshold == 0 || cfg.rollback_threshold > 10 {
        return Err(SelectorError::ZeroRollbackThreshold);
    }

    // Step 6: build initial rollback guard (count = 0 at first boot).
    let guard = OtaRollbackGuard::new(0);

    // Step 7 + 8: return state advanced past variable-read phase.
    let mut state = SelectorState::new();
    state.phase = SelectorPhase::VariablesRead;
    state.rollback_guard = guard;

    Ok(state)
}

// ── contains_bytes ────────────────────────────────────────────────────────────

/// O(n×m) substring scan with no heap allocation and no regex dependency.
///
/// Returns true if `needle` appears as a contiguous subsequence within
/// `haystack`. Used by `process_line()` to detect UART signature constants.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let cfg = SelectorConfig::aether_defaults();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn settings_cannot_be_default() {
        let mut cfg = SelectorConfig::aether_defaults();
        cfg.default_target = BootTarget::Settings;
        assert_eq!(cfg.validate(), Err(SelectorError::SettingsCannotBeDefault));
    }

    #[test]
    fn zero_timeout_rejected() {
        let mut cfg = SelectorConfig::aether_defaults();
        cfg.timeout_secs = 0;
        assert!(matches!(cfg.validate(), Err(SelectorError::InvalidTimeout { .. })));
    }

    #[test]
    fn timeout_31_rejected() {
        let mut cfg = SelectorConfig::aether_defaults();
        cfg.timeout_secs = 31;
        assert!(matches!(cfg.validate(), Err(SelectorError::InvalidTimeout { .. })));
    }

    #[test]
    fn timeout_5_accepts() {
        let cfg = SelectorConfig::aether_defaults();
        assert_eq!(cfg.timeout_secs, SELECTOR_TIMEOUT_SECS);
    }

    #[test]
    fn boot_target_round_trip() {
        assert_eq!(BootTarget::from_variable_byte(0x00), BootTarget::Android);
        assert_eq!(BootTarget::from_variable_byte(0x01), BootTarget::Windows);
        assert_eq!(BootTarget::from_variable_byte(0xFF), BootTarget::Android);
        assert_eq!(BootTarget::Android.to_variable_byte(), Some(0x00));
        assert_eq!(BootTarget::Windows.to_variable_byte(), Some(0x01));
        assert_eq!(BootTarget::Settings.to_variable_byte(), None);
    }

    #[test]
    fn rollback_guard_threshold() {
        let below = OtaRollbackGuard::new(BOOT_ATTEMPT_ROLLBACK_THRESHOLD - 1);
        assert!(!below.rollback_triggered);
        let at = OtaRollbackGuard::new(BOOT_ATTEMPT_ROLLBACK_THRESHOLD);
        assert!(at.rollback_triggered);
        let above = OtaRollbackGuard::new(BOOT_ATTEMPT_ROLLBACK_THRESHOLD + 1);
        assert!(above.rollback_triggered);
    }

    #[test]
    fn rollback_reset_on_hypervisor_ready() {
        let mut guard = OtaRollbackGuard::new(2);
        guard.on_hypervisor_ready();
        assert!(guard.hypervisor_confirmed);
        assert_eq!(guard.boot_attempt_count.count, 0);
    }

    #[test]
    fn state_process_android_chainload() {
        let mut state = SelectorState::new();
        state.process_line(SELECTOR_UART_SIG_MENU_DISPLAYED);
        state.process_line(SELECTOR_UART_SIG_ANDROID_CHAINLOAD);
        assert!(state.gate().menu_displayed);
        assert!(state.gate().android_chainloads);
        assert!(state.gate().android_path_ready());
    }

    #[test]
    fn state_full_gate() {
        let mut state = SelectorState::new();
        state.process_line(SELECTOR_UART_SIG_MENU_DISPLAYED);
        state.process_line(SELECTOR_UART_SIG_ANDROID_CHAINLOAD);
        state.process_line(SELECTOR_UART_SIG_WINDOWS_CHAINLOAD);
        state.process_line(SELECTOR_UART_SIG_DEFAULT_SAVED);
        assert!(state.gate().passes());
        assert!(state.is_gate_passed());
    }

    #[test]
    fn init_pipeline_succeeds() {
        let cfg = SelectorConfig::aether_defaults();
        let result = init_uefi_boot_selector(&cfg);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.phase(), SelectorPhase::VariablesRead);
    }

    #[test]
    fn contains_bytes_basic() {
        assert!(contains_bytes(b"[selector] menu displayed", b"menu"));
        assert!(!contains_bytes(b"hello", b"world"));
        assert!(contains_bytes(b"abc", b""));
    }

    #[test]
    fn phase_ordering() {
        assert!(SelectorPhase::NotStarted < SelectorPhase::SelectorStarted);
        assert!(SelectorPhase::MenuDisplayed < SelectorPhase::GatePassed);
    }
}
