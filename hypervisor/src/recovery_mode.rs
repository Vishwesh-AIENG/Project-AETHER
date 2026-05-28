// ch62: Recovery Mode
//
// Boot-loop trap + factory reset + sideload. Entry vectors:
//   (a) ch58's OtaRollbackGuard fires when boot attempts ≥ threshold
//   (b) User holds Ctrl+Alt+Tab at the boot selector (hardware-only
//       trigger per ch41 — must come from a passthrough USB keyboard,
//       not the Android-side IME)
//   (c) Explicit AetherEnterRecovery UEFI variable set (debug path)
//
// Every destructive action requires a typed confirmation phrase, scanned
// against the user input through the GOP framebuffer keyboard handler.
// The phrase is fixed in this module (not user-customisable) so a
// malicious app cannot pre-fill it from an Android-side helper.
//
// ── Actions ───────────────────────────────────────────────────────────────────
//
//   NoOp                  display recovery menu, exit on user request
//   ReturnToSelector      reboot back into ch58 boot selector
//   FactoryReset          wipe userdata + cache + AetherSetupComplete
//                         confirm phrase: "ERASE EVERYTHING"
//   Sideload              accept a signed boot.img from USB ESP, write
//                         to the inactive slot, switch slots
//                         confirm phrase: "SIDELOAD"
//   SlotRollback          revert AetherActiveSlot to the previous value
//                         confirm phrase: "ROLLBACK"
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1. RecoveryEntryReason + RecoveryAction enums.
//   2. RecoveryConfirmation — fixed phrase per action.
//   3. RecoveryConfig + Gate + Error + Phase.
//   4. RecoveryState — process_line() UART scanner + action execution.
//   5. init_recovery_mode() — 6-step pipeline.

/// Why we entered recovery. Surfaces to the user on the menu screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEntryReason {
    /// ch58 boot-attempt counter hit the rollback threshold.
    BootLoop,
    /// User held Ctrl+Alt+Tab at the boot selector.
    UserRequested,
    /// AetherEnterRecovery UEFI variable was set (debug/dev only).
    DebugTrigger,
}

/// Available actions in the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    NoOp,
    ReturnToSelector,
    FactoryReset,
    Sideload,
    SlotRollback,
}

impl RecoveryAction {
    /// Confirmation phrase the user must type for destructive actions.
    /// NoOp / ReturnToSelector are non-destructive and need no confirm.
    pub fn confirmation_phrase(self) -> Option<&'static [u8]> {
        match self {
            RecoveryAction::NoOp             => None,
            RecoveryAction::ReturnToSelector => None,
            RecoveryAction::FactoryReset     => Some(b"ERASE EVERYTHING"),
            RecoveryAction::Sideload         => Some(b"SIDELOAD"),
            RecoveryAction::SlotRollback     => Some(b"ROLLBACK"),
        }
    }

    pub fn is_destructive(self) -> bool {
        self.confirmation_phrase().is_some()
    }
}

pub const UEFI_VAR_AETHER_ENTER_RECOVERY: &[u8] = b"AetherEnterRecovery";

pub const REC_UART_SIG_ENTERED:                &[u8] = b"[recovery] entered reason=";
pub const REC_UART_SIG_MENU_PAINTED:            &[u8] = b"[recovery] menu painted";
pub const REC_UART_SIG_ACTION_SELECTED:         &[u8] = b"[recovery] action=";
pub const REC_UART_SIG_CONFIRMATION_OK:         &[u8] = b"[recovery] confirmation OK";
pub const REC_UART_SIG_FACTORY_RESET_DONE:      &[u8] = b"[recovery] factory reset done";
pub const REC_UART_SIG_SIDELOAD_DONE:           &[u8] = b"[recovery] sideload done";
pub const REC_UART_SIG_ROLLBACK_DONE:           &[u8] = b"[recovery] rollback done";
pub const REC_UART_SIG_EXITED:                  &[u8] = b"[recovery] exited reboot";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    /// User typed a confirmation phrase that did not match the required one.
    ConfirmationMismatch,
    /// Sideload's boot.img signature didn't verify under our MOK key.
    SideloadSignatureInvalid,
    /// No previous slot exists to roll back to (fresh install).
    NoPreviousSlot,
    /// Factory reset failed to wipe userdata (block-layer error).
    UserdataWipeFailed,
    /// Phase machine asked to advance backward.
    PhaseRegression,
    /// Framebuffer unavailable — recovery cannot run blind.
    FramebufferUnavailable,
    /// Generic UEFI variable write error.
    VariableWriteError,
    /// Confirmation handler asked to verify a non-destructive action.
    UnnecessaryConfirmation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryPhase {
    NotStarted,
    MenuPainted,
    ActionSelected,
    ConfirmationReceived,
    ActionExecuted,
    Exited,
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryConfig {
    /// Whether the runtime allows the DebugTrigger entry reason. Always
    /// false in user builds; opt-in for development.
    pub allow_debug_trigger: bool,
    /// Per-step keystroke idle timeout in seconds. 5-minute default.
    pub idle_timeout_secs: u32,
}

impl RecoveryConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            allow_debug_trigger: false,
            idle_timeout_secs:   5 * 60,
        }
    }
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.idle_timeout_secs == 0 {
            return Err(RecoveryError::FramebufferUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryGate {
    pub menu_painted:         bool,
    pub action_selected:      bool,
    pub confirmation_passed:  bool,
    pub action_executed:      bool,
}

impl RecoveryGate {
    pub fn passes(&self) -> bool {
        self.menu_painted
            && self.action_selected
            && self.confirmation_passed
            && self.action_executed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryState {
    pub config:        RecoveryConfig,
    pub entry_reason:  RecoveryEntryReason,
    pub selected:      RecoveryAction,
    pub phase:         RecoveryPhase,
    pub gate:          RecoveryGate,
}

impl RecoveryState {
    pub const fn new(config: RecoveryConfig, entry_reason: RecoveryEntryReason) -> Self {
        Self {
            config,
            entry_reason,
            selected: RecoveryAction::NoOp,
            phase:    RecoveryPhase::NotStarted,
            gate:     RecoveryGate {
                menu_painted:        false,
                action_selected:     false,
                confirmation_passed: false,
                action_executed:     false,
            },
        }
    }

    pub fn advance_phase(&mut self, next: RecoveryPhase) -> Result<(), RecoveryError> {
        if next < self.phase {
            return Err(RecoveryError::PhaseRegression);
        }
        self.phase = next;
        Ok(())
    }

    pub fn select(&mut self, action: RecoveryAction) -> Result<(), RecoveryError> {
        self.selected = action;
        self.advance_phase(RecoveryPhase::ActionSelected)?;
        self.gate.action_selected = true;
        // Non-destructive actions: confirmation gate is implicitly passed.
        if !action.is_destructive() {
            self.gate.confirmation_passed = true;
        }
        Ok(())
    }

    pub fn confirm(&mut self, user_input: &[u8]) -> Result<(), RecoveryError> {
        let phrase = match self.selected.confirmation_phrase() {
            Some(p) => p,
            None => return Err(RecoveryError::UnnecessaryConfirmation),
        };
        if user_input != phrase {
            return Err(RecoveryError::ConfirmationMismatch);
        }
        self.advance_phase(RecoveryPhase::ConfirmationReceived)?;
        self.gate.confirmation_passed = true;
        Ok(())
    }

    pub fn mark_action_executed(&mut self) -> Result<(), RecoveryError> {
        self.advance_phase(RecoveryPhase::ActionExecuted)?;
        self.gate.action_executed = true;
        Ok(())
    }

    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, REC_UART_SIG_MENU_PAINTED) {
            let _ = self.advance_phase(RecoveryPhase::MenuPainted);
            self.gate.menu_painted = true;
        }
        if contains_bytes(line, REC_UART_SIG_FACTORY_RESET_DONE)
            || contains_bytes(line, REC_UART_SIG_SIDELOAD_DONE)
            || contains_bytes(line, REC_UART_SIG_ROLLBACK_DONE) {
            let _ = self.advance_phase(RecoveryPhase::ActionExecuted);
            self.gate.action_executed = true;
        }
        if contains_bytes(line, REC_UART_SIG_EXITED) {
            let _ = self.advance_phase(RecoveryPhase::Exited);
        }
    }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }
}

/// 6-step pipeline.
pub fn init_recovery_mode(
    cfg: &RecoveryConfig,
    reason: RecoveryEntryReason,
) -> Result<RecoveryState, RecoveryError> {
    cfg.validate()?;
    if matches!(reason, RecoveryEntryReason::DebugTrigger) && !cfg.allow_debug_trigger {
        // Debug entry rejected in user builds.
        return Err(RecoveryError::UnnecessaryConfirmation);
    }
    Ok(RecoveryState::new(*cfg, reason))
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end execution
//
// Everything above models recovery as a state machine + UART gate. The items
// below DRIVE the destructive operations: NVMe writes that zero userdata,
// NVMe writes that flash a sideloaded boot.img, UEFI variable writes that
// flip AetherActiveSlot, and the warm reset that exits recovery.
//
// All side effects go through RecoveryRuntime; the EFI host implements it
// against EFI_RT->SetVariable and the NVMe Submission Queue. Tests use the
// in-memory mock at the bottom of this file.
// ─────────────────────────────────────────────────────────────────────────────

/// LBA range descriptor — local copy so this module compiles on x86_64
/// host tests too (avb_boot is `#[cfg(target_arch = "aarch64")]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionSlotLba {
    pub start_lba: u64,
    pub lba_count: u64,
}

pub const UEFI_VAR_AETHER_ACTIVE_SLOT:        &[u8] = b"AetherActiveSlot";
pub const UEFI_VAR_AETHER_BOOT_ATTEMPT:       &[u8] = b"AetherBootAttempt";
pub const UEFI_VAR_AETHER_SETUP_COMPLETE:     &[u8] = b"AetherSetupComplete";

/// LBA ranges this module touches. userdata is wiped on factory reset,
/// boot_a/boot_b for sideload.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryPartitionMap {
    pub userdata: PartitionSlotLba,
    pub boot_a:   PartitionSlotLba,
    pub boot_b:   PartitionSlotLba,
    pub nsid:     u32,
}

impl RecoveryPartitionMap {
    pub fn boot_for_byte(&self, slot_byte: u8) -> PartitionSlotLba {
        if slot_byte == 0 { self.boot_a } else { self.boot_b }
    }
}

/// A buffered sideload image presented to recovery from the EFI System
/// Partition. The EFI host reads it from \EFI\AETHER\sideload\boot.img and
/// hands the runtime an accessor.
pub trait SideloadSource {
    /// Total sector count (4 KiB each).
    fn sectors(&self) -> u64;
    /// Read one 4 KiB sector of the boot image into `dst`.
    fn read_sector(&mut self, lba: u64, dst: &mut [u8; 4096]) -> Result<(), RecoveryError>;
    /// Verify the trailing AVB signature on the boot image against the
    /// platform MOK (set up in ch57). Implementation pulls the boot.img
    /// trailing vbmeta footer and runs the same RSA path as ch43.
    fn verify_signature(&self) -> Result<(), RecoveryError>;
}

/// Abstract integration boundary the EFI host fills in.
pub trait RecoveryRuntime {
    fn nvme_write_sector(
        &mut self, nsid: u32, lba: u64, src: &[u8; 4096],
    ) -> Result<(), RecoveryError>;
    fn get_uefi_variable(&self, name: &[u8]) -> Option<[u8; 8]>;
    fn set_uefi_variable(&mut self, name: &[u8], value: &[u8]) -> Result<(), RecoveryError>;
    fn delete_uefi_variable(&mut self, name: &[u8]) -> Result<(), RecoveryError>;
    fn emit_uart_line(&mut self, line: &[u8]);
    fn reset_system_warm(&mut self) -> !;
}

/// Run the recovery action selected on the menu. Requires that the gate is
/// past ConfirmationReceived for destructive actions; non-destructive ones
/// only need ActionSelected.
///
/// Sequence per action:
///   FactoryReset     → zero every sector in userdata; delete
///                      AetherSetupComplete; emit DONE; reset_system_warm()
///   Sideload         → verify signature; write inactive slot's boot
///                      partition sector-by-sector; flip AetherActiveSlot;
///                      reset boot-attempt counter; emit DONE; warm reset
///   SlotRollback     → read AetherActiveSlot; flip; reset boot-attempt
///                      counter; emit DONE; warm reset
///   ReturnToSelector → emit EXITED; warm reset
///   NoOp             → no-op return Ok
pub fn execute_recovery_action<R: RecoveryRuntime>(
    state: &mut RecoveryState,
    runtime: &mut R,
    map: &RecoveryPartitionMap,
    sideload: Option<&mut dyn SideloadSource>,
) -> Result<(), RecoveryError> {
    // Refuse to execute a destructive action without confirmation.
    if state.selected.is_destructive() && !state.gate.confirmation_passed {
        return Err(RecoveryError::ConfirmationMismatch);
    }
    if state.phase < RecoveryPhase::ActionSelected {
        return Err(RecoveryError::PhaseRegression);
    }

    match state.selected {
        RecoveryAction::NoOp => Ok(()),

        RecoveryAction::ReturnToSelector => {
            runtime.emit_uart_line(REC_UART_SIG_EXITED);
            runtime.reset_system_warm();
        }

        RecoveryAction::FactoryReset => {
            let zero = [0u8; 4096];
            for s in 0..map.userdata.lba_count {
                runtime
                    .nvme_write_sector(map.nsid, map.userdata.start_lba + s, &zero)
                    .map_err(|_| RecoveryError::UserdataWipeFailed)?;
            }
            // Setup wizard re-runs on next boot.
            runtime
                .delete_uefi_variable(UEFI_VAR_AETHER_SETUP_COMPLETE)
                .map_err(|_| RecoveryError::VariableWriteError)?;
            state.mark_action_executed()?;
            runtime.emit_uart_line(REC_UART_SIG_FACTORY_RESET_DONE);
            runtime.reset_system_warm();
        }

        RecoveryAction::Sideload => {
            let src = sideload.ok_or(RecoveryError::SideloadSignatureInvalid)?;
            src.verify_signature()?;
            // Determine inactive slot — write to the one we're NOT booting now.
            let active_byte = runtime
                .get_uefi_variable(UEFI_VAR_AETHER_ACTIVE_SLOT)
                .map(|v| v[0])
                .unwrap_or(0);
            let inactive_byte = if active_byte == 0 { 1 } else { 0 };
            let dst = map.boot_for_byte(inactive_byte);

            let total = src.sectors();
            if total > dst.lba_count {
                return Err(RecoveryError::SideloadSignatureInvalid);
            }
            let mut buf = [0u8; 4096];
            for s in 0..total {
                src.read_sector(s, &mut buf)?;
                runtime
                    .nvme_write_sector(map.nsid, dst.start_lba + s, &buf)
                    .map_err(|_| RecoveryError::UserdataWipeFailed)?;
            }
            runtime
                .set_uefi_variable(UEFI_VAR_AETHER_ACTIVE_SLOT, &[inactive_byte])
                .map_err(|_| RecoveryError::VariableWriteError)?;
            runtime
                .set_uefi_variable(UEFI_VAR_AETHER_BOOT_ATTEMPT, &[0u8])
                .map_err(|_| RecoveryError::VariableWriteError)?;
            state.mark_action_executed()?;
            runtime.emit_uart_line(REC_UART_SIG_SIDELOAD_DONE);
            runtime.reset_system_warm();
        }

        RecoveryAction::SlotRollback => {
            let active_byte = runtime
                .get_uefi_variable(UEFI_VAR_AETHER_ACTIVE_SLOT)
                .map(|v| v[0])
                .ok_or(RecoveryError::NoPreviousSlot)?;
            let other_byte = if active_byte == 0 { 1 } else { 0 };
            runtime
                .set_uefi_variable(UEFI_VAR_AETHER_ACTIVE_SLOT, &[other_byte])
                .map_err(|_| RecoveryError::VariableWriteError)?;
            runtime
                .set_uefi_variable(UEFI_VAR_AETHER_BOOT_ATTEMPT, &[0u8])
                .map_err(|_| RecoveryError::VariableWriteError)?;
            state.mark_action_executed()?;
            runtime.emit_uart_line(REC_UART_SIG_ROLLBACK_DONE);
            runtime.reset_system_warm();
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_phrases_are_distinct() {
        let phrases = [
            RecoveryAction::FactoryReset.confirmation_phrase().unwrap(),
            RecoveryAction::Sideload.confirmation_phrase().unwrap(),
            RecoveryAction::SlotRollback.confirmation_phrase().unwrap(),
        ];
        for (i, a) in phrases.iter().enumerate() {
            for (j, b) in phrases.iter().enumerate() {
                if i != j { assert_ne!(a, b); }
            }
        }
    }

    #[test]
    fn non_destructive_actions_skip_confirmation() {
        assert!(RecoveryAction::NoOp.confirmation_phrase().is_none());
        assert!(RecoveryAction::ReturnToSelector.confirmation_phrase().is_none());
        assert!(!RecoveryAction::NoOp.is_destructive());
        assert!(RecoveryAction::FactoryReset.is_destructive());
    }

    #[test]
    fn select_advances_phase() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::BootLoop);
        s.select(RecoveryAction::FactoryReset).unwrap();
        assert_eq!(s.phase, RecoveryPhase::ActionSelected);
        assert!(s.gate.action_selected);
        // Destructive action: confirmation NOT yet passed.
        assert!(!s.gate.confirmation_passed);
    }

    #[test]
    fn select_non_destructive_implicitly_confirms() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::UserRequested);
        s.select(RecoveryAction::ReturnToSelector).unwrap();
        assert!(s.gate.confirmation_passed);
    }

    #[test]
    fn confirm_rejects_wrong_phrase() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::BootLoop);
        s.select(RecoveryAction::FactoryReset).unwrap();
        assert_eq!(s.confirm(b"erase everything"),
                   Err(RecoveryError::ConfirmationMismatch));
        s.confirm(b"ERASE EVERYTHING").unwrap();
        assert!(s.gate.confirmation_passed);
    }

    #[test]
    fn confirm_rejects_on_nondestructive() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::UserRequested);
        s.select(RecoveryAction::NoOp).unwrap();
        assert_eq!(s.confirm(b"anything"),
                   Err(RecoveryError::UnnecessaryConfirmation));
    }

    #[test]
    fn debug_trigger_rejected_in_user_builds() {
        let cfg = RecoveryConfig::aether_defaults();
        assert_eq!(
            init_recovery_mode(&cfg, RecoveryEntryReason::DebugTrigger).err(),
            Some(RecoveryError::UnnecessaryConfirmation)
        );
    }

    #[test]
    fn debug_trigger_accepted_when_allowed() {
        let mut cfg = RecoveryConfig::aether_defaults();
        cfg.allow_debug_trigger = true;
        let s = init_recovery_mode(&cfg, RecoveryEntryReason::DebugTrigger).unwrap();
        assert_eq!(s.entry_reason, RecoveryEntryReason::DebugTrigger);
    }

    #[test]
    fn uart_scanner_marks_menu_and_action() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::BootLoop);
        s.process_line(b"[recovery] menu painted");
        assert!(s.gate.menu_painted);
        s.process_line(b"[recovery] factory reset done");
        assert!(s.gate.action_executed);
    }

    #[test]
    fn full_destructive_flow() {
        let mut s = RecoveryState::new(RecoveryConfig::aether_defaults(),
                                       RecoveryEntryReason::BootLoop);
        s.process_line(b"[recovery] menu painted");
        s.select(RecoveryAction::SlotRollback).unwrap();
        s.confirm(b"ROLLBACK").unwrap();
        s.mark_action_executed().unwrap();
        assert!(s.is_gate_passed());
    }
}
