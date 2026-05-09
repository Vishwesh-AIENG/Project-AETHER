// ch16: USB And Input Routing
//
// USB is partitioned at the controller level, not the device level.
//
// A laptop carries multiple xHCI (eXtensible Host Controller Interface)
// controllers on its PCIe bus — typically:
//   • One for the integrated keyboard and trackpad
//   • One or more for external USB-A ports
//   • One or more for USB-C / Thunderbolt ports
//
// AETHER assigns each controller exclusively to one guest at boot. A device
// plugged into a port managed by the Android-assigned controller is visible
// to Android only; Windows has no visibility into that controller's DMA or
// interrupts. Isolation is enforced through the SMMU (same pipeline as
// ch11 passthrough) — the controller's DMA is constrained to the owning
// guest's memory region, and interrupts are routed only to the owning guest's
// cores.
//
// ── Integrated Input Device Problem ──────────────────────────────────────────
//
// The laptop has exactly one physical keyboard and one trackpad. Statically
// assigning them to one guest leaves the other guest without keyboard input.
// AETHER's solution is a cross-partition input switching mechanism:
//
//   1. AETHER intercepts raw HID reports from the integrated input controller
//      before they reach any guest. This interception happens below the guest
//      input subsystem — guests never see the intercept layer.
//
//   2. When a specific hardware key combination (e.g., Ctrl+Alt+Tab) is
//      detected in the raw HID stream, AETHER:
//        a. Consumes the triggering key events (neither guest receives them)
//        b. Issues an xHCI controller reset (clears the previous guest's
//           Transfer Request Block rings and doorbell state)
//        c. Reassigns the controller's SMMU STE to the new guest's VMID
//        d. Re-routes the controller's interrupts to the new guest's cores
//        e. Updates CurrentInputOwner
//
//   3. The switch is hardware-only: no hypercall, no MMIO write, no software
//      path can trigger it. A guest cannot steal input focus from the other
//      guest programmatically. This is the primary security requirement for
//      the switching mechanism.
//
//   4. The reset step (b) is mandatory. Skipping it leaves the previous guest's
//      TRB rings programmed in the controller — the new guest's USB driver
//      would encounter unexpected ring state and typically panic or deadlock.
//
// ── Embedded Controller (EC) Path ────────────────────────────────────────────
//
// On some ARM laptops the keyboard and trackpad bypass xHCI entirely and
// connect through an Embedded Controller on an I2C or SPI bus. In this case
// the InputPath enum records EmbeddedController and xHCI passthrough is not
// used for integrated input. EC-path interception is handled at the EC
// communication layer (platform-specific, left for production integration).
//
// ── xHCI Architecture Reference ──────────────────────────────────────────────
//
// xHCI Specification (Intel, available at intel.com):
//   §4  Host Controller Model — capability registers, operational registers
//   §5  Operational Model — Transfer Request Blocks (TRBs), doorbell array
//   §6  Register Interface — MMIO register layout
//
// Key xHCI concepts used here:
//   USBCMD.HCRST (bit 1): Host Controller Reset — software reset of the
//     entire controller, clears all TRB ring state, all port state, and
//     resets the controller to a known initial state. Must be issued and
//     completed (USBCMD.HCRST reads back 0) before the new guest's driver
//     initialises the controller.
//
//   SMMU STE update: after reset, the controller's SMMU stream table entry
//     is rewritten with the new guest's VMID Stage 2 base. The old STE is
//     cleared first (word 0 zeroed) with a DSB before the new STE is written.
//
// References:
//   xHCI Specification 1.2 — intel.com
//   USB 3.2 Specification — usb.org
//   USB HID Class Specification 1.11 — usb.org
//   linux-ref/drivers/usb/host/xhci.c — Linux xHCI host driver
//   linux-ref/drivers/hid/usbhid/     — USB HID event processing
//   linux-ref/drivers/input/          — Linux input subsystem

use crate::partition::GuestId;
use crate::passthrough::PcieAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    /// Controller is already assigned to a guest; re-assignment requires an
    /// explicit switch (input controllers) or is forbidden (external controllers).
    ControllerAlreadyAssigned,
    /// The specified controller is not in the registry.
    ControllerNotFound,
    /// Registry is at capacity (MAX_USB_CONTROLLERS reached).
    RegistryFull,
    /// An input switch was attempted but no integrated input controller is
    /// configured. Cannot switch without a designated input controller.
    NoInputController,
    /// An input switch cannot be triggered via software. Physical key combination
    /// only. This error is returned whenever a guest attempts a switch via hypercall.
    SoftwareSwitchForbidden,
    /// xHCI reset did not complete within the polling budget.
    /// The controller may be stuck; the switch is aborted.
    ResetTimeout,
    /// Integrated input controller has no SMMU STE configured.
    /// The controller must be configured with SMMU isolation before switching.
    SmmuNotConfigured,
}

// ─────────────────────────────────────────────────────────────────────────────
// USB controller classification
//
// AETHER classifies each xHCI controller by its physical role at boot time.
// The classification informs assignment policy:
//   - Integrated: may be reassigned via input switching; requires EC-path check
//   - External*: assigned once at boot; never reassigned
// ─────────────────────────────────────────────────────────────────────────────

/// Physical role of an xHCI controller in the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbControllerKind {
    /// Controller for the integrated keyboard and trackpad.
    /// Subject to cross-partition input switching.
    IntegratedInput,
    /// Controller for external USB-A ports (e.g., USB-A 3.2 Gen 1/2).
    ExternalUsbA,
    /// Controller for USB-C / Thunderbolt ports.
    ExternalUsbC,
    /// Internal hub or bridge controller (e.g., a PCIe-to-USB bridge).
    Bridge,
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical path for integrated input
//
// On most ARM laptops the keyboard and trackpad appear as USB HID devices
// under the xHCI controller. On some platforms they connect through an
// Embedded Controller (EC) on an I2C or SPI bus. The path determines which
// interception layer AETHER uses for the input switching mechanism.
// ─────────────────────────────────────────────────────────────────────────────

/// How the integrated keyboard and trackpad connect to the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPath {
    /// Keyboard and trackpad appear as USB HID devices under an xHCI controller.
    /// AETHER intercepts raw HID reports from the controller's interrupt endpoint.
    UsbHid,
    /// Keyboard and trackpad connect through an Embedded Controller on I2C/SPI.
    /// xHCI passthrough is not used for integrated input in this case.
    /// EC-path interception is platform-specific and handled separately.
    EmbeddedController,
}

// ─────────────────────────────────────────────────────────────────────────────
// Input switch trigger
//
// Describes the hardware key combination that activates cross-partition input
// switching. This is a description only — the actual interception is performed
// by AETHER's HID report parser running below any guest-visible layer.
//
// SECURITY INVARIANT: this trigger can only be produced by physical key presses
// detected in raw HID reports. It is never reachable via hypercall, MMIO write,
// or any guest software path. Any guest attempt to trigger a switch returns
// SoftwareSwitchForbidden.
// ─────────────────────────────────────────────────────────────────────────────

/// The hardware key combination that triggers an input controller switch.
///
/// Default: Ctrl + Alt + Tab (all three physically held simultaneously).
/// This combination is unlikely to be pressed accidentally and is not used
/// by standard Android or Windows keyboard shortcuts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputSwitchTrigger {
    /// USB HID usage code for the primary modifier (default: Left Ctrl = 0xE0).
    pub modifier_a: u8,
    /// USB HID usage code for the secondary modifier (default: Left Alt = 0xE2).
    pub modifier_b: u8,
    /// USB HID usage code for the action key (default: Tab = 0x2B).
    pub action_key: u8,
}

impl InputSwitchTrigger {
    /// Default trigger: Left Ctrl (0xE0) + Left Alt (0xE2) + Tab (0x2B).
    ///
    /// HID usage codes from USB HID Usage Tables 1.5, §10 (Keyboard/Keypad Page).
    pub const DEFAULT: Self = Self {
        modifier_a: 0xE0, // Left Control
        modifier_b: 0xE2, // Left Alt
        action_key: 0x2B, // Tab
    };

    /// Check whether a raw HID keyboard report matches this trigger.
    ///
    /// A standard USB HID keyboard boot protocol report is 8 bytes:
    ///   Byte 0: modifier bitmap (bit 0=LCtrl, bit 1=LShift, bit 2=LAlt, ...)
    ///   Byte 1: reserved (0x00)
    ///   Bytes 2–7: up to 6 simultaneously pressed keycodes
    ///
    /// The modifier byte bit layout (USB HID §10):
    ///   bit 0 → Left Control  (usage 0xE0)
    ///   bit 1 → Left Shift    (usage 0xE1)
    ///   bit 2 → Left Alt      (usage 0xE2)
    ///   bit 3 → Left GUI
    ///   bit 4 → Right Control (usage 0xE4)
    ///   bit 5 → Right Shift
    ///   bit 6 → Right Alt
    ///   bit 7 → Right GUI
    pub fn matches_hid_report(&self, report: &[u8; 8]) -> bool {
        let modifiers = report[0];
        let keys = &report[2..8];

        // Translate usage codes for modifier_a and modifier_b into bitmap bits.
        let bit_a = Self::modifier_usage_to_bit(self.modifier_a);
        let bit_b = Self::modifier_usage_to_bit(self.modifier_b);

        let modifiers_match = match (bit_a, bit_b) {
            (Some(a), Some(b)) => (modifiers & (a | b)) == (a | b),
            _ => false,
        };

        let action_present = keys.iter().any(|&k| k == self.action_key);

        modifiers_match && action_present
    }

    /// Convert a modifier usage code (0xE0–0xE7) to its HID report bitmap bit.
    fn modifier_usage_to_bit(usage: u8) -> Option<u8> {
        match usage {
            0xE0 => Some(1 << 0), // Left Control
            0xE1 => Some(1 << 1), // Left Shift
            0xE2 => Some(1 << 2), // Left Alt
            0xE3 => Some(1 << 3), // Left GUI
            0xE4 => Some(1 << 4), // Right Control
            0xE5 => Some(1 << 5), // Right Shift
            0xE6 => Some(1 << 6), // Right Alt
            0xE7 => Some(1 << 7), // Right GUI
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// xHCI reset state
//
// Tracks whether a controller reset is required before the next guest can
// use the integrated input controller. Reset is always required after a switch
// to prevent the previous guest's TRB ring state from being inherited.
// ─────────────────────────────────────────────────────────────────────────────

/// Reset state of an xHCI controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhciResetState {
    /// Controller has been reset and is in a clean initial state.
    /// Safe for the new guest's driver to initialize.
    Clean,
    /// Controller has not been reset since the last guest used it.
    /// Must be reset before reassigning to a new guest.
    PendingReset,
}

// ─────────────────────────────────────────────────────────────────────────────
// USB controller descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Describes one xHCI controller in the system.
#[derive(Clone, Copy, Debug)]
pub struct UsbController {
    /// PCIe BUS:DEV:FUNC address of the xHCI controller.
    pub addr: PcieAddr,
    /// Physical role of this controller.
    pub kind: UsbControllerKind,
    /// Guest currently assigned this controller.
    pub assigned_guest: GuestId,
    /// Reset state — must be `Clean` before the assigned guest can use it.
    pub reset_state: XhciResetState,
    /// True if this controller's SMMU STE has been configured in translated mode.
    /// An xHCI controller with Bypass STE defeats DMA isolation entirely.
    pub smmu_configured: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Input switch state
//
// Tracks the live state of the cross-partition input switching mechanism.
// There is exactly one integrated input controller per system; its current
// owner can change at runtime via hardware trigger only.
// ─────────────────────────────────────────────────────────────────────────────

/// Live state of the cross-partition input switch.
#[derive(Clone, Copy, Debug)]
pub struct InputSwitchState {
    /// Key combination that triggers a switch.
    pub trigger: InputSwitchTrigger,
    /// Which guest currently receives integrated keyboard and trackpad input.
    pub current_owner: GuestId,
    /// Physical path for the integrated input (USB HID or Embedded Controller).
    pub input_path: InputPath,
    /// How many times the switch has fired since boot (diagnostic counter).
    pub switch_count: u32,
}

impl InputSwitchState {
    pub const fn new(initial_owner: GuestId, input_path: InputPath) -> Self {
        Self {
            trigger: InputSwitchTrigger::DEFAULT,
            current_owner: initial_owner,
            input_path,
            switch_count: 0,
        }
    }

    /// The guest that is NOT the current owner (will receive input after a switch).
    pub fn next_owner(&self) -> GuestId {
        match self.current_owner {
            GuestId::Android => GuestId::Windows,
            GuestId::Windows => GuestId::Android,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB partition registry
// ─────────────────────────────────────────────────────────────────────────────

const MAX_USB_CONTROLLERS: usize = 8;

/// Registry of xHCI controllers and their guest assignments.
#[derive(Debug)]
pub struct UsbPartitionRegistry {
    controllers: [Option<UsbController>; MAX_USB_CONTROLLERS],
    count: usize,
}

impl UsbPartitionRegistry {
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_USB_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a controller with its initial guest assignment.
    pub fn register(&mut self, ctrl: UsbController) -> Result<(), UsbError> {
        if self.count >= MAX_USB_CONTROLLERS {
            return Err(UsbError::RegistryFull);
        }
        // Duplicate address check.
        for existing in self.controllers.iter().flatten() {
            if existing.addr == ctrl.addr {
                return Err(UsbError::ControllerAlreadyAssigned);
            }
        }
        self.controllers[self.count] = Some(ctrl);
        self.count += 1;
        Ok(())
    }

    /// Query which guest owns a controller.
    pub fn owner(&self, addr: PcieAddr) -> Option<GuestId> {
        self.controllers
            .iter()
            .flatten()
            .find(|c| c.addr == addr)
            .map(|c| c.assigned_guest)
    }

    /// Look up a controller by address (immutable).
    pub fn get(&self, addr: PcieAddr) -> Option<&UsbController> {
        self.controllers.iter().flatten().find(|c| c.addr == addr)
    }

    /// Look up a controller by address (mutable).
    fn get_mut(&mut self, addr: PcieAddr) -> Option<&mut UsbController> {
        self.controllers
            .iter_mut()
            .flatten()
            .find(|c| c.addr == addr)
    }

    /// Mark a controller as having a clean xHCI reset applied.
    pub fn mark_reset_clean(&mut self, addr: PcieAddr) -> Result<(), UsbError> {
        let ctrl = self.get_mut(addr).ok_or(UsbError::ControllerNotFound)?;
        ctrl.reset_state = XhciResetState::Clean;
        Ok(())
    }

    /// Mark a controller as needing a reset (e.g., after a guest uses it).
    pub fn mark_reset_pending(&mut self, addr: PcieAddr) -> Result<(), UsbError> {
        let ctrl = self.get_mut(addr).ok_or(UsbError::ControllerNotFound)?;
        ctrl.reset_state = XhciResetState::PendingReset;
        Ok(())
    }

    /// Update the SMMU configuration flag for a controller.
    pub fn mark_smmu_configured(&mut self, addr: PcieAddr) -> Result<(), UsbError> {
        let ctrl = self.get_mut(addr).ok_or(UsbError::ControllerNotFound)?;
        ctrl.smmu_configured = true;
        Ok(())
    }

    /// Count of registered controllers.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Find the IntegratedInput controller, if registered.
    pub fn integrated_input_addr(&self) -> Option<PcieAddr> {
        self.controllers
            .iter()
            .flatten()
            .find(|c| c.kind == UsbControllerKind::IntegratedInput)
            .map(|c| c.addr)
    }
}

impl Default for UsbPartitionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB partition state — top-level
//
// Boot-time sequence:
//   1. register_controller()       — record each xHCI controller and its guest
//   2. mark_smmu_configured()      — after SMMU STE is written in translated mode
//   3. mark_reset_clean()          — after initial xHCI reset at boot
//   4. configure_input_switch()    — set up the input switching mechanism
//      (only if an IntegratedInput controller is present)
//
// Runtime (input switch):
//   5. process_hid_report()        — AETHER calls this for every raw HID report
//                                    from the integrated keyboard. Returns
//                                    HidAction::Switch when the trigger fires.
//   6. execute_switch()            — called by the exception handler after
//                                    HidAction::Switch is returned.
//                                    Never called from guest code.
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level USB partitioning state.
pub struct UsbPartitionState {
    /// Registry of all xHCI controllers.
    pub registry: UsbPartitionRegistry,
    /// Input switching state (None if no IntegratedInput controller registered).
    pub input_switch: Option<InputSwitchState>,
}

impl UsbPartitionState {
    pub const fn new() -> Self {
        Self {
            registry: UsbPartitionRegistry::new(),
            input_switch: None,
        }
    }

    /// Register an xHCI controller and assign it to a guest.
    pub fn register_controller(&mut self, ctrl: UsbController) -> Result<(), UsbError> {
        self.registry.register(ctrl)
    }

    /// Configure the cross-partition input switching mechanism.
    ///
    /// Must be called after the IntegratedInput controller is registered.
    /// `initial_owner` is the guest that starts with keyboard/trackpad focus.
    pub fn configure_input_switch(
        &mut self,
        initial_owner: GuestId,
        input_path: InputPath,
    ) -> Result<(), UsbError> {
        // Verify there is an IntegratedInput controller to switch.
        if self.registry.integrated_input_addr().is_none() {
            return Err(UsbError::NoInputController);
        }
        self.input_switch = Some(InputSwitchState::new(initial_owner, input_path));
        Ok(())
    }

    /// Process a raw 8-byte USB HID keyboard boot-protocol report.
    ///
    /// Returns the action AETHER should take for this report.
    ///
    /// Called from AETHER's xHCI interrupt handler for every keyboard interrupt
    /// transfer on the integrated input controller. This runs at EL2, below any
    /// guest-visible layer. Guests never see this call.
    pub fn process_hid_report(&mut self, report: &[u8; 8]) -> HidAction {
        let switch = match self.input_switch.as_ref() {
            Some(s) => s,
            None => return HidAction::Forward,
        };

        if switch.trigger.matches_hid_report(report) {
            HidAction::Switch
        } else {
            HidAction::Forward
        }
    }

    /// Execute a cross-partition input switch.
    ///
    /// This is called ONLY from AETHER's exception handler after
    /// `process_hid_report` returns `HidAction::Switch`. It must never
    /// be reachable via a guest hypercall.
    ///
    /// Sequence:
    ///   1. Locate the integrated input controller.
    ///   2. Verify SMMU is configured (abort if not — safety gate).
    ///   3. Mark controller as PendingReset (the caller must issue xHCI HCRST).
    ///   4. Transfer ownership to the other guest in both the registry and
    ///      the input switch state.
    ///   5. Increment the switch counter.
    ///
    /// In production, after this call returns, the caller:
    ///   - Writes USBCMD.HCRST = 1 via the controller's MMIO base
    ///   - Polls until USBCMD.HCRST reads back 0 (controller ready)
    ///   - Calls mark_reset_clean() on the registry
    ///   - Updates the SMMU STE for the new guest's VMID
    ///   - Re-routes the controller's interrupt to the new guest's cores
    pub fn execute_switch(&mut self) -> Result<SwitchResult, UsbError> {
        let addr = self
            .registry
            .integrated_input_addr()
            .ok_or(UsbError::NoInputController)?;

        // Safety gate: SMMU must be configured.
        {
            let ctrl = self.registry.get(addr).ok_or(UsbError::ControllerNotFound)?;
            if !ctrl.smmu_configured {
                return Err(UsbError::SmmuNotConfigured);
            }
        }

        // Mark the controller as needing reset before the new guest uses it.
        self.registry.mark_reset_pending(addr)?;

        // Transfer ownership.
        let switch = self.input_switch.as_mut().ok_or(UsbError::NoInputController)?;
        let new_owner = switch.next_owner();
        let old_owner = switch.current_owner;
        switch.current_owner = new_owner;
        switch.switch_count += 1;

        // Update the registry entry's assigned_guest.
        if let Some(ctrl) = self.registry.get_mut(addr) {
            ctrl.assigned_guest = new_owner;
        }

        Ok(SwitchResult { old_owner, new_owner })
    }

    /// Reject a software-triggered switch attempt from a guest hypercall.
    ///
    /// Called from the HVC/SMC dispatcher when a guest issues an input-switch
    /// hypercall. Always returns SoftwareSwitchForbidden — the trigger is
    /// hardware-only.
    pub fn reject_software_switch(&self) -> UsbError {
        UsbError::SoftwareSwitchForbidden
    }

    /// Query the current input owner.
    pub fn current_input_owner(&self) -> Option<GuestId> {
        self.input_switch.as_ref().map(|s| s.current_owner)
    }

    /// Count of input switches since boot.
    pub fn switch_count(&self) -> u32 {
        self.input_switch.as_ref().map_or(0, |s| s.switch_count)
    }
}

impl Default for UsbPartitionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Action returned by `process_hid_report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidAction {
    /// Forward the HID report to the current input owner guest.
    Forward,
    /// Consume the report (do not forward) and execute an input switch.
    /// The triggering key events are never delivered to either guest.
    Switch,
}

/// Result of a successful `execute_switch` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchResult {
    /// Guest that previously owned the integrated input.
    pub old_owner: GuestId,
    /// Guest that now owns the integrated input.
    pub new_owner: GuestId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── InputSwitchTrigger — HID report matching ───────────────────────────────

    /// Build an 8-byte HID keyboard boot-protocol report.
    /// modifier_byte: bit field per USB HID §10.
    /// keys: up to 6 key usage codes in bytes 2–7.
    fn hid_report(modifier_byte: u8, keys: &[u8]) -> [u8; 8] {
        let mut report = [0u8; 8];
        report[0] = modifier_byte;
        for (i, &k) in keys.iter().enumerate().take(6) {
            report[2 + i] = k;
        }
        report
    }

    #[test]
    fn test_trigger_default_matches_ctrl_alt_tab() {
        let trigger = InputSwitchTrigger::DEFAULT;
        // Left Ctrl (bit 0) + Left Alt (bit 2) = 0b00000101 = 0x05
        let report = hid_report(0x05, &[0x2B]); // Tab key
        assert!(trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_trigger_missing_modifier_no_match() {
        let trigger = InputSwitchTrigger::DEFAULT;
        // Only Left Ctrl, no Alt.
        let report = hid_report(0x01, &[0x2B]);
        assert!(!trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_trigger_missing_action_key_no_match() {
        let trigger = InputSwitchTrigger::DEFAULT;
        // Both modifiers but no Tab key.
        let report = hid_report(0x05, &[0x04]); // 'A' instead of Tab
        assert!(!trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_trigger_empty_report_no_match() {
        let trigger = InputSwitchTrigger::DEFAULT;
        let report = hid_report(0x00, &[]);
        assert!(!trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_trigger_extra_keys_still_matches() {
        let trigger = InputSwitchTrigger::DEFAULT;
        // Ctrl+Alt+Tab plus another key — still a match.
        let report = hid_report(0x05, &[0x2B, 0x04]);
        assert!(trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_custom_trigger() {
        let trigger = InputSwitchTrigger {
            modifier_a: 0xE0, // Left Ctrl
            modifier_b: 0xE4, // Right Ctrl
            action_key: 0x3A, // F1
        };
        // Left Ctrl (bit 0) + Right Ctrl (bit 4) = 0b00010001 = 0x11
        let report = hid_report(0x11, &[0x3A]);
        assert!(trigger.matches_hid_report(&report));
    }

    #[test]
    fn test_modifier_bit_mapping() {
        assert_eq!(InputSwitchTrigger::modifier_usage_to_bit(0xE0), Some(0x01));
        assert_eq!(InputSwitchTrigger::modifier_usage_to_bit(0xE2), Some(0x04));
        assert_eq!(InputSwitchTrigger::modifier_usage_to_bit(0xE7), Some(0x80));
        assert_eq!(InputSwitchTrigger::modifier_usage_to_bit(0x2B), None);
    }

    // ── InputSwitchState ──────────────────────────────────────────────────────

    #[test]
    fn test_next_owner_flips() {
        let state = InputSwitchState::new(GuestId::Android, InputPath::UsbHid);
        assert_eq!(state.next_owner(), GuestId::Windows);

        let state2 = InputSwitchState::new(GuestId::Windows, InputPath::UsbHid);
        assert_eq!(state2.next_owner(), GuestId::Android);
    }

    // ── UsbPartitionRegistry ──────────────────────────────────────────────────

    fn make_ctrl(bus: u8, dev: u8, func: u8, kind: UsbControllerKind, guest: GuestId) -> UsbController {
        UsbController {
            addr: PcieAddr::new(bus, dev, func),
            kind,
            assigned_guest: guest,
            reset_state: XhciResetState::PendingReset,
            smmu_configured: false,
        }
    }

    #[test]
    fn test_registry_register_and_query() {
        let mut reg = UsbPartitionRegistry::new();
        let ctrl = make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android);
        reg.register(ctrl).unwrap();
        assert_eq!(reg.owner(PcieAddr::new(0, 0, 0)), Some(GuestId::Android));
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_registry_duplicate_addr_rejected() {
        let mut reg = UsbPartitionRegistry::new();
        let c1 = make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android);
        let c2 = make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbC, GuestId::Windows);
        reg.register(c1).unwrap();
        assert_eq!(reg.register(c2), Err(UsbError::ControllerAlreadyAssigned));
    }

    #[test]
    fn test_registry_integrated_input_addr() {
        let mut reg = UsbPartitionRegistry::new();
        reg.register(make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android)).unwrap();
        assert_eq!(reg.integrated_input_addr(), None);
        reg.register(make_ctrl(0, 1, 0, UsbControllerKind::IntegratedInput, GuestId::Android)).unwrap();
        assert_eq!(reg.integrated_input_addr(), Some(PcieAddr::new(0, 1, 0)));
    }

    #[test]
    fn test_registry_mark_reset_clean() {
        let mut reg = UsbPartitionRegistry::new();
        let ctrl = make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android);
        reg.register(ctrl).unwrap();
        reg.mark_reset_clean(PcieAddr::new(0, 0, 0)).unwrap();
        assert_eq!(reg.get(PcieAddr::new(0, 0, 0)).unwrap().reset_state, XhciResetState::Clean);
    }

    #[test]
    fn test_registry_mark_smmu_configured() {
        let mut reg = UsbPartitionRegistry::new();
        let ctrl = make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android);
        reg.register(ctrl).unwrap();
        assert!(!reg.get(PcieAddr::new(0, 0, 0)).unwrap().smmu_configured);
        reg.mark_smmu_configured(PcieAddr::new(0, 0, 0)).unwrap();
        assert!(reg.get(PcieAddr::new(0, 0, 0)).unwrap().smmu_configured);
    }

    #[test]
    fn test_registry_not_found() {
        let mut reg = UsbPartitionRegistry::new();
        assert_eq!(reg.mark_reset_clean(PcieAddr::new(9, 9, 9)), Err(UsbError::ControllerNotFound));
    }

    // ── UsbPartitionState — full lifecycle ────────────────────────────────────

    fn state_with_integrated_input(initial_owner: GuestId) -> UsbPartitionState {
        let mut state = UsbPartitionState::new();
        // External USB-A → Android.
        state.register_controller(
            make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android)
        ).unwrap();
        // Integrated input controller.
        let mut ctrl = make_ctrl(0, 1, 0, UsbControllerKind::IntegratedInput, initial_owner);
        ctrl.smmu_configured = true;
        ctrl.reset_state = XhciResetState::Clean;
        state.register_controller(ctrl).unwrap();
        state.configure_input_switch(initial_owner, InputPath::UsbHid).unwrap();
        state
    }

    #[test]
    fn test_state_configure_without_integrated_fails() {
        let mut state = UsbPartitionState::new();
        state.register_controller(
            make_ctrl(0, 0, 0, UsbControllerKind::ExternalUsbA, GuestId::Android)
        ).unwrap();
        assert_eq!(
            state.configure_input_switch(GuestId::Android, InputPath::UsbHid),
            Err(UsbError::NoInputController)
        );
    }

    #[test]
    fn test_state_process_hid_forward() {
        let mut state = state_with_integrated_input(GuestId::Android);
        let report = hid_report(0x01, &[0x04]); // Just Ctrl + A
        assert_eq!(state.process_hid_report(&report), HidAction::Forward);
    }

    #[test]
    fn test_state_process_hid_switch() {
        let mut state = state_with_integrated_input(GuestId::Android);
        let report = hid_report(0x05, &[0x2B]); // Ctrl+Alt+Tab
        assert_eq!(state.process_hid_report(&report), HidAction::Switch);
    }

    #[test]
    fn test_state_execute_switch_changes_owner() {
        let mut state = state_with_integrated_input(GuestId::Android);
        let result = state.execute_switch().unwrap();
        assert_eq!(result.old_owner, GuestId::Android);
        assert_eq!(result.new_owner, GuestId::Windows);
        assert_eq!(state.current_input_owner(), Some(GuestId::Windows));
    }

    #[test]
    fn test_state_switch_twice_returns_to_original() {
        let mut state = state_with_integrated_input(GuestId::Android);
        // After first switch: Windows owns input.
        state.execute_switch().unwrap();
        // Mark clean so second switch can proceed.
        state.registry.mark_reset_clean(
            state.registry.integrated_input_addr().unwrap()
        ).unwrap();
        // After second switch: Android owns input again.
        let result = state.execute_switch().unwrap();
        assert_eq!(result.new_owner, GuestId::Android);
        assert_eq!(state.switch_count(), 2);
    }

    #[test]
    fn test_state_execute_switch_marks_reset_pending() {
        let mut state = state_with_integrated_input(GuestId::Android);
        let addr = state.registry.integrated_input_addr().unwrap();
        state.execute_switch().unwrap();
        assert_eq!(
            state.registry.get(addr).unwrap().reset_state,
            XhciResetState::PendingReset
        );
    }

    #[test]
    fn test_state_switch_no_controller_fails() {
        let mut state = UsbPartitionState::new();
        assert_eq!(state.execute_switch(), Err(UsbError::NoInputController));
    }

    #[test]
    fn test_state_switch_smmu_not_configured_fails() {
        let mut state = UsbPartitionState::new();
        // Register integrated input but do NOT mark SMMU configured.
        let ctrl = make_ctrl(0, 1, 0, UsbControllerKind::IntegratedInput, GuestId::Android);
        state.register_controller(ctrl).unwrap();
        state.configure_input_switch(GuestId::Android, InputPath::UsbHid).unwrap();
        assert_eq!(state.execute_switch(), Err(UsbError::SmmuNotConfigured));
    }

    #[test]
    fn test_state_software_switch_forbidden() {
        let state = UsbPartitionState::new();
        assert_eq!(state.reject_software_switch(), UsbError::SoftwareSwitchForbidden);
    }

    #[test]
    fn test_state_no_input_switch_owner_is_none() {
        let state = UsbPartitionState::new();
        assert_eq!(state.current_input_owner(), None);
        assert_eq!(state.switch_count(), 0);
    }

    // ── Error variants ────────────────────────────────────────────────────────

    #[test]
    fn test_error_variants_distinct() {
        assert_ne!(UsbError::ControllerAlreadyAssigned, UsbError::ControllerNotFound);
        assert_ne!(UsbError::SoftwareSwitchForbidden, UsbError::NoInputController);
        assert_ne!(UsbError::SmmuNotConfigured, UsbError::ResetTimeout);
    }

    // ── Controller kind coverage ──────────────────────────────────────────────

    #[test]
    fn test_controller_kinds_all_distinct() {
        assert_ne!(UsbControllerKind::IntegratedInput, UsbControllerKind::ExternalUsbA);
        assert_ne!(UsbControllerKind::ExternalUsbA, UsbControllerKind::ExternalUsbC);
        assert_ne!(UsbControllerKind::ExternalUsbC, UsbControllerKind::Bridge);
    }

    #[test]
    fn test_input_path_variants() {
        assert_ne!(InputPath::UsbHid, InputPath::EmbeddedController);
    }

    #[test]
    fn test_hid_action_variants() {
        assert_ne!(HidAction::Forward, HidAction::Switch);
    }
}
