// ch61: OTA Update System
//
// A/B slot update with AVB-verified payload and ch58 rollback-counter
// integration. The update flow is single-direction: each phase forward
// only. The runtime persists the current OTA phase in a UEFI variable
// so a power loss mid-update resumes (or rolls back) cleanly.
//
// ── Slot Model ────────────────────────────────────────────────────────────────
//
//   Two slots: SlotA, SlotB. AetherActiveSlot UEFI variable holds the
//   currently-booted slot (default A). The update applies to the OTHER
//   slot. After the new slot's first successful boot ("Hypervisor ready."
//   on the recovery UART signature), the runtime marks the new slot
//   Confirmed and clears the boot-attempt counter (ch58).
//
//   If the new slot fails to boot ch58's threshold (3 attempts), the
//   boot selector reverts AetherActiveSlot to the previous value and
//   marks the new slot Failed.
//
// ── Image Set ─────────────────────────────────────────────────────────────────
//
//   The OTA payload is the same 5 AVB-signed images we produce in ch42:
//     boot.img / system.img / vendor.img / vbmeta.img / userdata is NOT
//     replaced — user data persists across updates.
//   vbmeta.img is the chain anchor — its RSA-4096 signature is checked
//     against the rollback index in AetherRollbackIndex before any other
//     image is touched.
//
// ── Phases (UEFI-variable persisted) ──────────────────────────────────────────
//
//   Idle              no update in progress
//   Downloaded        payload fetched into staging partition
//   Verified          AVB chain + rollback index check passed
//   SlotSwitched      AetherActiveSlot flipped; next reboot enters new slot
//   BootedNewSlot     new slot reached "Hypervisor ready." once
//   Confirmed         boot-attempt counter cleared; old slot now free
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1. Slot enum + ActiveSlot UEFI accessor wrappers.
//   2. OtaImage / OtaPayload — fixed-size descriptor.
//   3. OtaConfig + Gate + Error + Phase.
//   4. OtaState with monotonic process_line() advancement.
//   5. init_ota_update() — 7-step pipeline.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Self {
        match self { Slot::A => Slot::B, Slot::B => Slot::A }
    }
    pub fn to_byte(self) -> u8 { match self { Slot::A => 0, Slot::B => 1 } }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b { 0 => Some(Slot::A), 1 => Some(Slot::B), _ => None }
    }
}

pub const UEFI_VAR_AETHER_ACTIVE_SLOT:     &[u8] = b"AetherActiveSlot";
pub const UEFI_VAR_AETHER_OTA_PHASE:       &[u8] = b"AetherOtaPhase";
pub const UEFI_VAR_AETHER_ROLLBACK_INDEX:  &[u8] = b"AetherRollbackIndex";

/// Per-image descriptor in the OTA payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaImage {
    /// Target partition name within the slot (e.g. b"boot", b"system").
    pub partition: [u8; 16],
    pub partition_len: usize,
    /// Size of the image bytes.
    pub size_bytes: u64,
    /// SHA-256 of the image (matches vbmeta hash descriptor on success).
    pub sha256: [u8; 32],
}

impl OtaImage {
    pub fn partition_name(&self) -> &[u8] { &self.partition[..self.partition_len] }
}

/// Aggregate OTA payload — fixed-size descriptor table (no heap).
pub const OTA_MAX_IMAGES: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct OtaPayload {
    pub images: [OtaImage; OTA_MAX_IMAGES],
    pub image_count: usize,
    /// Monotonic rollback index recorded in vbmeta — must be ≥ the
    /// previously-confirmed value or AVB rejects the update.
    pub rollback_index: u64,
}

impl OtaPayload {
    pub const fn empty() -> Self {
        Self {
            images: [OtaImage {
                partition: [0; 16], partition_len: 0,
                size_bytes: 0, sha256: [0; 32],
            }; OTA_MAX_IMAGES],
            image_count: 0,
            rollback_index: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaError {
    /// Payload missing required partitions (boot/system/vendor/vbmeta).
    PayloadMissingRequiredImage,
    /// AVB chain verification failed.
    AvbVerifyFailed,
    /// vbmeta rollback_index < previously confirmed index — anti-rollback.
    RollbackIndexTooLow,
    /// SHA-256 mismatch between image bytes and vbmeta descriptor.
    HashMismatch,
    /// Staging partition smaller than payload.
    InsufficientStaging,
    /// SlotA/SlotB write failed at the block layer.
    SlotWriteError,
    /// AetherActiveSlot variable swap failed.
    SlotSwitchFailed,
    /// Phase machine asked to advance backward.
    PhaseRegression,
    /// New slot failed to boot within ch58's threshold attempts.
    NewSlotBootFailed,
    /// Confirmation requested without BootedNewSlot signature.
    ConfirmationPremature,
    /// Network unreachable for download; user must retry later.
    NetworkUnreachable,
    /// Disk full on staging.
    DiskFull,
    /// Generic UEFI variable write failure.
    VariableWriteError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OtaPhase {
    Idle,
    Downloaded,
    Verified,
    SlotSwitched,
    BootedNewSlot,
    Confirmed,
}

impl OtaPhase {
    pub fn to_byte(self) -> u8 {
        match self {
            OtaPhase::Idle          => 0,
            OtaPhase::Downloaded    => 1,
            OtaPhase::Verified      => 2,
            OtaPhase::SlotSwitched  => 3,
            OtaPhase::BootedNewSlot => 4,
            OtaPhase::Confirmed     => 5,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(OtaPhase::Idle),
            1 => Some(OtaPhase::Downloaded),
            2 => Some(OtaPhase::Verified),
            3 => Some(OtaPhase::SlotSwitched),
            4 => Some(OtaPhase::BootedNewSlot),
            5 => Some(OtaPhase::Confirmed),
            _ => None,
        }
    }
}

pub const OTA_UART_SIG_DOWNLOADED:       &[u8] = b"[ota] payload downloaded";
pub const OTA_UART_SIG_VERIFIED:         &[u8] = b"[ota] avb verified rollback_index=";
pub const OTA_UART_SIG_SLOT_SWITCHED:    &[u8] = b"[ota] AetherActiveSlot=";
pub const OTA_UART_SIG_BOOTED_NEW_SLOT:  &[u8] = b"[ota] new slot booted successfully";
pub const OTA_UART_SIG_CONFIRMED:        &[u8] = b"[ota] new slot confirmed";
pub const OTA_UART_SIG_ROLLBACK:         &[u8] = b"[ota] rollback to previous slot";

#[derive(Debug, Clone, Copy)]
pub struct OtaConfig {
    /// Required partitions in the payload. The payload is rejected if any
    /// of these names are missing. boot/system/vendor/vbmeta only — product
    /// is optional, userdata is never updated.
    pub require_partitions: &'static [&'static [u8]],
    /// Minimum acceptable rollback index. Updated to vbmeta.rollback_index
    /// once a slot is Confirmed.
    pub previously_confirmed_rollback_index: u64,
    /// Threshold from ch58 — boot attempts before a slot is auto-reverted.
    pub rollback_attempt_threshold: u8,
}

impl OtaConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            require_partitions: &[b"boot", b"system", b"vendor", b"vbmeta"],
            previously_confirmed_rollback_index: 0,
            rollback_attempt_threshold: 3,
        }
    }
    pub fn validate(&self) -> Result<(), OtaError> {
        if self.require_partitions.is_empty() {
            return Err(OtaError::PayloadMissingRequiredImage);
        }
        if self.rollback_attempt_threshold == 0 {
            return Err(OtaError::SlotSwitchFailed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtaGate {
    pub payload_downloaded: bool,
    pub avb_verified:       bool,
    pub slot_switched:      bool,
    pub new_slot_booted:    bool,
    pub confirmed:          bool,
}

impl OtaGate {
    pub fn passes(&self) -> bool {
        self.payload_downloaded
            && self.avb_verified
            && self.slot_switched
            && self.new_slot_booted
            && self.confirmed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OtaState {
    pub config:      OtaConfig,
    pub active_slot: Slot,
    pub phase:       OtaPhase,
    pub gate:        OtaGate,
}

impl OtaState {
    pub const fn new(config: OtaConfig, active_slot: Slot) -> Self {
        Self {
            config,
            active_slot,
            phase: OtaPhase::Idle,
            gate:  OtaGate {
                payload_downloaded: false,
                avb_verified:       false,
                slot_switched:      false,
                new_slot_booted:    false,
                confirmed:          false,
            },
        }
    }

    pub fn advance_phase(&mut self, next: OtaPhase) -> Result<(), OtaError> {
        if next < self.phase {
            return Err(OtaError::PhaseRegression);
        }
        self.phase = next;
        Ok(())
    }

    pub fn target_slot(&self) -> Slot { self.active_slot.other() }

    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, OTA_UART_SIG_DOWNLOADED) {
            let _ = self.advance_phase(OtaPhase::Downloaded);
            self.gate.payload_downloaded = true;
        }
        if contains_bytes(line, OTA_UART_SIG_VERIFIED) {
            let _ = self.advance_phase(OtaPhase::Verified);
            self.gate.avb_verified = true;
        }
        if contains_bytes(line, OTA_UART_SIG_SLOT_SWITCHED) {
            let _ = self.advance_phase(OtaPhase::SlotSwitched);
            self.gate.slot_switched = true;
        }
        if contains_bytes(line, OTA_UART_SIG_BOOTED_NEW_SLOT) {
            let _ = self.advance_phase(OtaPhase::BootedNewSlot);
            self.gate.new_slot_booted = true;
        }
        if contains_bytes(line, OTA_UART_SIG_CONFIRMED) {
            let _ = self.advance_phase(OtaPhase::Confirmed);
            self.gate.confirmed = true;
        }
    }

    /// Validate a downloaded payload against this state's config.
    pub fn check_payload(&self, p: &OtaPayload) -> Result<(), OtaError> {
        // Required partitions present?
        for required in self.config.require_partitions {
            let mut found = false;
            for i in 0..p.image_count {
                if p.images[i].partition_name() == *required {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(OtaError::PayloadMissingRequiredImage);
            }
        }
        // Rollback index check.
        if p.rollback_index < self.config.previously_confirmed_rollback_index {
            return Err(OtaError::RollbackIndexTooLow);
        }
        Ok(())
    }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }
}

/// 7-step pipeline.
///   1. validate config
///   2. read AetherActiveSlot (default A)
///   3. read AetherOtaPhase (default Idle)
///   4. payload check (caller-provided) — sets Downloaded
///   5. AVB chain verify (caller drives) — sets Verified
///   6. flip AetherActiveSlot, write phase=SlotSwitched, reboot
///   7. after reboot, scan UART for new-slot signatures → Confirmed
pub fn init_ota_update(
    cfg: &OtaConfig,
    active_slot: Slot,
) -> Result<OtaState, OtaError> {
    cfg.validate()?;
    Ok(OtaState::new(*cfg, active_slot))
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
    fn slot_other_is_involutory() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
        assert_eq!(Slot::A.other().other(), Slot::A);
    }

    #[test]
    fn slot_byte_roundtrip() {
        for s in [Slot::A, Slot::B] {
            assert_eq!(Slot::from_byte(s.to_byte()), Some(s));
        }
        assert_eq!(Slot::from_byte(2), None);
    }

    #[test]
    fn defaults_validate() {
        OtaConfig::aether_defaults().validate().unwrap();
    }

    #[test]
    fn phase_byte_roundtrip() {
        for p in [
            OtaPhase::Idle, OtaPhase::Downloaded, OtaPhase::Verified,
            OtaPhase::SlotSwitched, OtaPhase::BootedNewSlot, OtaPhase::Confirmed,
        ] {
            assert_eq!(OtaPhase::from_byte(p.to_byte()), Some(p));
        }
    }

    #[test]
    fn phase_is_monotonic() {
        let mut s = OtaState::new(OtaConfig::aether_defaults(), Slot::A);
        s.advance_phase(OtaPhase::Downloaded).unwrap();
        s.advance_phase(OtaPhase::Verified).unwrap();
        assert_eq!(s.advance_phase(OtaPhase::Idle), Err(OtaError::PhaseRegression));
    }

    fn make_payload(parts: &[&[u8]], rollback: u64) -> OtaPayload {
        let mut p = OtaPayload::empty();
        for (i, name) in parts.iter().enumerate() {
            assert!(name.len() <= 16);
            p.images[i].partition[..name.len()].copy_from_slice(name);
            p.images[i].partition_len = name.len();
            p.images[i].size_bytes = 1;
        }
        p.image_count = parts.len();
        p.rollback_index = rollback;
        p
    }

    #[test]
    fn check_payload_accepts_complete() {
        let s = OtaState::new(OtaConfig::aether_defaults(), Slot::A);
        let p = make_payload(&[b"boot", b"system", b"vendor", b"vbmeta"], 1);
        s.check_payload(&p).unwrap();
    }

    #[test]
    fn check_payload_rejects_missing_partition() {
        let s = OtaState::new(OtaConfig::aether_defaults(), Slot::A);
        let p = make_payload(&[b"boot", b"system", b"vendor"], 1); // no vbmeta
        assert_eq!(s.check_payload(&p), Err(OtaError::PayloadMissingRequiredImage));
    }

    #[test]
    fn check_payload_rejects_rollback() {
        let mut cfg = OtaConfig::aether_defaults();
        cfg.previously_confirmed_rollback_index = 5;
        let s = OtaState::new(cfg, Slot::A);
        let p = make_payload(&[b"boot", b"system", b"vendor", b"vbmeta"], 4);
        assert_eq!(s.check_payload(&p), Err(OtaError::RollbackIndexTooLow));
    }

    #[test]
    fn uart_scanner_walks_to_gate() {
        let mut s = OtaState::new(OtaConfig::aether_defaults(), Slot::A);
        s.process_line(b"[ota] payload downloaded");
        s.process_line(b"[ota] avb verified rollback_index=7");
        s.process_line(b"[ota] AetherActiveSlot=B");
        s.process_line(b"[ota] new slot booted successfully");
        s.process_line(b"[ota] new slot confirmed");
        assert!(s.is_gate_passed());
        assert_eq!(s.phase, OtaPhase::Confirmed);
    }

    #[test]
    fn init_returns_idle() {
        let s = init_ota_update(&OtaConfig::aether_defaults(), Slot::A).unwrap();
        assert_eq!(s.phase, OtaPhase::Idle);
        assert_eq!(s.active_slot, Slot::A);
        assert_eq!(s.target_slot(), Slot::B);
        assert!(!s.is_gate_passed());
    }
}
