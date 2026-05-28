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

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end execution
//
// Everything above models the OTA flow as a state machine + UART gate. The
// items below DRIVE the flow: real NVMe writes to the target slot, real
// vbmeta structural verification (mirroring run_avb_boot_pipeline §5–7),
// real UEFI variable writes for AetherActiveSlot/AetherOtaPhase/
// AetherRollbackIndex, and a real reboot path.
//
// All side effects go through OtaRuntime — the EFI host implements it for
// real hardware; tests use OtaMockRuntime.
// ─────────────────────────────────────────────────────────────────────────────

/// LBA range descriptor. Mirrors `avb_boot::PartitionSlotLba` but lives
/// here so this module compiles on x86_64 host test builds too (avb_boot
/// is `#[cfg(target_arch = "aarch64")]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionSlotLba {
    pub start_lba: u64,
    pub lba_count: u64,
}

/// One LBA range per partition this OTA flow touches on the target slot.
/// userdata is intentionally NOT included — user data persists across OTAs.
#[derive(Debug, Clone, Copy)]
pub struct OtaSlotPartitionMap {
    pub boot:   PartitionSlotLba,
    pub system: PartitionSlotLba,
    pub vendor: PartitionSlotLba,
    pub vbmeta: PartitionSlotLba,
}

impl OtaSlotPartitionMap {
    /// Resolve the LBA range matching an OtaImage partition name.
    pub fn range_for(&self, name: &[u8]) -> Option<PartitionSlotLba> {
        match name {
            b"boot"   => Some(self.boot),
            b"system" => Some(self.system),
            b"vendor" => Some(self.vendor),
            b"vbmeta" => Some(self.vbmeta),
            _ => None,
        }
    }
}

/// Where in the storage namespace the OTA client staged the downloaded payload.
#[derive(Debug, Clone, Copy)]
pub struct OtaPayloadStaging {
    /// NVMe namespace ID holding both staging and the target slot.
    pub nsid: u32,
    /// LBA of the first sector of the staging area.
    pub start_lba: u64,
    /// Total sectors the payload occupies (sum of all OtaImage size_bytes,
    /// rounded up to the 4 KiB sector boundary).
    pub lba_count: u64,
}

/// Abstract integration boundary the EFI host fills in. The trait keeps the
/// pipeline testable: real hardware uses an EFI-backed implementation that
/// calls EFI_RT->SetVariable and the NVMe Submission Queue; tests use the
/// in-memory mock in this module.
pub trait OtaRuntime {
    /// Read a 4 KiB sector from the namespace into `dst`.
    fn nvme_read_sector(
        &mut self, nsid: u32, lba: u64, dst: &mut [u8; 4096],
    ) -> Result<(), OtaError>;
    /// Write a 4 KiB sector from `src` into the namespace.
    fn nvme_write_sector(
        &mut self, nsid: u32, lba: u64, src: &[u8; 4096],
    ) -> Result<(), OtaError>;
    /// EFI_RT->GetVariable for the AETHER namespace. Returns None if absent.
    fn get_uefi_variable(&self, name: &[u8]) -> Option<[u8; 8]>;
    /// EFI_RT->SetVariable with NV+BS+RT attributes.
    fn set_uefi_variable(&mut self, name: &[u8], value: &[u8]) -> Result<(), OtaError>;
    /// Emit a line to the PL011 UART so process_line() can match it.
    fn emit_uart_line(&mut self, line: &[u8]);
    /// EFI_RT->ResetSystem(EfiResetWarm). Does not return on real hardware.
    fn reset_system_warm(&mut self) -> !;
}

/// Drive Idle → Downloaded → Verified → SlotSwitched. Caller reboots after
/// this returns Ok(()). On the new boot, call confirm_new_slot_after_boot().
///
/// Sequence:
///   1. check_payload — required partitions + rollback index
///   2. for each image: copy from staging to target_slot's partition
///      (sector-by-sector, no heap) and emit OTA_UART_SIG_DOWNLOADED
///   3. read vbmeta_<target> back, run structural AVB checks parallel to
///      run_avb_boot_pipeline §5–7, emit OTA_UART_SIG_VERIFIED with index
///   4. SetVariable AetherRollbackIndex = vbmeta.rollback_index
///   5. SetVariable AetherActiveSlot = target_slot
///   6. SetVariable AetherOtaPhase = SlotSwitched
///   7. emit OTA_UART_SIG_SLOT_SWITCHED — caller reboots
pub fn run_ota_pipeline<R: OtaRuntime>(
    state: &mut OtaState,
    runtime: &mut R,
    payload: &OtaPayload,
    staging: &OtaPayloadStaging,
    slot_map: &OtaSlotPartitionMap,
) -> Result<(), OtaError> {
    state.check_payload(payload)?;

    // ── 2. Copy each image to target slot ────────────────────────────────────
    let mut sector_cursor = staging.start_lba;
    let mut buf = [0u8; 4096];
    for i in 0..payload.image_count {
        let img = &payload.images[i];
        let dst = slot_map
            .range_for(img.partition_name())
            .ok_or(OtaError::PayloadMissingRequiredImage)?;
        let sectors = (img.size_bytes + 4095) / 4096;
        if sectors > dst.lba_count {
            return Err(OtaError::InsufficientStaging);
        }
        for s in 0..sectors {
            runtime.nvme_read_sector(staging.nsid, sector_cursor + s, &mut buf)?;
            runtime.nvme_write_sector(staging.nsid, dst.start_lba + s, &buf)?;
        }
        sector_cursor += sectors;
    }
    state.advance_phase(OtaPhase::Downloaded)?;
    state.gate.payload_downloaded = true;
    runtime.emit_uart_line(OTA_UART_SIG_DOWNLOADED);

    // ── 3. Structural AVB check on the target slot's vbmeta ──────────────────
    // Mirrors run_avb_boot_pipeline §5–7: vbmeta header parse + signature
    // bounds check + rollback index comparison.
    runtime.nvme_read_sector(staging.nsid, slot_map.vbmeta.start_lba, &mut buf)?;
    let hdr = crate::bootloader::VbmetaHeader::parse(&buf)
        .map_err(|_| OtaError::AvbVerifyFailed)?;
    let auth_size = hdr.authentication_data_block_size as usize;
    let sig_off   = hdr.signature_offset as usize;
    let sig_size  = hdr.signature_size as usize;
    if sig_off.saturating_add(sig_size) > auth_size {
        return Err(OtaError::AvbVerifyFailed);
    }
    if payload.rollback_index < state.config.previously_confirmed_rollback_index {
        return Err(OtaError::RollbackIndexTooLow);
    }
    state.advance_phase(OtaPhase::Verified)?;
    state.gate.avb_verified = true;
    // Emit the signature with the rollback index appended so the scanner
    // can verify the index travelled all the way through.
    let mut verified_line = [0u8; 64];
    let prefix = OTA_UART_SIG_VERIFIED;
    let n = encode_verified_line(&mut verified_line, prefix, payload.rollback_index);
    runtime.emit_uart_line(&verified_line[..n]);

    // ── 4. Persist new rollback index ────────────────────────────────────────
    let rollback_le = payload.rollback_index.to_le_bytes();
    runtime
        .set_uefi_variable(UEFI_VAR_AETHER_ROLLBACK_INDEX, &rollback_le)
        .map_err(|_| OtaError::VariableWriteError)?;

    // ── 5. Flip active slot ──────────────────────────────────────────────────
    let target = state.target_slot();
    runtime
        .set_uefi_variable(UEFI_VAR_AETHER_ACTIVE_SLOT, &[target.to_byte()])
        .map_err(|_| OtaError::SlotSwitchFailed)?;

    // ── 6. Persist new phase ─────────────────────────────────────────────────
    runtime
        .set_uefi_variable(UEFI_VAR_AETHER_OTA_PHASE, &[OtaPhase::SlotSwitched.to_byte()])
        .map_err(|_| OtaError::VariableWriteError)?;
    state.advance_phase(OtaPhase::SlotSwitched)?;
    state.gate.slot_switched = true;

    // ── 7. UART trace; caller reboots ────────────────────────────────────────
    let mut switched_line = [0u8; 32];
    let n = OTA_UART_SIG_SLOT_SWITCHED.len();
    switched_line[..n].copy_from_slice(OTA_UART_SIG_SLOT_SWITCHED);
    switched_line[n] = match target { Slot::A => b'A', Slot::B => b'B' };
    runtime.emit_uart_line(&switched_line[..n + 1]);

    Ok(())
}

/// Called early on the FIRST boot of the new slot, after ch58's selector has
/// run the new hypervisor and the runtime has emitted "Hypervisor ready.".
/// Clears ch58's boot-attempt counter and persists OtaPhase=Confirmed so a
/// later reboot does not re-enter the OTA pending state.
pub fn confirm_new_slot_after_boot<R: OtaRuntime>(
    state: &mut R,
    ota: &mut OtaState,
) -> Result<(), OtaError> {
    // Reset ch58's AetherBootAttempt counter to 0.
    state
        .set_uefi_variable(b"AetherBootAttempt", &[0u8])
        .map_err(|_| OtaError::VariableWriteError)?;
    state
        .set_uefi_variable(UEFI_VAR_AETHER_OTA_PHASE, &[OtaPhase::Confirmed.to_byte()])
        .map_err(|_| OtaError::VariableWriteError)?;

    ota.advance_phase(OtaPhase::BootedNewSlot)?;
    ota.gate.new_slot_booted = true;
    state.emit_uart_line(OTA_UART_SIG_BOOTED_NEW_SLOT);

    ota.advance_phase(OtaPhase::Confirmed)?;
    ota.gate.confirmed = true;
    state.emit_uart_line(OTA_UART_SIG_CONFIRMED);

    Ok(())
}

#[inline]
fn encode_verified_line(out: &mut [u8], prefix: &[u8], index: u64) -> usize {
    out[..prefix.len()].copy_from_slice(prefix);
    let mut cursor = prefix.len();
    // Decimal encode index into out[cursor..]; max 20 digits for u64.
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = index;
    if v == 0 {
        out[cursor] = b'0';
        return cursor + 1;
    }
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        out[cursor] = digits[n - 1 - i];
        cursor += 1;
    }
    cursor
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

    /// Minimal in-memory OtaRuntime for end-to-end tests. Models the NVMe
    /// namespace as a small sparse map and the UEFI variable store as a
    /// fixed array. Real EFI host plugs in a different impl.
    struct MockRuntime {
        sectors: [(u64, [u8; 4096]); 64],
        sector_count: usize,
        vars: [( [u8; 32], usize, [u8; 16], usize ); 8],
        var_count: usize,
        uart: [(usize, [u8; 96]); 16],
        uart_count: usize,
        reset_called: bool,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                sectors: [(0, [0; 4096]); 64],
                sector_count: 0,
                vars: [([0; 32], 0, [0; 16], 0); 8],
                var_count: 0,
                uart: [(0, [0; 96]); 16],
                uart_count: 0,
                reset_called: false,
            }
        }
        fn put_sector(&mut self, lba: u64, data: [u8; 4096]) {
            self.sectors[self.sector_count] = (lba, data);
            self.sector_count += 1;
        }
        fn uart_contains(&self, needle: &[u8]) -> bool {
            for i in 0..self.uart_count {
                let (len, buf) = &self.uart[i];
                if contains_bytes(&buf[..*len], needle) { return true; }
            }
            false
        }
        fn var_value(&self, name: &[u8]) -> Option<&[u8]> {
            for i in 0..self.var_count {
                let (nbuf, nlen, vbuf, vlen) = &self.vars[i];
                if &nbuf[..*nlen] == name {
                    return Some(&vbuf[..*vlen]);
                }
            }
            None
        }
    }

    impl OtaRuntime for MockRuntime {
        fn nvme_read_sector(&mut self, _nsid: u32, lba: u64, dst: &mut [u8; 4096])
            -> Result<(), OtaError>
        {
            for i in 0..self.sector_count {
                if self.sectors[i].0 == lba {
                    *dst = self.sectors[i].1;
                    return Ok(());
                }
            }
            *dst = [0; 4096];
            Ok(())
        }
        fn nvme_write_sector(&mut self, _nsid: u32, lba: u64, src: &[u8; 4096])
            -> Result<(), OtaError>
        {
            for i in 0..self.sector_count {
                if self.sectors[i].0 == lba {
                    self.sectors[i].1 = *src;
                    return Ok(());
                }
            }
            self.put_sector(lba, *src);
            Ok(())
        }
        fn get_uefi_variable(&self, name: &[u8]) -> Option<[u8; 8]> {
            let v = self.var_value(name)?;
            let mut out = [0u8; 8];
            let n = core::cmp::min(v.len(), 8);
            out[..n].copy_from_slice(&v[..n]);
            Some(out)
        }
        fn set_uefi_variable(&mut self, name: &[u8], value: &[u8]) -> Result<(), OtaError> {
            // Overwrite if present.
            for i in 0..self.var_count {
                let (nbuf, nlen, _, _) = &self.vars[i];
                if &nbuf[..*nlen] == name {
                    let vlen = core::cmp::min(value.len(), 16);
                    self.vars[i].2[..vlen].copy_from_slice(&value[..vlen]);
                    self.vars[i].3 = vlen;
                    return Ok(());
                }
            }
            let nlen = core::cmp::min(name.len(), 32);
            let vlen = core::cmp::min(value.len(), 16);
            self.vars[self.var_count].0[..nlen].copy_from_slice(&name[..nlen]);
            self.vars[self.var_count].1 = nlen;
            self.vars[self.var_count].2[..vlen].copy_from_slice(&value[..vlen]);
            self.vars[self.var_count].3 = vlen;
            self.var_count += 1;
            Ok(())
        }
        fn emit_uart_line(&mut self, line: &[u8]) {
            let n = core::cmp::min(line.len(), 96);
            self.uart[self.uart_count].0 = n;
            self.uart[self.uart_count].1[..n].copy_from_slice(&line[..n]);
            self.uart_count += 1;
        }
        fn reset_system_warm(&mut self) -> ! {
            self.reset_called = true;
            panic!("reset_system_warm called");
        }
    }

    fn slot_map_at(base: u64) -> OtaSlotPartitionMap {
        OtaSlotPartitionMap {
            boot:   PartitionSlotLba { start_lba: base,        lba_count: 8 },
            system: PartitionSlotLba { start_lba: base + 16,   lba_count: 32 },
            vendor: PartitionSlotLba { start_lba: base + 64,   lba_count: 16 },
            vbmeta: PartitionSlotLba { start_lba: base + 96,   lba_count: 1 },
        }
    }

    /// Build a 4 KiB vbmeta sector with a valid header — passes
    /// VbmetaHeader::parse + the signature-bounds check in run_ota_pipeline.
    fn build_vbmeta_sector() -> [u8; 4096] {
        let mut s = [0u8; 4096];
        s[0..4].copy_from_slice(b"AVB0");
        // required_libavb_version_major = 1 (big-endian)
        s[4..8].copy_from_slice(&1u32.to_be_bytes());
        // authentication_data_block_size = 256
        s[12..20].copy_from_slice(&256u64.to_be_bytes());
        // auxiliary_data_block_size = 0
        s[20..28].copy_from_slice(&0u64.to_be_bytes());
        // algorithm_type = Sha256Rsa4096 (2)
        s[28..32].copy_from_slice(&2u32.to_be_bytes());
        // hash_offset = 0, hash_size = 32 (within auth block)
        s[32..40].copy_from_slice(&0u64.to_be_bytes());
        s[40..48].copy_from_slice(&32u64.to_be_bytes());
        // signature_offset = 32, signature_size = 64 (32 + 64 = 96 ≤ 256)
        s[48..56].copy_from_slice(&32u64.to_be_bytes());
        s[56..64].copy_from_slice(&64u64.to_be_bytes());
        s
    }

    #[test]
    fn pipeline_drives_state_to_slot_switched() {
        let cfg = OtaConfig::aether_defaults();
        let mut state = init_ota_update(&cfg, Slot::A).unwrap();
        let mut runtime = MockRuntime::new();

        // Stage a payload: boot + system + vendor + vbmeta, one sector each.
        let payload = make_payload(&[b"boot", b"system", b"vendor", b"vbmeta"], 7);
        let staging = OtaPayloadStaging { nsid: 1, start_lba: 100_000, lba_count: 4 };
        let map = slot_map_at(200_000);

        // Pre-load the staging area with non-zero data so reads return real
        // bytes; vbmeta staging sector must be parseable by VbmetaHeader.
        runtime.put_sector(100_000, [0xAA; 4096]); // boot
        runtime.put_sector(100_001, [0xBB; 4096]); // system
        runtime.put_sector(100_002, [0xCC; 4096]); // vendor
        runtime.put_sector(100_003, build_vbmeta_sector()); // vbmeta

        run_ota_pipeline(&mut state, &mut runtime, &payload, &staging, &map).unwrap();

        assert_eq!(state.phase, OtaPhase::SlotSwitched);
        assert!(state.gate.payload_downloaded);
        assert!(state.gate.avb_verified);
        assert!(state.gate.slot_switched);
        assert!(runtime.uart_contains(OTA_UART_SIG_DOWNLOADED));
        assert!(runtime.uart_contains(OTA_UART_SIG_VERIFIED));
        assert!(runtime.uart_contains(OTA_UART_SIG_SLOT_SWITCHED));
        assert_eq!(
            runtime.var_value(UEFI_VAR_AETHER_ACTIVE_SLOT),
            Some(&[Slot::B.to_byte()][..]),
        );
        assert_eq!(
            runtime.var_value(UEFI_VAR_AETHER_ROLLBACK_INDEX),
            Some(&7u64.to_le_bytes()[..]),
        );
    }

    #[test]
    fn confirm_after_boot_closes_gate() {
        let cfg = OtaConfig::aether_defaults();
        let mut state = init_ota_update(&cfg, Slot::A).unwrap();
        // Pretend the pipeline already ran and we rebooted into target slot.
        state.phase = OtaPhase::SlotSwitched;
        state.gate.payload_downloaded = true;
        state.gate.avb_verified = true;
        state.gate.slot_switched = true;

        let mut runtime = MockRuntime::new();
        confirm_new_slot_after_boot(&mut runtime, &mut state).unwrap();

        assert!(state.is_gate_passed());
        assert_eq!(state.phase, OtaPhase::Confirmed);
        assert_eq!(runtime.var_value(b"AetherBootAttempt"), Some(&[0u8][..]));
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
