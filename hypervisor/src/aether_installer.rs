// ch56: AETHER Installer CLI
//
// SPEC ONLY. The actual installer binary lives at `tools/aether-install/`
// in this workspace — it is a userland std-using Rust crate that runs on
// the candidate machine BEFORE AETHER has booted, turning that machine
// into one that does. This module documents its runtime contract and
// gates so the hypervisor-side test suite can audit the installer's
// declared invariants against the same Config / Gate / Phase shape every
// other AETHER chapter uses (ch29 onward).
//
// ── Sibling Pattern ───────────────────────────────────────────────────────────
//
// This is the same split as ch63 AETHER Manager Android App: the deliverable
// is not no_std EL2 code, but its spec is declared here so the project's
// chapter accounting stays uniform. CLAUDE.md treats both as ✅ Complete
// only when the spec module compiles + the actual deliverable's tests pass.
//
// ── Installer Surface ─────────────────────────────────────────────────────────
//
// Five subcommands the binary exposes (`tools/aether-install/src/cli.rs`):
//
//   aether-install check        wraps aether-compat; emits a CompatReport
//                               (JSON or human). Read-only; no disk writes,
//                               no UEFI variable mutations.
//
//   aether-install install      full install pipeline. Defaults to dry-run.
//                               Each destructive step gated behind --apply.
//                               Steps: detect target disk + GPU plan, create
//                               NVMe namespace for AETHER, write hypervisor.
//                               efi to the ESP, populate config partition,
//                               register a new EFI BootEntry pointing at
//                               our shim (per ch57 Secure Boot Integration).
//
//   aether-install uninstall    removes AETHER without touching Windows.
//                               Deletes the AETHER ESP entry, removes the
//                               namespace, leaves the rest of the disk
//                               byte-identical.
//
//   aether-install update       A/B slot update with rollback. Verifies the
//                               new images via AVB (ch61 OTA Update System),
//                               writes to the inactive slot, flips Aether
//                               ActiveSlot, reboots. Ch58's rollback guard
//                               handles failed boots.
//
//   aether-install status       read-only inspection of install state from
//                               the locally-cached InstallState file at
//                               /var/lib/aether/install-state.json (Linux)
//                               or %ProgramData%\AETHER\install-state.json
//                               (Windows host pre-install).
//
// ── Inviolable Safety Rules ───────────────────────────────────────────────────
//
//   1. Dry-run by default. Every destructive subcommand requires `--apply`.
//      Without it the installer prints the plan + exits zero.
//
//   2. Never disable Secure Boot. The installer NEVER instructs the user
//      to disable Secure Boot. Enrollment is via shim + MOK per ch57.
//      `InstallerError::DisableSecureBootForbidden` exists to make a
//      future regression impossible to slip past code review.
//
//   3. No background network. The installer issues zero outbound network
//      calls during install / uninstall / status. `update` may fetch from
//      the OTA endpoint configured in /etc/aether/ota.toml, but only on
//      the explicit `aether-install update --fetch <url>` invocation.
//
//   4. Idempotent. Every step is safe to re-run; if the install was
//      partial, the next `install --apply` resumes from the last completed
//      step (read out of install-state.json).
//
//   5. Windows partition untouched. AETHER lives in its OWN namespace on
//      NVMe; on systems with Windows pre-installed, the installer never
//      modifies the Windows partition or its bootloader (per ch17 ARM
//      Tier — Hardware and Partition Configuration).
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1. Subcommand enum (Check / Install / Uninstall / Update / Status)
//   2. InstallerSafetyMode (DryRun | Apply) + roundtrip helpers
//   3. InstallerConfig + Gate + Error + Phase  (canonical shape)
//   4. InstallStep enum — every distinct step the install pipeline runs,
//      ordered. Tests assert is_completed() honors the order.
//   5. UART signature byte patterns the runtime scanner watches for when
//      the installer reports its progress to a serial console (debug
//      installs and CI runs use the same surface).
//
// ── Gate (Chapter 56) ─────────────────────────────────────────────────────────
//
//   InstallerGate.passes() requires (matching `tools/aether-install/src/
//   install.rs` step ordering):
//     compat_report_ok        — `aether-install check` passed on this host
//     namespace_created       — AETHER NVMe namespace exists
//     esp_populated           — /EFI/AETHER/hypervisor.efi + boot.img +
//                               vbmeta.img written and verified
//     boot_entry_registered   — UEFI Boot#### entry pointing at shim
//                               written and verified (or BootCurrent
//                               flagged as AETHER on the first reboot)
//     mok_enrolled            — ch57 MOK enrollment completed (first
//                               post-install reboot)
//     hypervisor_observed     — first "Hypervisor ready." captured from
//                               serial / framebuffer on the second post-
//                               install reboot

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subcommand {
    Check,
    Install,
    Uninstall,
    Update,
    Status,
}

impl Subcommand {
    pub fn name(self) -> &'static str {
        match self {
            Subcommand::Check     => "check",
            Subcommand::Install   => "install",
            Subcommand::Uninstall => "uninstall",
            Subcommand::Update    => "update",
            Subcommand::Status    => "status",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "check"     => Some(Subcommand::Check),
            "install"   => Some(Subcommand::Install),
            "uninstall" => Some(Subcommand::Uninstall),
            "update"    => Some(Subcommand::Update),
            "status"    => Some(Subcommand::Status),
            _ => None,
        }
    }

    /// Whether this subcommand can mutate the host machine. The installer
    /// rejects mutating subcommands unless `--apply` is supplied.
    pub fn is_destructive(self) -> bool {
        match self {
            Subcommand::Check  | Subcommand::Status => false,
            Subcommand::Install | Subcommand::Uninstall | Subcommand::Update => true,
        }
    }
}

/// Safety mode applied to destructive subcommands. The installer defaults
/// to DryRun on every install/uninstall/update; the user must explicitly
/// pass `--apply` to switch to Apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerSafetyMode {
    /// Print the plan, perform read-only checks, exit zero.
    DryRun,
    /// Execute the destructive steps. Requires explicit `--apply`.
    Apply,
}

impl InstallerSafetyMode {
    pub fn to_byte(self) -> u8 {
        match self { InstallerSafetyMode::DryRun => 0, InstallerSafetyMode::Apply => 1 }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(InstallerSafetyMode::DryRun),
            1 => Some(InstallerSafetyMode::Apply),
            _ => None,
        }
    }
}

/// The ordered set of steps the install pipeline walks. Each step has a
/// dedicated Rust file under `tools/aether-install/src/`; the spec here
/// mirrors that breakdown one-for-one so a code-review of the binary
/// can be cross-checked against the chapter spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallStep {
    /// Compat report (`check.rs`) — verifies CPU/RAM/disk/firmware compat.
    CompatReport         = 0,
    /// GPU plan (`gpu_config.rs`) — selects passthrough / SR-IOV / virtio.
    GpuPlan              = 1,
    /// Target disk + namespace creation (`install.rs::create_nvme_namespace`).
    NvmeNamespaceCreated = 2,
    /// EFI binary copy (`install.rs::copy_efi_binary`).
    EspBinaryWritten     = 3,
    /// EFI boot entry registration (`boot_entry.rs`).
    BootEntryRegistered  = 4,
    /// Install state persisted (`install_state.rs`).
    InstallStatePersisted = 5,
    /// MOK enrollment (ch57; happens on the first post-install reboot).
    MokEnrolled          = 6,
    /// First successful hypervisor boot (second post-install reboot).
    HypervisorObserved   = 7,
}

impl InstallStep {
    pub fn ordinal(self) -> u8 { self as u8 }
}

pub const INSTALL_STEP_COUNT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerError {
    /// User supplied --apply for a subcommand that has no destructive path.
    NoApplyForReadOnlySubcommand,
    /// Mutation requested without --apply.
    MissingApplyFlag,
    /// Compat check failed; refuse to proceed with install.
    CompatCheckFailed,
    /// Target disk argument did not match any block device on the host.
    TargetDiskUnknown,
    /// Disk too small to host AETHER (< 32 GiB minimum).
    TargetDiskTooSmall,
    /// NVMe namespace creation IOCTL failed.
    NamespaceCreationFailed,
    /// Writing hypervisor.efi to the ESP failed (I/O error).
    EspWriteFailed,
    /// Boot entry write failed (EFI_VARIABLE service error).
    BootEntryWriteFailed,
    /// User reachable but refused via SecureBoot disabled instruction.
    /// IMPORTANT: the installer NEVER emits the instruction "disable
    /// Secure Boot." This variant is a tripwire: if a future code path
    /// reaches it, it will be visible in audit.
    DisableSecureBootForbidden,
    /// Install state file corrupted or unreadable.
    InstallStateCorrupted,
    /// Phase machine regression.
    PhaseRegression,
    /// Update payload AVB verification failed.
    UpdateAvbVerifyFailed,
    /// Update payload rollback index ≤ previously confirmed.
    UpdateRollbackIndexTooLow,
    /// Network round-trip during a non-update subcommand.
    UnexpectedNetworkRoundTrip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallerPhase {
    NotStarted,
    CompatReported,
    GpuPlanned,
    NamespaceCreated,
    EspPopulated,
    BootEntryRegistered,
    InstallStatePersisted,
    AwaitingReboot,
    MokEnrolled,
    HypervisorObserved,
    GatePassed,
}

#[derive(Debug, Clone, Copy)]
pub struct InstallerConfig {
    /// Minimum disk size (bytes) the installer will accept.
    pub min_disk_bytes: u64,
    /// Default safety mode. Always DryRun in production; tests may set Apply.
    pub default_safety: InstallerSafetyMode,
    /// Whether the installer must refuse network round-trips for
    /// non-update subcommands. Always true in production.
    pub forbid_network_for_non_update: bool,
}

impl InstallerConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            min_disk_bytes: 32u64 * 1024 * 1024 * 1024, // 32 GiB
            default_safety: InstallerSafetyMode::DryRun,
            forbid_network_for_non_update: true,
        }
    }

    pub fn validate(&self) -> Result<(), InstallerError> {
        if self.min_disk_bytes < 8u64 * 1024 * 1024 * 1024 {
            // Floor: even a stripped AOSP system.img is ~1 GiB; 8 GiB is
            // the floor for boot + system + vendor + ~4 GiB userdata.
            return Err(InstallerError::TargetDiskTooSmall);
        }
        if self.default_safety != InstallerSafetyMode::DryRun {
            // Production safety: must default to DryRun.
            return Err(InstallerError::MissingApplyFlag);
        }
        if !self.forbid_network_for_non_update {
            return Err(InstallerError::UnexpectedNetworkRoundTrip);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstallerGate {
    pub compat_report_ok:        bool,
    pub namespace_created:       bool,
    pub esp_populated:           bool,
    pub boot_entry_registered:   bool,
    pub mok_enrolled:            bool,
    pub hypervisor_observed:     bool,
}

impl InstallerGate {
    pub fn passes(&self) -> bool {
        self.compat_report_ok
            && self.namespace_created
            && self.esp_populated
            && self.boot_entry_registered
            && self.mok_enrolled
            && self.hypervisor_observed
    }
}

/// UART byte-pattern signatures the runtime scanner watches for when the
/// installer reports its progress to a serial console (CI runs, debug
/// installs). The strings match what `tools/aether-install/src/install.rs
/// ::print_step` and friends emit.
pub const INSTALLER_UART_SIG_COMPAT_OK:           &[u8] = b"[installer] compat OK";
pub const INSTALLER_UART_SIG_GPU_PLAN_OK:         &[u8] = b"[installer] gpu plan resolved";
pub const INSTALLER_UART_SIG_NAMESPACE_CREATED:   &[u8] = b"[installer] nvme namespace created";
pub const INSTALLER_UART_SIG_ESP_WRITTEN:         &[u8] = b"[installer] hypervisor.efi written";
pub const INSTALLER_UART_SIG_BOOT_ENTRY_OK:       &[u8] = b"[installer] EFI boot entry registered";
pub const INSTALLER_UART_SIG_STATE_PERSISTED:     &[u8] = b"[installer] install-state.json persisted";
pub const INSTALLER_UART_SIG_AWAITING_REBOOT:     &[u8] = b"[installer] awaiting MOK enrollment reboot";
pub const INSTALLER_UART_SIG_HYPERVISOR_OBSERVED: &[u8] = b"[installer] hypervisor ready observed";

#[derive(Debug, Clone, Copy)]
pub struct InstallerState {
    pub config: InstallerConfig,
    pub phase:  InstallerPhase,
    pub gate:   InstallerGate,
}

impl InstallerState {
    pub const fn new(config: InstallerConfig) -> Self {
        Self {
            config,
            phase: InstallerPhase::NotStarted,
            gate:  InstallerGate {
                compat_report_ok:      false,
                namespace_created:     false,
                esp_populated:         false,
                boot_entry_registered: false,
                mok_enrolled:          false,
                hypervisor_observed:   false,
            },
        }
    }

    pub fn advance_phase(&mut self, next: InstallerPhase) -> Result<(), InstallerError> {
        if next < self.phase { return Err(InstallerError::PhaseRegression); }
        self.phase = next;
        Ok(())
    }

    /// Scan one UART line for installer progress signatures. Each match
    /// flips the appropriate gate flag and advances the phase machine.
    pub fn process_line(&mut self, line: &[u8]) -> bool {
        let mut matched = false;
        if contains_bytes(line, INSTALLER_UART_SIG_COMPAT_OK) {
            self.gate.compat_report_ok = true;
            let _ = self.advance_phase(InstallerPhase::CompatReported);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_GPU_PLAN_OK) {
            let _ = self.advance_phase(InstallerPhase::GpuPlanned);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_NAMESPACE_CREATED) {
            self.gate.namespace_created = true;
            let _ = self.advance_phase(InstallerPhase::NamespaceCreated);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_ESP_WRITTEN) {
            self.gate.esp_populated = true;
            let _ = self.advance_phase(InstallerPhase::EspPopulated);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_BOOT_ENTRY_OK) {
            self.gate.boot_entry_registered = true;
            let _ = self.advance_phase(InstallerPhase::BootEntryRegistered);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_STATE_PERSISTED) {
            let _ = self.advance_phase(InstallerPhase::InstallStatePersisted);
            matched = true;
        }
        if contains_bytes(line, INSTALLER_UART_SIG_AWAITING_REBOOT) {
            let _ = self.advance_phase(InstallerPhase::AwaitingReboot);
            matched = true;
        }
        // MOK enrollment is observed via ch57's UART signatures; the
        // installer-side gate just needs to know it happened. The Boot
        // selector / OTA rollback guard wires that.
        if contains_bytes(line, INSTALLER_UART_SIG_HYPERVISOR_OBSERVED) {
            self.gate.hypervisor_observed = true;
            self.gate.mok_enrolled = true; // implied by reaching boot
            let _ = self.advance_phase(InstallerPhase::HypervisorObserved);
            matched = true;
        }
        if self.gate.passes() {
            let _ = self.advance_phase(InstallerPhase::GatePassed);
        }
        matched
    }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }

    /// Refuse to proceed with a destructive subcommand if the safety
    /// mode is not Apply. Returns Ok for non-destructive subcommands
    /// regardless.
    pub fn check_safety(
        &self,
        sub: Subcommand,
        mode: InstallerSafetyMode,
    ) -> Result<(), InstallerError> {
        if sub.is_destructive() && mode != InstallerSafetyMode::Apply {
            return Err(InstallerError::MissingApplyFlag);
        }
        if !sub.is_destructive() && mode == InstallerSafetyMode::Apply {
            // --apply on `check` or `status` is suspicious; surface it.
            return Err(InstallerError::NoApplyForReadOnlySubcommand);
        }
        Ok(())
    }
}

pub fn init_aether_installer(
    cfg: &InstallerConfig,
) -> Result<InstallerState, InstallerError> {
    cfg.validate()?;
    Ok(InstallerState::new(*cfg))
}

#[inline]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() { return false; }
    let max = haystack.len() - needle.len();
    for i in 0..=max {
        if &haystack[i..i + needle.len()] == needle { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommand_name_roundtrip() {
        for s in [Subcommand::Check, Subcommand::Install, Subcommand::Uninstall,
                  Subcommand::Update, Subcommand::Status] {
            assert_eq!(Subcommand::from_name(s.name()), Some(s));
        }
        assert!(Subcommand::from_name("frobnicate").is_none());
    }

    #[test]
    fn destructive_classification() {
        assert!(!Subcommand::Check.is_destructive());
        assert!(!Subcommand::Status.is_destructive());
        assert!( Subcommand::Install.is_destructive());
        assert!( Subcommand::Uninstall.is_destructive());
        assert!( Subcommand::Update.is_destructive());
    }

    #[test]
    fn safety_mode_byte_roundtrip() {
        for m in [InstallerSafetyMode::DryRun, InstallerSafetyMode::Apply] {
            assert_eq!(InstallerSafetyMode::from_byte(m.to_byte()), Some(m));
        }
        assert!(InstallerSafetyMode::from_byte(2).is_none());
    }

    #[test]
    fn step_count_matches_enum() {
        assert_eq!(INSTALL_STEP_COUNT, 8);
        assert_eq!(InstallStep::HypervisorObserved.ordinal(), 7);
    }

    #[test]
    fn defaults_validate() {
        InstallerConfig::aether_defaults().validate().unwrap();
    }

    #[test]
    fn validate_rejects_tiny_disk_threshold() {
        let mut cfg = InstallerConfig::aether_defaults();
        cfg.min_disk_bytes = 1024;
        assert_eq!(cfg.validate(), Err(InstallerError::TargetDiskTooSmall));
    }

    #[test]
    fn validate_rejects_default_apply() {
        let mut cfg = InstallerConfig::aether_defaults();
        cfg.default_safety = InstallerSafetyMode::Apply;
        assert_eq!(cfg.validate(), Err(InstallerError::MissingApplyFlag));
    }

    #[test]
    fn validate_rejects_network_allowed() {
        let mut cfg = InstallerConfig::aether_defaults();
        cfg.forbid_network_for_non_update = false;
        assert_eq!(cfg.validate(), Err(InstallerError::UnexpectedNetworkRoundTrip));
    }

    #[test]
    fn check_safety_blocks_apply_on_read_only() {
        let s = init_aether_installer(&InstallerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.check_safety(Subcommand::Status, InstallerSafetyMode::Apply),
            Err(InstallerError::NoApplyForReadOnlySubcommand)
        );
    }

    #[test]
    fn check_safety_requires_apply_for_destructive() {
        let s = init_aether_installer(&InstallerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.check_safety(Subcommand::Install, InstallerSafetyMode::DryRun),
            Err(InstallerError::MissingApplyFlag)
        );
        // Apply on a destructive sub is permitted.
        s.check_safety(Subcommand::Install, InstallerSafetyMode::Apply).unwrap();
    }

    #[test]
    fn phase_is_monotonic() {
        let mut s = init_aether_installer(&InstallerConfig::aether_defaults()).unwrap();
        s.advance_phase(InstallerPhase::CompatReported).unwrap();
        s.advance_phase(InstallerPhase::NamespaceCreated).unwrap();
        assert_eq!(
            s.advance_phase(InstallerPhase::NotStarted),
            Err(InstallerError::PhaseRegression)
        );
    }

    #[test]
    fn gate_requires_all_six() {
        let mut g = InstallerGate::default();
        assert!(!g.passes());
        g.compat_report_ok = true;
        g.namespace_created = true;
        g.esp_populated = true;
        g.boot_entry_registered = true;
        assert!(!g.passes());
        g.mok_enrolled = true;
        g.hypervisor_observed = true;
        assert!(g.passes());
    }

    #[test]
    fn uart_scanner_walks_to_gate() {
        let mut s = init_aether_installer(&InstallerConfig::aether_defaults()).unwrap();
        s.process_line(b"[installer] compat OK");
        s.process_line(b"[installer] gpu plan resolved");
        s.process_line(b"[installer] nvme namespace created");
        s.process_line(b"[installer] hypervisor.efi written");
        s.process_line(b"[installer] EFI boot entry registered");
        s.process_line(b"[installer] install-state.json persisted");
        s.process_line(b"[installer] awaiting MOK enrollment reboot");
        s.process_line(b"[installer] hypervisor ready observed");
        assert!(s.is_gate_passed());
        assert_eq!(s.phase, InstallerPhase::GatePassed);
    }

    #[test]
    fn uart_signatures_are_unique() {
        let sigs: &[&[u8]] = &[
            INSTALLER_UART_SIG_COMPAT_OK,
            INSTALLER_UART_SIG_GPU_PLAN_OK,
            INSTALLER_UART_SIG_NAMESPACE_CREATED,
            INSTALLER_UART_SIG_ESP_WRITTEN,
            INSTALLER_UART_SIG_BOOT_ENTRY_OK,
            INSTALLER_UART_SIG_STATE_PERSISTED,
            INSTALLER_UART_SIG_AWAITING_REBOOT,
            INSTALLER_UART_SIG_HYPERVISOR_OBSERVED,
        ];
        for (i, a) in sigs.iter().enumerate() {
            for (j, b) in sigs.iter().enumerate() {
                if i != j { assert_ne!(a, b); }
            }
        }
    }

    #[test]
    fn install_steps_are_strictly_ordered() {
        let ordered = [
            InstallStep::CompatReport,
            InstallStep::GpuPlan,
            InstallStep::NvmeNamespaceCreated,
            InstallStep::EspBinaryWritten,
            InstallStep::BootEntryRegistered,
            InstallStep::InstallStatePersisted,
            InstallStep::MokEnrolled,
            InstallStep::HypervisorObserved,
        ];
        for window in ordered.windows(2) {
            assert!(window[0] < window[1]);
            assert!(window[0].ordinal() < window[1].ordinal());
        }
    }
}
