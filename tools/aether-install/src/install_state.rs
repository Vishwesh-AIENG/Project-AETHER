// install_state.rs -- Persistent state file for the AETHER installer.
//
// Why this exists: the install pipeline writes to multiple subsystems
// (UEFI variables, ESP filesystem, NVMe namespaces). A second `install`
// invocation has to discover what was already done so it doesn't duplicate
// work or, worse, create a divergent state. The skills file (P5-SKILLS.md)
// is explicit: "Installer operations must be idempotent."
//
// The state file lives at:
//   Linux:   /var/lib/aether/install-state.json   (root-owned)
//   Windows: %ProgramData%\AETHER\install-state.json
//
// It is a plain JSON document. Schema is versioned via `schema_version` so
// future installer releases can migrate older states cleanly.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::gpu_config::GpuPlan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallState {
    pub schema_version: u32,                  // bump on incompatible change
    pub install_id:     String,               // random per-install identifier
    pub version:        String,               // AETHER release version installed
    pub installed_at:   String,               // ISO-8601 timestamp
    pub last_updated:   String,               // ISO-8601 timestamp
    pub esp_mount:      String,               // ESP mount point used by the install
    pub esp_partition_guid: String,           // GPT GUID of the ESP partition
    pub target_disk:    String,               // NVMe device path
    pub android_nsid:   Option<u32>,          // NVMe namespace ID for Android (None until allocated)
    pub config_partition_guid: Option<String>, // AETHER config partition GUID
    pub boot_entry_index: Option<u16>,        // Boot#### index assigned
    pub gpu_plan:       Option<GpuPlan>,      // chosen GPU mode
    pub active_slot:    Slot,                 // A/B for OTA
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    A,
    B,
}

impl Default for InstallState {
    fn default() -> Self {
        InstallState {
            schema_version: 1,
            install_id:     String::new(),
            version:        env!("CARGO_PKG_VERSION").to_string(),
            installed_at:   String::new(),
            last_updated:   String::new(),
            esp_mount:      String::new(),
            esp_partition_guid: String::new(),
            target_disk:    String::new(),
            android_nsid:   None,
            config_partition_guid: None,
            boot_entry_index: None,
            gpu_plan:       None,
            active_slot:    Slot::A,
        }
    }
}

impl InstallState {
    pub fn path() -> PathBuf {
        #[cfg(target_os = "linux")]
        { PathBuf::from("/var/lib/aether/install-state.json") }
        #[cfg(target_os = "windows")]
        {
            let pd = std::env::var("ProgramData")
                .unwrap_or_else(|_| "C:\\ProgramData".to_string());
            PathBuf::from(format!("{}\\AETHER\\install-state.json", pd))
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        { PathBuf::from("./aether-install-state.json") }
    }

    /// Load existing state; returns None if no install is present (not an error).
    pub fn load() -> Result<Option<InstallState>, std::io::Error> {
        let p = Self::path();
        match std::fs::read(&p) {
            Ok(bytes) => {
                match serde_json::from_slice::<InstallState>(&bytes) {
                    Ok(s) => Ok(Some(s)),
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("install state at {:?} is corrupt: {}", p, e))),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persist state atomically: write to a temp file, then rename.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let p = Self::path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = p.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// Remove the state file (used by uninstall).
    pub fn delete() -> Result<(), std::io::Error> {
        let p = Self::path();
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Returns true if an existing install is described by this state.
    pub fn is_installed(&self) -> bool {
        self.boot_entry_index.is_some() && !self.install_id.is_empty()
    }

    /// Flip the active A/B slot (used by OTA update).
    pub fn flip_slot(&mut self) {
        self.active_slot = match self.active_slot {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_empty() {
        let s = InstallState::default();
        assert!(!s.is_installed());
        assert_eq!(s.active_slot, Slot::A);
    }

    #[test]
    fn flip_slot_toggles() {
        let mut s = InstallState::default();
        assert_eq!(s.active_slot, Slot::A);
        s.flip_slot();
        assert_eq!(s.active_slot, Slot::B);
        s.flip_slot();
        assert_eq!(s.active_slot, Slot::A);
    }

    #[test]
    fn is_installed_requires_id_and_boot_entry() {
        let mut s = InstallState::default();
        s.boot_entry_index = Some(0x0042);
        assert!(!s.is_installed(), "install_id still empty");
        s.install_id = "deadbeef".into();
        assert!(s.is_installed());
    }

    #[test]
    fn json_round_trip() {
        let s = InstallState {
            install_id: "abc123".into(),
            version: "0.1.0".into(),
            installed_at: "2026-05-20T16:30:00Z".into(),
            last_updated: "2026-05-20T16:30:00Z".into(),
            esp_mount: "/boot/efi".into(),
            esp_partition_guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B".into(),
            target_disk: "/dev/nvme0".into(),
            android_nsid: Some(2),
            config_partition_guid: Some("8AB6F88D-BAF1-4E0E-9F26-1234567890AB".into()),
            boot_entry_index: Some(0x0042),
            gpu_plan: None,
            active_slot: Slot::B,
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: InstallState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.install_id, "abc123");
        assert_eq!(back.boot_entry_index, Some(0x0042));
        assert_eq!(back.active_slot, Slot::B);
    }
}
