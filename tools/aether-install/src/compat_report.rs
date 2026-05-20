// compat_report.rs -- Deserialize-compatible mirror of aether-compat's JSON
// schema. This is a local copy of the report types so the installer doesn't
// need to take a build dependency on the compat-check crate -- it spawns the
// aether-compat binary and parses its --json output.
//
// Schema MUST stay in lockstep with tools/compat-check/src/report.rs. If a
// field is added there, mirror it here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatReport {
    pub schema_version: u32,
    pub timestamp:      String,
    pub host_arch:      String,
    pub cpu:            CpuResult,
    pub memory:         MemoryResult,
    pub storage:        StorageResult,
    pub gpu:            GpuResult,
    pub overall:        String,  // "Pass" | "Warn" | "Fail"
    pub notes:          Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuResult {
    pub vendor:        String,
    pub brand:         String,
    pub logical_cores: u32,
    pub vmx_supported: bool,
    pub svm_supported: bool,
    pub tier:          String,
    pub pass:          bool,
    pub note:          Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryResult {
    pub total_bytes: u64,
    pub total_gib:   u64,
    pub minimum_gib: u64,
    pub pass:        bool,
    pub note:        Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResult {
    pub drives:           Vec<DiskEntry>,
    pub largest_free_gib: u64,
    pub minimum_free_gib: u64,
    pub nvme_present:     bool,
    pub pass:             bool,
    pub note:             Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskEntry {
    pub name:          String,
    pub mount_point:   String,
    pub total_gib:     u64,
    pub available_gib: u64,
    pub is_nvme:       bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuResult {
    pub devices:        Vec<GpuDevice>,
    pub best_max_vfs:   Option<u32>,
    pub sriov_capable:  bool,
    pub check_complete: bool,
    pub pass:           bool,
    pub note:           Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDevice {
    pub pci_id:        String,
    pub vendor_id:     String,
    pub device_id:     String,
    pub name:          String,
    pub sriov_max_vfs: Option<u32>,
}

impl CompatReport {
    #[allow(dead_code)] pub fn is_pass(&self) -> bool { self.overall == "Pass" }
    #[allow(dead_code)] pub fn is_warn(&self) -> bool { self.overall == "Warn" }
    pub fn is_fail(&self) -> bool { self.overall == "Fail" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_minimal_json() {
        let json = serde_json::json!({
            "schema_version": 1,
            "timestamp": "2026-05-20T16:17:25Z",
            "host_arch": "x86_64",
            "cpu": {
                "vendor": "AuthenticAMD",
                "brand": "Ryzen 7 5700X",
                "logical_cores": 16,
                "vmx_supported": false,
                "svm_supported": true,
                "tier": "X86Amd",
                "pass": true,
                "note": null
            },
            "memory": {
                "total_bytes": 34000000000u64,
                "total_gib": 31,
                "minimum_gib": 8,
                "pass": true,
                "note": null
            },
            "storage": {
                "drives": [],
                "largest_free_gib": 100,
                "minimum_free_gib": 64,
                "nvme_present": true,
                "pass": true,
                "note": null
            },
            "gpu": {
                "devices": [],
                "best_max_vfs": null,
                "sriov_capable": false,
                "check_complete": true,
                "pass": true,
                "note": null
            },
            "overall": "Pass",
            "notes": []
        });
        let r: CompatReport = serde_json::from_value(json).unwrap();
        assert!(r.is_pass());
        assert_eq!(r.cpu.vendor, "AuthenticAMD");
    }
}
