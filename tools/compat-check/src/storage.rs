// storage.rs -- Storage space check.
//
// Minimum: 64 GiB free on any single drive.
// NVMe preferred (detected by device name heuristic).
// Uses sysinfo Disks (no admin required).

use serde::Serialize;
use sysinfo::Disks;

pub const MINIMUM_FREE_GIB: u64 = 64;

#[derive(Debug, Clone, Serialize)]
pub struct DiskEntry {
    pub name:            String,
    pub mount_point:     String,
    pub total_gib:       u64,
    pub available_gib:   u64,
    pub is_nvme:         bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageResult {
    pub drives:                Vec<DiskEntry>,
    pub largest_free_gib:      u64,
    pub minimum_free_gib:      u64,
    pub nvme_present:          bool,
    pub pass:                  bool,
    pub note:                  Option<String>,
}

pub fn check() -> StorageResult {
    let disks = Disks::new_with_refreshed_list();

    let mut drives: Vec<DiskEntry> = Vec::new();

    for disk in &disks {
        let raw_name = disk.name().to_string_lossy().to_string();
        let mount    = disk.mount_point().to_string_lossy().to_string();

        // NVMe detection: device name or mount contains "nvme",
        // or sysinfo DiskKind is SSD (best we can do on Windows).
        let is_nvme = raw_name.to_lowercase().contains("nvme")
            || mount.to_lowercase().contains("nvme");

        let total_bytes = disk.total_space();
        let avail_bytes = disk.available_space();

        drives.push(DiskEntry {
            name:          raw_name,
            mount_point:   mount,
            total_gib:     total_bytes / (1024 * 1024 * 1024),
            available_gib: avail_bytes / (1024 * 1024 * 1024),
            is_nvme,
        });
    }

    // Sort largest-free-first for display.
    drives.sort_by(|a, b| b.available_gib.cmp(&a.available_gib));

    let largest_free_gib = drives.first().map(|d| d.available_gib).unwrap_or(0);
    let nvme_present     = drives.iter().any(|d| d.is_nvme);
    let pass             = largest_free_gib >= MINIMUM_FREE_GIB;

    let note = if drives.is_empty() {
        Some("No drives detected. Run with admin privileges if drives are missing.".into())
    } else if !pass {
        Some(format!(
            "Largest free partition is {} GiB. AETHER Android partition requires at least {} GiB.",
            largest_free_gib, MINIMUM_FREE_GIB
        ))
    } else if !nvme_present {
        Some("No NVMe drive detected. AETHER works on SATA SSD/HDD but NVMe is strongly recommended for performance.".into())
    } else {
        None
    };

    StorageResult {
        drives,
        largest_free_gib,
        minimum_free_gib: MINIMUM_FREE_GIB,
        nvme_present,
        pass,
        note,
    }
}
