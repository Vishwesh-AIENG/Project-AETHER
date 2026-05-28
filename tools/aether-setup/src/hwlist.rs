// hwlist.rs — enumerate the candidate physical disks the user might pick as
// the AETHER target. On Windows we use `wmic diskdrive list` because it does
// not require a build-time dependency on the Win32 crate; we parse its CSV
// output. Falls back to a single placeholder entry on non-Windows hosts so
// developers can run the GUI on Linux/macOS for layout iteration.

use std::process::Command;

#[derive(Debug, Clone)]
pub struct Disk {
    /// e.g. \\.\PHYSICALDRIVE1 — the path aether-install expects.
    pub device_path: String,
    /// Vendor/model string from WMI (e.g. "Samsung SSD 990 PRO 2TB").
    pub model: String,
    /// Capacity in bytes; 0 if unknown.
    pub size_bytes: u64,
    /// "Fixed" / "Removable" — discourage installing onto USB by default.
    pub kind: String,
}

impl Disk {
    pub fn size_human(&self) -> String {
        let b = self.size_bytes as f64;
        if b >= 1_000_000_000_000.0 {
            format!("{:.1} TB", b / 1_000_000_000_000.0)
        } else if b >= 1_000_000_000.0 {
            format!("{:.0} GB", b / 1_000_000_000.0)
        } else if b > 0.0 {
            format!("{:.0} MB", b / 1_000_000.0)
        } else {
            "unknown".to_string()
        }
    }
}

#[cfg(target_os = "windows")]
pub fn enumerate() -> Vec<Disk> {
    // CSV columns: Node,Caption,DeviceID,MediaType,Model,Size
    let out = Command::new("wmic")
        .args(["diskdrive", "list", "brief", "/format:csv"])
        .output();
    let Ok(out) = out else { return Vec::new(); };
    if !out.status.success() { return Vec::new(); }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut disks = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.trim().is_empty() { continue; } // header / blank
        let cols: Vec<&str> = line.split(',').collect();
        // wmic brief columns vary by version; we look up by name in the
        // header row when present, but the brief form is stable enough that
        // index lookup is OK here.
        if cols.len() < 5 { continue; }
        let device_path = cols.iter().find(|c| c.starts_with("\\\\.\\PHYSICALDRIVE"))
            .map(|s| s.to_string())
            .unwrap_or_default();
        if device_path.is_empty() { continue; }
        let model = cols.get(4).unwrap_or(&"").trim().to_string();
        let size_bytes = cols.last()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let kind = cols.get(3).unwrap_or(&"Fixed").trim().to_string();
        disks.push(Disk { device_path, model, size_bytes, kind });
    }
    disks
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate() -> Vec<Disk> {
    // Stub for dev iteration on non-Windows hosts.
    vec![Disk {
        device_path: "/dev/nvme0n1".to_string(),
        model: "Developer stub disk".to_string(),
        size_bytes: 1_000_000_000_000,
        kind: "Fixed".to_string(),
    }]
}
