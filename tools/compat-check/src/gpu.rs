// gpu.rs -- GPU SR-IOV capability check.
//
// Linux:   reads /sys/bus/pci/devices/*/class + sriov_totalvfs (no admin required).
// Windows: enumerates GPUs via PowerShell Win32_VideoController (no admin required).
//          SR-IOV VF count cannot be read on Windows without admin -- reported as Unknown.
//
// SR-IOV MaxVFs > 0 is required for hardware-accelerated Android GPU (Adreno VF assignment).
// A GPU without SR-IOV is a WARN (not FAIL) -- Android boots with software rendering.

use serde::Serialize;

// PCI class codes for display adapters (Linux /sys scan only).
#[cfg(target_os = "linux")]
const PCI_CLASS_VGA:  u32 = 0x0300; // VGA compatible controller (top 16 bits of 24-bit class)
#[cfg(target_os = "linux")]
const PCI_CLASS_3D:   u32 = 0x0302; // 3D controller
#[cfg(target_os = "linux")]
const PCI_CLASS_DISP: u32 = 0x0380; // Display controller (generic)

#[derive(Debug, Clone, Serialize)]
pub struct GpuDevice {
    pub pci_id:       String,   // "0000:01:00.0" on Linux, "PCI\\VEN_..." on Windows
    pub vendor_id:    String,   // "0x1002" (AMD), "0x10de" (NVIDIA), "0x8086" (Intel)
    pub device_id:    String,
    pub name:         String,
    pub sriov_max_vfs: Option<u32>,  // None = unknown (Windows non-admin path)
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuResult {
    pub devices:           Vec<GpuDevice>,
    pub best_max_vfs:      Option<u32>,  // highest sriov_totalvfs across all GPUs
    pub sriov_capable:     bool,         // any GPU with MaxVFs > 0
    pub check_complete:    bool,         // false on Windows (SR-IOV unreadable without admin)
    pub pass:              bool,         // WARN if no SR-IOV, not FAIL
    pub note:              Option<String>,
}

pub fn check() -> GpuResult {
    #[cfg(target_os = "linux")]
    { check_linux() }

    #[cfg(target_os = "windows")]
    { check_windows() }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        GpuResult {
            devices:        Vec::new(),
            best_max_vfs:   None,
            sriov_capable:  false,
            check_complete: false,
            pass:           true, // treat as WARN, not block
            note:           Some("GPU SR-IOV check not supported on this OS.".into()),
        }
    }
}

// ---- Linux ------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn check_linux() -> GpuResult {
    use std::fs;
    use std::path::PathBuf;

    let pci_root = PathBuf::from("/sys/bus/pci/devices");

    let mut devices: Vec<GpuDevice> = Vec::new();

    let entries = match fs::read_dir(&pci_root) {
        Ok(e)  => e,
        Err(_) => {
            return GpuResult {
                devices:        Vec::new(),
                best_max_vfs:   None,
                sriov_capable:  false,
                check_complete: false,
                pass:           true,
                note:           Some("Could not read /sys/bus/pci/devices -- GPU check skipped.".into()),
            };
        }
    };

    for entry in entries.flatten() {
        let dev_path = entry.path();

        // Read PCI class (3 bytes, e.g. "0x030000\n").
        let class_raw = read_sysfs_hex(&dev_path.join("class")).unwrap_or(0);
        let class_top = (class_raw >> 8) as u32; // top 16 bits (class + subclass)

        if class_top != PCI_CLASS_VGA && class_top != PCI_CLASS_3D && class_top != PCI_CLASS_DISP {
            continue;
        }

        let vendor_id = format!("0x{:04x}", read_sysfs_hex(&dev_path.join("vendor")).unwrap_or(0));
        let device_id = format!("0x{:04x}", read_sysfs_hex(&dev_path.join("device")).unwrap_or(0));
        let pci_id    = dev_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // SR-IOV total VFs (file exists only if device supports SR-IOV).
        let sriov_max_vfs = read_sysfs_u32(&dev_path.join("sriov_totalvfs"));

        let name = resolve_gpu_name(&vendor_id, &device_id);

        devices.push(GpuDevice {
            pci_id,
            vendor_id,
            device_id,
            name,
            sriov_max_vfs,
        });
    }

    build_result(devices, true)
}

#[cfg(target_os = "linux")]
fn read_sysfs_hex(path: &std::path::Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim().trim_start_matches("0x");
    u64::from_str_radix(trimmed, 16).ok()
}

#[cfg(target_os = "linux")]
fn read_sysfs_u32(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse::<u32>().ok()
}

// ---- Windows ----------------------------------------------------------------

#[cfg(target_os = "windows")]
fn check_windows() -> GpuResult {
    // Use PowerShell to enumerate GPUs via WMI -- no admin required.
    // SR-IOV VF count requires reading PCI config space which needs admin;
    // report as None (unknown) on this path.
    let ps_cmd = concat!(
        "Get-WmiObject Win32_VideoController | ",
        "Select-Object Name,PNPDeviceID | ",
        "ConvertTo-Json -Compress"
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
        .output();

    let mut devices: Vec<GpuDevice> = Vec::new();

    if let Ok(out) = output {
        let raw  = String::from_utf8_lossy(&out.stdout);
        // PowerShell ConvertTo-Json HTML-escapes '&' as '&'.
        // Unescape before parsing so vendor IDs like "VEN_10DE&DEV_..." split correctly.
        let text = raw.replace("\\u0026", "&");
        // Parse minimal JSON: array or single object.
        devices = parse_wmi_json(&text);
    }

    if devices.is_empty() {
        // Fallback: at least report that we could not enumerate.
        devices.push(GpuDevice {
            pci_id:       "unknown".into(),
            vendor_id:    "unknown".into(),
            device_id:    "unknown".into(),
            name:         "GPU enumeration failed".into(),
            sriov_max_vfs: None,
        });
    }

    let mut result = build_result(devices, false);
    result.note = Some(
        "Windows: GPU names listed. SR-IOV MaxVFs cannot be read without admin. \
         Run on Linux or re-run as Administrator for full GPU SR-IOV check."
            .into(),
    );
    result
}

#[cfg(target_os = "windows")]
fn parse_wmi_json(text: &str) -> Vec<GpuDevice> {
    // Minimal hand-rolled parse -- avoids pulling in a full JSON dep for this path.
    // WMI returns either a single object {} or an array [{},...].
    // We extract "Name" and "PNPDeviceID" fields only.
    let mut devices = Vec::new();

    // Split into per-object chunks by looking for Name field.
    for chunk in text.split("\"Name\"") {
        if let Some(name_start) = chunk.find(':') {
            let rest = &chunk[name_start + 1..].trim_start_matches([' ', '"']);
            let name = rest
                .split('"')
                .next()
                .unwrap_or("Unknown GPU")
                .trim()
                .replace("\\u0026", "&")
                .replace("&amp;", "&");

            if name.is_empty() || name == "Unknown GPU" {
                continue;
            }

            // Extract vendor_id from PNPDeviceID: "PCI\\VEN_1002&DEV_687F..."
            let (vendor_id, device_id, pci_id) = extract_pnp_ids(chunk);

            devices.push(GpuDevice {
                pci_id,
                vendor_id,
                device_id,
                name,
                sriov_max_vfs: None, // unknown without admin
            });
        }
    }
    devices
}

#[cfg(target_os = "windows")]
fn extract_pnp_ids(chunk: &str) -> (String, String, String) {
    // PNPDeviceID looks like: "PCI\\VEN_1002&DEV_687F&..."
    let mut vendor = "unknown".to_owned();
    let mut device = "unknown".to_owned();
    let mut pci_id = "unknown".to_owned();

    if let Some(start) = chunk.find("PCI\\\\VEN_") {
        let rest = &chunk[start + 9..];
        if let Some(ven) = rest.split('&').next() {
            vendor = format!("0x{}", ven.to_lowercase());
        }
        if let Some(dev_part) = rest.split("DEV_").nth(1) {
            if let Some(dev) = dev_part.split('&').next() {
                device = format!("0x{}", dev.to_lowercase());
            }
        }
        // PCI address usually in SUBSYS or LOCATION -- use VEN_DEV as ID.
        pci_id = format!("PCI\\VEN_{}", &rest[..rest.find('"').unwrap_or(rest.len())]);
    }

    (vendor, device, pci_id)
}

// ---- Shared helpers ---------------------------------------------------------

fn build_result(devices: Vec<GpuDevice>, check_complete: bool) -> GpuResult {
    let best_max_vfs = devices
        .iter()
        .filter_map(|d| d.sriov_max_vfs)
        .max();

    let sriov_capable = best_max_vfs.map(|v| v > 0).unwrap_or(false);

    // GPU SR-IOV is WARN (not FAIL): Android boots with software rendering without it.
    let pass = true;

    let note = if !check_complete {
        None // caller sets note for Windows
    } else if sriov_capable {
        None
    } else if devices.is_empty() {
        Some("No GPU detected via PCI scan.".into())
    } else {
        Some(
            "No SR-IOV capable GPU found. Android will use software rendering (llvmpipe). \
             Hardware GPU acceleration requires a GPU with SR-IOV support (e.g. Adreno, \
             Intel Arc, or a Radeon Pro with SRIOV enabled in BIOS)."
                .into(),
        )
    };

    GpuResult {
        devices,
        best_max_vfs,
        sriov_capable,
        check_complete,
        pass,
        note,
    }
}

/// Best-effort GPU name lookup for common vendor+device combos (Linux path).
#[cfg(target_os = "linux")]
/// Real implementation would use a PCI ID database; this covers AETHER targets.
fn resolve_gpu_name(vendor_id: &str, device_id: &str) -> String {
    let vendor_label = match vendor_id {
        "0x1002" => "AMD Radeon",
        "0x10de" => "NVIDIA",
        "0x8086" => "Intel",
        _        => "Unknown GPU",
    };
    format!("{} (device {})", vendor_label, device_id)
}
