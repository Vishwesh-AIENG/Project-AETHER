// gpu_config.rs -- GPU mode auto-selection logic.
//
// Decision tree implemented here:
//
//   SR-IOV MaxVFs > 0 ?
//       YES  -> auto-select SR-IOV partition (no prompt)
//   SR-IOV = 0 or Unknown ?
//       NVIDIA consumer       -> prompt: [1] software [2] passthrough (warn on reset bug)
//       AMD discrete (no SR-IOV) -> prompt: [1] software [2] passthrough  (no reset warning)
//       Intel integrated      -> auto-select software (cannot safely pass through iGPU)
//       Unknown / no GPU      -> auto-select software, warn user
//
// The caller passes in a parsed CompatReport from aether-compat --json. The
// function returns a GpuPlan describing what to do and how to communicate it
// to the user. Prompts are NOT issued from this module -- it just emits a
// Plan that the install pipeline can show.

use crate::compat_report::{CompatReport, GpuDevice};
use crate::nvidia_db;
use serde::{Deserialize, Serialize};

// ---- Public types -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuMode {
    /// Hardware SR-IOV partition: a VF gets assigned to Android.
    /// Best path. Host (when re-purposed via dual-boot) gets the PF; Android
    /// gets a VF. Or just give Android one of the VFs.
    Sriov,
    /// Whole GPU assigned to Android. Host gets no GPU while Android runs.
    /// For AETHER's dual-boot model, "host" means the Windows side -- which
    /// isn't running concurrently anyway.
    Passthrough,
    /// llvmpipe software rendering inside the Android guest. No CPU/GPU
    /// hardware sharing concerns; works on any host.
    Software,
}

impl GpuMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            GpuMode::Sriov       => "sriov",
            GpuMode::Passthrough => "passthrough",
            GpuMode::Software    => "software",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuVendorKind {
    NvidiaConsumer,
    NvidiaProfessional,
    AmdDiscrete,
    AmdIntegrated,
    IntelIntegrated,
    IntelDiscrete,    // Arc
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPlan {
    /// The chosen mode (final decision if not interactive, or default if a
    /// menu is presented).
    pub mode: GpuMode,
    /// Whether the choice is automatic (true) or requires user confirmation
    /// (false). When false, the install pipeline must show a menu before
    /// proceeding.
    pub auto: bool,
    /// Human-readable explanation of why this mode was chosen.
    pub reason: String,
    /// Warnings to display to the user. Always shown.
    pub warnings: Vec<String>,
    /// The GPU that this plan refers to (None if no GPU was detected).
    pub gpu_label: Option<String>,
    /// PCI vendor/device IDs (for reproducibility in the install state file).
    pub pci_vendor_id: Option<String>,
    pub pci_device_id: Option<String>,
}

// ---- Public entry point -----------------------------------------------------

/// Compute the GPU plan from a CompatReport.
///
/// `override_mode`: if the user passed `--gpu MODE` on the CLI, force that
/// choice (still emit warnings if the choice doesn't match the hardware).
pub fn decide(report: &CompatReport, override_mode: Option<GpuMode>) -> GpuPlan {
    // Pick the "primary" GPU: highest sriov_max_vfs first, then first listed.
    let primary = pick_primary_gpu(&report.gpu.devices);

    // No GPU at all -- fall back to software.
    let Some(gpu) = primary else {
        let mut plan = GpuPlan {
            mode: GpuMode::Software,
            auto: true,
            reason: "No GPU detected by PCI scan.".into(),
            warnings: vec![
                "No GPU found. Android will run with software rendering (llvmpipe).".into(),
            ],
            gpu_label: None,
            pci_vendor_id: None,
            pci_device_id: None,
        };
        if let Some(forced) = override_mode {
            plan.warnings.push(format!(
                "Override --gpu {} requested but no GPU detected. Falling back to software.",
                forced.as_str()
            ));
        }
        return plan;
    };

    let vendor = classify_vendor(gpu);
    let label  = gpu.name.clone();
    let pci_v  = gpu.vendor_id.clone();
    let pci_d  = gpu.device_id.clone();

    // Path 1: SR-IOV capable -> auto-select SR-IOV.
    let has_sriov = gpu.sriov_max_vfs.unwrap_or(0) > 0;
    if has_sriov {
        let n = gpu.sriov_max_vfs.unwrap_or(0);
        let mut plan = GpuPlan {
            mode: GpuMode::Sriov,
            auto: true,
            reason: format!("SR-IOV capable -- {} VFs available. Auto-configured.", n),
            warnings: Vec::new(),
            gpu_label: Some(label),
            pci_vendor_id: Some(pci_v),
            pci_device_id: Some(pci_d),
        };
        if let Some(forced) = override_mode {
            if forced != GpuMode::Sriov {
                plan.mode = forced;
                plan.auto = false;
                plan.reason = format!(
                    "Override --gpu {} requested (hardware supports SR-IOV but user opted out).",
                    forced.as_str()
                );
            }
        }
        return plan;
    }

    // Path 2: No SR-IOV. Branch on vendor.
    let (default_mode, auto, mut warnings, reason) = match vendor {
        GpuVendorKind::NvidiaConsumer => {
            let mut warns = Vec::new();
            let parsed_id = parse_hex_device_id(&pci_d);
            match parsed_id.and_then(nvidia_db::lookup) {
                Some(entry) => match entry.severity {
                    nvidia_db::ResetBugSeverity::Affected => warns.push(format!(
                        "{} is known to be affected by the NVIDIA reset bug. \
                         After an Android session ends, return to Windows by power-OFF \
                         then power-ON. A warm reboot may leave the GPU in a bad state.",
                        entry.name
                    )),
                    nvidia_db::ResetBugSeverity::LikelyAffected => warns.push(format!(
                        "{} is likely affected by the NVIDIA reset bug. \
                         If a warm reboot to Windows leaves the GPU unrecognised, power-cycle.",
                        entry.name
                    )),
                    nvidia_db::ResetBugSeverity::LikelyFixed => warns.push(format!(
                        "{}: reset bug largely fixed in Ada Lovelace generation but \
                         not guaranteed. If reboot to Windows fails, power-cycle.",
                        entry.name
                    )),
                },
                None => warns.push(
                    "NVIDIA consumer GPU: reset behaviour unknown on this exact device ID. \
                     Passthrough works, but if a warm reboot to Windows leaves the GPU in a \
                     bad state, use power-OFF then power-ON instead.".into()
                ),
            }
            (GpuMode::Passthrough, false, warns,
             "NVIDIA consumer GPU without SR-IOV. Recommend full passthrough \
              (Android gets the GPU; Windows is on the other boot option, \
              so they never compete).".to_string())
        }

        GpuVendorKind::AmdDiscrete => (
            GpuMode::Passthrough,
            false,
            Vec::new(),
            "AMD discrete GPU without SR-IOV. Full passthrough recommended; \
             AMD resets cleanly on reboot, so no reset bug warning.".to_string()
        ),

        GpuVendorKind::IntelIntegrated => (
            GpuMode::Software,
            true,
            vec![
                "Intel integrated GPU cannot be safely passed through (it backs the \
                 display the firmware uses for boot). Auto-selecting software rendering.".into()
            ],
            "Intel iGPU detected -- software rendering is the only safe choice.".to_string()
        ),

        GpuVendorKind::AmdIntegrated => (
            GpuMode::Software,
            true,
            vec![
                "AMD integrated GPU (APU) cannot be safely passed through. \
                 Auto-selecting software rendering.".into()
            ],
            "AMD APU iGPU detected -- software rendering only.".to_string()
        ),

        GpuVendorKind::IntelDiscrete => (
            GpuMode::Passthrough,
            false,
            vec![
                "Intel Arc detected without SR-IOV exposed. If your firmware supports \
                 Resizable BAR and SR-IOV for this card, enable both in BIOS and re-run \
                 the installer to get a partition instead of full passthrough.".into()
            ],
            "Intel Arc discrete GPU without SR-IOV. Full passthrough.".to_string()
        ),

        GpuVendorKind::NvidiaProfessional => (
            GpuMode::Passthrough,
            true,
            Vec::new(),
            "NVIDIA professional GPU (Quadro / A-series). Clean FLR. Full passthrough.".to_string()
        ),

        GpuVendorKind::Unknown => (
            GpuMode::Software,
            true,
            vec![format!(
                "GPU vendor unrecognised (vendor_id={}). Falling back to software rendering \
                 to avoid blind passthrough risk. Pass --gpu passthrough to override.",
                pci_v
            )],
            "Unknown GPU vendor -- defaulting to software rendering.".to_string()
        ),
    };

    // Apply CLI override if present.
    let (final_mode, final_auto) = match override_mode {
        Some(forced) if forced != default_mode => {
            warnings.push(format!(
                "User override: --gpu {} (default would have been {}).",
                forced.as_str(),
                default_mode.as_str()
            ));
            (forced, true)   // override = no prompt
        }
        Some(_) => (default_mode, auto),
        None    => (default_mode, auto),
    };

    GpuPlan {
        mode: final_mode,
        auto: final_auto,
        reason,
        warnings,
        gpu_label: Some(label),
        pci_vendor_id: Some(pci_v),
        pci_device_id: Some(pci_d),
    }
}

// ---- Helpers ----------------------------------------------------------------

fn pick_primary_gpu(devices: &[GpuDevice]) -> Option<&GpuDevice> {
    // Prefer the GPU with the highest known sriov_max_vfs; ties broken by
    // first occurrence. None vs Some(0) tie-broken in favour of Some(0)
    // (an explicit zero is more informative than "unknown").
    let mut best: Option<&GpuDevice> = None;
    let mut best_score: i64 = -2;

    for d in devices {
        // Skip virtual/non-PCI entries (e.g. "Easy&Light Display HUB Virtual Display")
        // which lack a real PCI vendor ID.
        if d.vendor_id == "unknown" || d.vendor_id.is_empty() {
            continue;
        }
        let score: i64 = match d.sriov_max_vfs {
            Some(n) => n as i64,
            None    => -1,
        };
        if score > best_score {
            best_score = score;
            best = Some(d);
        }
    }
    best.or_else(|| devices.first())
}

fn classify_vendor(gpu: &GpuDevice) -> GpuVendorKind {
    let v = gpu.vendor_id.to_ascii_lowercase();
    match v.as_str() {
        "0x10de" => {
            // Heuristic: device ID range.
            if let Some(id) = parse_hex_device_id(&gpu.device_id) {
                if nvidia_db::is_consumer_device_id(id) {
                    GpuVendorKind::NvidiaConsumer
                } else {
                    GpuVendorKind::NvidiaProfessional
                }
            } else {
                GpuVendorKind::NvidiaConsumer  // best guess
            }
        }
        "0x1002" => {
            // AMD: integrated APUs have device IDs that overlap with discrete
            // cards across generations. Distinguish by looking at the device-
            // name hint (Ryzen / APU / Radeon Graphics suggests integrated).
            let name = gpu.name.to_ascii_lowercase();
            if name.contains("ryzen") || name.contains("apu") || name.contains("vega")
                || name.contains("integrated") || name.contains("renoir")
                || name.contains("cezanne") || name.contains("rembrandt")
                || name.contains("phoenix")
            {
                GpuVendorKind::AmdIntegrated
            } else {
                GpuVendorKind::AmdDiscrete
            }
        }
        "0x8086" => {
            // Intel: Arc discrete uses PCI class 3D-controller (subclass 0x02);
            // integrated uses VGA (subclass 0x00). We don't have subclass info
            // from compat-check's flat output, so use device name hints.
            let name = gpu.name.to_ascii_lowercase();
            if name.contains("arc")
                || name.contains("dg2")
                || name.contains("a380") || name.contains("a580")
                || name.contains("a750") || name.contains("a770")
            {
                GpuVendorKind::IntelDiscrete
            } else {
                GpuVendorKind::IntelIntegrated
            }
        }
        _ => GpuVendorKind::Unknown,
    }
}

fn parse_hex_device_id(s: &str) -> Option<u16> {
    let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(stripped, 16).ok()
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat_report::{
        CompatReport, CpuResult, MemoryResult, StorageResult, GpuResult, GpuDevice,
    };

    fn empty_report() -> CompatReport {
        CompatReport {
            schema_version: 1,
            timestamp: "test".into(),
            host_arch: "x86_64".into(),
            cpu: CpuResult {
                vendor: "AuthenticAMD".into(),
                brand: "Ryzen 7 5700X".into(),
                logical_cores: 16,
                vmx_supported: false,
                svm_supported: true,
                tier: "X86Amd".into(),
                pass: true,
                note: None,
            },
            memory: MemoryResult {
                total_bytes: 34_000_000_000,
                total_gib: 31,
                minimum_gib: 8,
                pass: true,
                note: None,
            },
            storage: StorageResult {
                drives: Vec::new(),
                largest_free_gib: 200,
                minimum_free_gib: 64,
                nvme_present: true,
                pass: true,
                note: None,
            },
            gpu: GpuResult {
                devices: Vec::new(),
                best_max_vfs: None,
                sriov_capable: false,
                check_complete: true,
                pass: true,
                note: None,
            },
            overall: "Pass".into(),
            notes: Vec::new(),
        }
    }

    fn gpu(vendor: &str, device: &str, name: &str, vfs: Option<u32>) -> GpuDevice {
        GpuDevice {
            pci_id: "0000:01:00.0".into(),
            vendor_id: vendor.into(),
            device_id: device.into(),
            name: name.into(),
            sriov_max_vfs: vfs,
        }
    }

    #[test]
    fn no_gpu_falls_back_to_software() {
        let r = empty_report();
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Software);
        assert!(plan.auto);
        assert!(plan.gpu_label.is_none());
    }

    #[test]
    fn sriov_capable_auto_selects_sriov() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x8086", "0x56a0", "Intel Arc A380", Some(4)));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Sriov);
        assert!(plan.auto);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn rtx_3060_prompts_with_reset_warning() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x10de", "0x2504", "NVIDIA GeForce RTX 3060", None));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Passthrough);
        assert!(!plan.auto, "consumer NVIDIA should require user confirmation");
        assert!(plan.warnings.iter().any(|w| w.contains("3060")
                                               && w.to_lowercase().contains("reset")));
    }

    #[test]
    fn amd_discrete_no_sriov_prompts_without_reset_warning() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x1002", "0x73bf", "Radeon RX 6800 XT", None));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Passthrough);
        assert!(!plan.auto);
        assert!(!plan.warnings.iter().any(|w| w.to_lowercase().contains("reset bug")));
    }

    #[test]
    fn intel_integrated_auto_selects_software() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x8086", "0x9a49", "Intel Iris Xe Graphics", None));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Software);
        assert!(plan.auto);
    }

    #[test]
    fn intel_arc_passthrough_when_sriov_off() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x8086", "0x56a5", "Intel Arc A380", None));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Passthrough);
        assert!(!plan.auto);
    }

    #[test]
    fn cli_override_to_software_forces_software() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x10de", "0x2504", "RTX 3060", None));
        let plan = decide(&r, Some(GpuMode::Software));
        assert_eq!(plan.mode, GpuMode::Software);
        assert!(plan.auto);
        assert!(plan.warnings.iter().any(|w| w.contains("override")
                                                || w.contains("Override")));
    }

    #[test]
    fn cli_override_to_sriov_when_hardware_supports_it_no_change() {
        let mut r = empty_report();
        r.gpu.devices.push(gpu("0x8086", "0x56a0", "Intel Arc A380", Some(4)));
        let plan = decide(&r, Some(GpuMode::Sriov));
        assert_eq!(plan.mode, GpuMode::Sriov);
        assert!(plan.auto);
    }

    #[test]
    fn skips_virtual_display_picks_real_gpu() {
        let mut r = empty_report();
        // Add a Windows "virtual display HUB" first (vendor_id unknown), then a real GPU.
        r.gpu.devices.push(gpu("unknown", "unknown", "Easy&Light Display HUB Virtual Display", None));
        r.gpu.devices.push(gpu("0x10de", "0x2504", "NVIDIA GeForce RTX 3060", None));
        let plan = decide(&r, None);
        assert_eq!(plan.mode, GpuMode::Passthrough);
        assert_eq!(plan.gpu_label.as_deref(), Some("NVIDIA GeForce RTX 3060"));
    }
}
