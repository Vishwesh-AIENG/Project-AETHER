// cpu.rs -- CPU capability detection for AETHER compat checker.
//
// x86_64: uses raw-cpuid to read vendor, brand, VMX (Intel VT-x), SVM (AMD-V).
// aarch64: reads /proc/cpuinfo on Linux; reports ARM64 tier.
// Other arches: Unsupported.

use serde::Serialize;

// ---- Public types -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[allow(dead_code)] // Arm64 variant constructed only on aarch64 host
pub enum CpuTier {
    /// Intel x86-64 with VT-x enabled.
    X86Intel,
    /// AMD x86-64 with SVM enabled.
    X86Amd,
    /// AArch64 (Snapdragon-class) with EL2 virtualization.
    Arm64,
    /// VT-x / SVM disabled in BIOS, or unrecognised CPU.
    Unsupported,
}

impl CpuTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            CpuTier::X86Intel    => "x86 Intel (VT-x)",
            CpuTier::X86Amd      => "x86 AMD (SVM)",
            CpuTier::Arm64       => "ARM64 (EL2)",
            CpuTier::Unsupported => "Unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuResult {
    pub vendor:          String,
    pub brand:           String,
    pub logical_cores:   u32,
    pub vmx_supported:   bool,   // Intel VT-x
    pub svm_supported:   bool,   // AMD-V / SVM
    pub tier:            CpuTier,
    pub pass:            bool,
    pub note:            Option<String>,
}

// ---- Entry point ------------------------------------------------------------

pub fn check() -> CpuResult {
    #[cfg(target_arch = "x86_64")]
    { check_x86() }

    #[cfg(target_arch = "aarch64")]
    { check_arm64() }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        CpuResult {
            vendor:        "Unknown".into(),
            brand:         "Unknown".into(),
            logical_cores: 0,
            vmx_supported: false,
            svm_supported: false,
            tier:          CpuTier::Unsupported,
            pass:          false,
            note:          Some("CPU architecture not supported by AETHER.".into()),
        }
    }
}

// ---- x86_64 -----------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn check_x86() -> CpuResult {
    use raw_cpuid::CpuId;

    let cpuid = CpuId::new();

    let vendor = cpuid
        .get_vendor_info()
        .map(|v| v.as_str().to_owned())
        .unwrap_or_else(|| "Unknown".into());

    let brand = cpuid
        .get_processor_brand_string()
        .map(|b| b.as_str().trim().to_owned())
        .unwrap_or_else(|| vendor.clone());

    let feat = cpuid.get_feature_info();
    let vmx             = feat.as_ref().map(|f| f.has_vmx()).unwrap_or(false);
    let logical_cores   = feat.as_ref().map(|f| f.max_logical_processor_ids() as u32).unwrap_or(1);
    // CPUID leaf 1 ECX bit 31: set when running inside any hypervisor.
    let inside_hypervisor = feat.as_ref().map(|f| f.has_hypervisor()).unwrap_or(false);

    let svm = cpuid
        .get_extended_processor_and_feature_identifiers()
        .map(|e| e.has_svm())
        .unwrap_or(false);

    // --- Hypervisor guest path -----------------------------------------------
    // Windows with Core Isolation / Memory Integrity / Credential Guard enabled
    // runs as a Hyper-V VBS guest. In that mode the firmware exposes SVM/VT-x to
    // the hypervisor only; CPUID inside the guest sees them as disabled.
    // The USB bare-metal boot test (green screen) is the authoritative check.
    // Do not FAIL -- just note the environment.
    if inside_hypervisor && !vmx && !svm {
        // Infer tier from vendor so the report is still useful.
        let (tier, note_extra) = match vendor.as_str() {
            "GenuineIntel" => (CpuTier::X86Intel,
                "VT-x hidden by Hyper-V VBS guest mode."),
            "AuthenticAMD" => (CpuTier::X86Amd,
                "SVM hidden by Hyper-V VBS guest mode."),
            _ => (CpuTier::Unsupported,
                "Running inside unknown hypervisor."),
        };
        let pass = tier != CpuTier::Unsupported;
        return CpuResult {
            vendor,
            brand,
            logical_cores,
            vmx_supported: false,
            svm_supported: false,
            tier,
            pass,
            note: Some(format!(
                "{} Running inside a hypervisor (Windows Core Isolation / VBS). \
                 SVM/VT-x flags are hidden from this environment. \
                 AETHER USB boot GREEN screen is the authoritative hardware test. \
                 To see accurate flags here: Windows Security > Core Isolation > \
                 Memory Integrity OFF, then recheck.",
                note_extra
            )),
        };
    }

    // --- Bare-metal / no-hypervisor path -------------------------------------
    // Determine tier and pass/fail.
    let tier = match vendor.as_str() {
        "GenuineIntel" if vmx  => CpuTier::X86Intel,
        "AuthenticAMD" if svm  => CpuTier::X86Amd,
        _ => CpuTier::Unsupported,
    };

    let (pass, note) = match &tier {
        CpuTier::X86Intel | CpuTier::X86Amd => (true, None),
        _ => {
            let hint = if vendor.contains("Intel") {
                "VT-x not enabled. Enter BIOS Setup, enable Intel VT-x / Virtualization Technology."
            } else if vendor.contains("AMD") {
                "SVM not enabled. Enter BIOS Setup, enable AMD SVM Mode / Virtualization."
            } else {
                "CPU not supported. AETHER requires Intel VT-x or AMD SVM."
            };
            (false, Some(hint.into()))
        }
    };

    CpuResult {
        vendor,
        brand,
        logical_cores,
        vmx_supported: vmx,
        svm_supported: svm,
        tier,
        pass,
        note,
    }
}

// ---- aarch64 ----------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
fn check_arm64() -> CpuResult {
    let brand = read_arm64_brand();
    let logical_cores = read_arm64_cores();

    CpuResult {
        vendor:        "ARM".into(),
        brand,
        logical_cores,
        vmx_supported: false,
        svm_supported: false,
        tier:          CpuTier::Arm64,
        pass:          true,
        note:          Some(
            "ARM64 tier detected. EL2 virtualization support assumed on Snapdragon SoCs.".into()
        ),
    }
}

#[cfg(target_arch = "aarch64")]
fn read_arm64_brand() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("Hardware") {
                if let Some(val) = rest.split(':').nth(1) {
                    return val.trim().to_owned();
                }
            }
            if let Some(rest) = line.strip_prefix("Model name") {
                if let Some(val) = rest.split(':').nth(1) {
                    return val.trim().to_owned();
                }
            }
        }
    }
    "ARM64 (brand unknown)".into()
}

#[cfg(target_arch = "aarch64")]
fn read_arm64_cores() -> u32 {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/present") {
        // Format: "0-7" means CPUs 0 through 7 (8 cores).
        if let Some(last) = s.trim().split('-').last() {
            if let Ok(n) = last.parse::<u32>() {
                return n + 1;
            }
        }
    }
    1
}
