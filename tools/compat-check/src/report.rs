// report.rs -- CompatReport aggregation and human-readable terminal output.
//
// CompatReport is Serialize so it can be emitted as JSON with --json flag.
// print_human() writes plain ASCII (7-bit only, no Unicode) to stdout.

use serde::Serialize;

use crate::cpu::{CpuResult, CpuTier};
use crate::memory::MemoryResult;
use crate::storage::StorageResult;
use crate::gpu::GpuResult;

// ---- Report types -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum OverallStatus {
    Pass,
    Warn,
    Fail,
}

impl OverallStatus {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            OverallStatus::Pass => "PASS",
            OverallStatus::Warn => "WARN",
            OverallStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatReport {
    pub schema_version: u32,
    pub timestamp:      String,
    pub host_arch:      String,
    pub cpu:            CpuResult,
    pub memory:         MemoryResult,
    pub storage:        StorageResult,
    pub gpu:            GpuResult,
    pub overall:        OverallStatus,
    pub notes:          Vec<String>,
}

impl CompatReport {
    pub fn build(
        cpu:     CpuResult,
        memory:  MemoryResult,
        storage: StorageResult,
        gpu:     GpuResult,
    ) -> Self {
        let mut notes: Vec<String> = Vec::new();

        // Collect per-section notes.
        if let Some(n) = &cpu.note     { notes.push(n.clone()); }
        if let Some(n) = &memory.note  { notes.push(n.clone()); }
        if let Some(n) = &storage.note { notes.push(n.clone()); }
        if let Some(n) = &gpu.note     { notes.push(n.clone()); }

        // Overall: FAIL if any hard requirement unmet; WARN if only GPU SR-IOV missing.
        let hard_fail = !cpu.pass || !memory.pass || !storage.pass;
        let soft_warn = !gpu.sriov_capable;

        let overall = if hard_fail {
            OverallStatus::Fail
        } else if soft_warn {
            OverallStatus::Warn
        } else {
            OverallStatus::Pass
        };

        let host_arch = std::env::consts::ARCH.to_owned();

        // Timestamp: seconds since UNIX epoch as a simple string (no chrono dep).
        let timestamp = timestamp_utc();

        CompatReport {
            schema_version: 1,
            timestamp,
            host_arch,
            cpu,
            memory,
            storage,
            gpu,
            overall,
            notes,
        }
    }
}

// ---- Human-readable output --------------------------------------------------

const LINE: &str = "========================================";
const THIN: &str = "----------------------------------------";

pub fn print_human(r: &CompatReport) {
    println!("{}", LINE);
    println!(" AETHER Hardware Compatibility Checker");
    println!(" v{}", env!("CARGO_PKG_VERSION"));
    println!("{}", LINE);
    println!(" Timestamp : {}", r.timestamp);
    println!(" Host arch : {}", r.host_arch);
    println!();

    // --- CPU -----------------------------------------------------------------
    println!("[CPU]");
    println!("  Vendor  : {}", r.cpu.vendor);
    println!("  Brand   : {}", r.cpu.brand);
    println!("  Cores   : {} logical", r.cpu.logical_cores);

    let virt_label = match r.cpu.tier {
        CpuTier::X86Intel => "VT-x   : YES",
        CpuTier::X86Amd   => "SVM    : YES",
        CpuTier::Arm64    => "EL2    : assumed",
        CpuTier::Unsupported => {
            if r.cpu.vmx_supported || r.cpu.svm_supported {
                "Virt   : detected but tier unknown"
            } else {
                "Virt   : NO -- BIOS DISABLED"
            }
        }
    };
    println!("  {}", virt_label);
    println!("  Tier    : {}", r.cpu.tier.as_str());
    println!("  Result  : {}", pass_fail(r.cpu.pass));
    if let Some(n) = &r.cpu.note { println!("  Note    : {}", n); }
    println!();

    // --- Memory --------------------------------------------------------------
    println!("[MEMORY]");
    println!("  Total   : {} GiB", r.memory.total_gib);
    println!("  Minimum : {} GiB", r.memory.minimum_gib);
    println!("  Result  : {}", pass_fail(r.memory.pass));
    if let Some(n) = &r.memory.note { println!("  Note    : {}", n); }
    println!();

    // --- Storage -------------------------------------------------------------
    println!("[STORAGE]");
    if r.storage.drives.is_empty() {
        println!("  (no drives detected)");
    } else {
        println!(
            "  {:<20} {:<8} {:<10} {:<10} {:<5} {}",
            "Drive", "Mount", "Total", "Free", "NVMe", "Status"
        );
        println!("  {}", &THIN[..60.min(THIN.len())]);
        for d in &r.storage.drives {
            println!(
                "  {:<20} {:<8} {:<10} {:<10} {:<5} {}",
                truncate(&d.name, 20),
                truncate(&d.mount_point, 8),
                format!("{} GiB", d.total_gib),
                format!("{} GiB", d.available_gib),
                if d.is_nvme { "YES" } else { "no" },
                if d.available_gib >= r.storage.minimum_free_gib { "OK" } else { "low" }
            );
        }
    }
    println!("  Largest free : {} GiB (need {} GiB)", r.storage.largest_free_gib, r.storage.minimum_free_gib);
    println!("  Result       : {}", pass_fail(r.storage.pass));
    if let Some(n) = &r.storage.note { println!("  Note         : {}", n); }
    println!();

    // --- GPU -----------------------------------------------------------------
    println!("[GPU / SR-IOV]");
    if r.gpu.devices.is_empty() {
        println!("  (no GPU detected)");
    } else {
        println!(
            "  {:<30} {:<8} {:<8} {}",
            "Name", "Vendor", "Device", "SR-IOV MaxVFs"
        );
        println!("  {}", &THIN[..60.min(THIN.len())]);
        for d in &r.gpu.devices {
            let vfs = match d.sriov_max_vfs {
                Some(0) => "not capable".into(),
                Some(n) => format!("{}", n),
                None    => "unknown (needs admin)".into(),
            };
            println!(
                "  {:<30} {:<8} {:<8} {}",
                truncate(&d.name, 30),
                truncate(&d.vendor_id, 8),
                truncate(&d.device_id, 8),
                vfs
            );
        }
    }
    let sriov_str = match r.gpu.best_max_vfs {
        Some(0) | None if !r.gpu.sriov_capable => "NONE -- Android uses software rendering",
        Some(n)                                 => &*format!("{} VFs -- hardware GPU acceleration available", n),
        _                                       => "capable",
    };
    // Workaround for lifetime: just print inline.
    println!("  SR-IOV  : {}", if r.gpu.sriov_capable {
        format!("{} VFs available -- hardware GPU acceleration enabled",
            r.gpu.best_max_vfs.unwrap_or(0))
    } else {
        "NONE -- Android will use software rendering (llvmpipe)".into()
    });
    println!("  Result  : {}", if r.gpu.sriov_capable { "PASS" } else { "WARN" });
    if let Some(n) = &r.gpu.note { println!("  Note    : {}", n); }
    let _ = sriov_str; // suppress unused warning
    println!();

    // --- Overall -------------------------------------------------------------
    println!("{}", LINE);
    let banner = match r.overall {
        OverallStatus::Pass => " OVERALL: PASS -- Ready to install AETHER",
        OverallStatus::Warn => " OVERALL: WARN -- AETHER installs; GPU acceleration limited",
        OverallStatus::Fail => " OVERALL: FAIL -- Hardware requirements not met",
    };
    println!("{}", banner);

    if !r.notes.is_empty() {
        println!("{}", THIN);
        for (i, note) in r.notes.iter().enumerate() {
            println!(" [{}] {}", i + 1, note);
        }
    }

    println!("{}", LINE);
}

// ---- Helpers ----------------------------------------------------------------

fn pass_fail(pass: bool) -> &'static str {
    if pass { "PASS" } else { "FAIL" }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Returns an ISO-8601-like timestamp without pulling in chrono.
/// Format: "2026-05-20T14:54:00Z" (approximate -- seconds since Unix epoch).
fn timestamp_utc() -> String {
    // Use a simple approach: read system time, convert manually.
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Simple Julian/Gregorian calendar calculation.
    let s   = secs % 60;
    let m   = (secs / 60) % 60;
    let h   = (secs / 3600) % 24;
    let days = secs / 86400; // days since 1970-01-01

    let (year, month, day) = days_to_ymd(days);

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, h, m, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
