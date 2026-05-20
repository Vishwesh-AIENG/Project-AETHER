// check.rs -- `aether-install check` subcommand.
//
// Spawns the aether-compat binary as a subprocess and parses its --json
// output. We look for the binary in:
//   1. $AETHER_COMPAT_BIN if set
//   2. PATH
//   3. ../compat-check/target/{debug,release}/aether-compat (workspace dev)
//
// This avoids a library dependency between the two crates -- aether-compat
// can be shipped standalone, and aether-install only needs the JSON contract.

use crate::cli::CliArgs;
use crate::compat_report::CompatReport;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
pub enum CheckError {
    BinaryNotFound,
    SpawnFailed(String),
    Killed(i32),
    BadJson(String),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::BinaryNotFound =>
                write!(f, "aether-compat binary not found. Set AETHER_COMPAT_BIN \
                          or add it to PATH."),
            CheckError::SpawnFailed(e) =>
                write!(f, "failed to spawn aether-compat: {}", e),
            CheckError::Killed(c) =>
                write!(f, "aether-compat exited with signal: code={}", c),
            CheckError::BadJson(e) =>
                write!(f, "aether-compat produced unparseable JSON: {}", e),
        }
    }
}

pub fn locate_binary() -> Option<PathBuf> {
    // 1. Environment override.
    if let Ok(p) = std::env::var("AETHER_COMPAT_BIN") {
        let path = PathBuf::from(p);
        if path.is_file() { return Some(path); }
    }

    // 2. PATH lookup.
    let exe_name = if cfg!(windows) { "aether-compat.exe" } else { "aether-compat" };
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(sep) {
            let candidate = PathBuf::from(dir).join(exe_name);
            if candidate.is_file() { return Some(candidate); }
        }
    }

    // 3. Workspace dev paths (relative to aether-install binary location).
    if let Ok(self_exe) = std::env::current_exe() {
        // self_exe is .../target/{debug,release}/aether-install[.exe].
        // The aether-compat binary lives in the same target dir.
        if let Some(target_dir) = self_exe.parent() {
            let candidate = target_dir.join(exe_name);
            if candidate.is_file() { return Some(candidate); }
        }
    }

    None
}

/// Run aether-compat --json and parse the result. Returns the CompatReport
/// regardless of exit code (the exit code only indicates PASS/WARN/FAIL,
/// which is also in the report's `overall` field).
pub fn run_compat_check() -> Result<CompatReport, CheckError> {
    let bin = locate_binary().ok_or(CheckError::BinaryNotFound)?;

    let out = Command::new(&bin)
        .arg("--json")
        .output()
        .map_err(|e| CheckError::SpawnFailed(format!("{}: {}", bin.display(), e)))?;

    // Exit code 0/1/2 = PASS/WARN/FAIL all return valid JSON. Anything else
    // is a real failure (3 = serialization error, signal, etc.).
    let code = out.status.code();
    if code.is_none() {
        return Err(CheckError::Killed(-1));
    }
    let report: CompatReport = serde_json::from_slice(&out.stdout)
        .map_err(|e| CheckError::BadJson(format!(
            "{}\nstdout: {}\nstderr: {}",
            e,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        )))?;
    Ok(report)
}

/// Top-level handler for `aether-install check`.
pub fn run(args: &CliArgs) -> i32 {
    match run_compat_check() {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{}", s),
                    Err(e) => {
                        eprintln!("serialization error: {}", e);
                        return 3;
                    }
                }
            } else {
                print_summary(&report);
            }
            match report.overall.as_str() {
                "Pass" => 0,
                "Warn" => 1,
                _      => 2,
            }
        }
        Err(e) => {
            eprintln!("check failed: {}", e);
            4
        }
    }
}

fn print_summary(r: &CompatReport) {
    println!("aether-install check");
    println!("====================");
    println!("CPU      : {} ({}) -- {}", r.cpu.brand, r.cpu.tier,
             if r.cpu.pass { "PASS" } else { "FAIL" });
    if let Some(n) = &r.cpu.note { println!("           note: {}", n); }
    println!("Memory   : {} GiB / {} GiB minimum -- {}",
             r.memory.total_gib, r.memory.minimum_gib,
             if r.memory.pass { "PASS" } else { "FAIL" });
    println!("Storage  : {} GiB free (need {}) -- {}",
             r.storage.largest_free_gib, r.storage.minimum_free_gib,
             if r.storage.pass { "PASS" } else { "FAIL" });
    println!("GPU      : {} devices, SR-IOV {} -- {}",
             r.gpu.devices.len(),
             if r.gpu.sriov_capable { "capable" } else { "none" },
             if r.gpu.sriov_capable { "PASS" } else { "WARN" });
    for d in &r.gpu.devices {
        let vfs = match d.sriov_max_vfs {
            Some(n) => format!("{}", n),
            None    => "unknown".into(),
        };
        println!("           - {} ({}/{}), VFs: {}", d.name, d.vendor_id, d.device_id, vfs);
    }
    println!("--------------------");
    println!("Overall  : {}", r.overall);
    for n in &r.notes {
        println!("  * {}", n);
    }
}
