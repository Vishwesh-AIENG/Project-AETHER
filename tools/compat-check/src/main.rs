// main.rs -- AETHER Hardware Compatibility Checker
//
// Usage:
//   aether-compat           -- human-readable report to stdout
//   aether-compat --json    -- structured JSON to stdout (pipe-friendly)
//   aether-compat --json > report.json
//
// Exit codes:
//   0 = PASS  (all requirements met, SR-IOV present)
//   1 = WARN  (CPU/RAM/storage OK; GPU SR-IOV missing -- Android boots with software rendering)
//   2 = FAIL  (CPU virt disabled, or RAM < 8 GiB, or no 64 GiB free)
//
// No administrator / root privileges required for the check phase.

mod cpu;
mod gpu;
mod memory;
mod report;
mod storage;

use report::{CompatReport, OverallStatus};
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");

    if !json_mode {
        // Print a brief header to stderr so it doesn't pollute JSON piped output.
        eprintln!("AETHER Hardware Compatibility Checker v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("Running checks...");
        eprintln!();
    }

    let cpu     = cpu::check();
    let memory  = memory::check();
    let storage = storage::check();
    let gpu     = gpu::check();

    let report = CompatReport::build(cpu, memory, storage, gpu);

    if json_mode {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{}", json),
            Err(e)   => {
                eprintln!("JSON serialization error: {}", e);
                process::exit(3);
            }
        }
    } else {
        report::print_human(&report);
    }

    // Exit code matches overall status so scripts can `if aether-compat; then ...`
    match report.overall {
        OverallStatus::Pass => process::exit(0),
        OverallStatus::Warn => process::exit(1),
        OverallStatus::Fail => process::exit(2),
    }
}
