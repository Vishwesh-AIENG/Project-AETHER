// status.rs -- `aether-install status` subcommand.
//
// Read-only inspection of the current install state. Safe to run any time;
// no privileges required.

use crate::cli::CliArgs;
use crate::install_state::InstallState;
use crate::uefi_vars;
use crate::boot_entry::{self, EFI_GLOBAL_VARIABLE_GUID};

pub fn run(args: &CliArgs) -> i32 {
    let state = match InstallState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not read install state: {}", e);
            return 5;
        }
    };

    if args.json {
        let payload = serde_json::json!({
            "installed":   state.as_ref().map(|s| s.is_installed()).unwrap_or(false),
            "state_file":  format!("{:?}", InstallState::path()),
            "state":       state,
            "uefi_vars_available": uefi_vars::available(),
        });
        match serde_json::to_string_pretty(&payload) {
            Ok(s) => println!("{}", s),
            Err(e) => { eprintln!("serialization error: {}", e); return 3; }
        }
        return 0;
    }

    println!("aether-install status");
    println!("=====================");
    println!("UEFI variables available : {}", uefi_vars::available());
    println!("State file               : {:?}", InstallState::path());

    let Some(s) = state else {
        println!("Install status           : NOT INSTALLED");
        println!();
        println!("Run `aether-install install` to install AETHER.");
        return 0;
    };

    println!("Install status           : {}",
        if s.is_installed() { "INSTALLED" } else { "PARTIAL / CORRUPT" });
    println!("Install ID               : {}", s.install_id);
    println!("Version                  : {}", s.version);
    println!("Installed at             : {}", s.installed_at);
    println!("Last updated             : {}", s.last_updated);
    println!("ESP mount                : {}", s.esp_mount);
    println!("ESP partition GUID       : {}", s.esp_partition_guid);
    println!("Target disk              : {}", s.target_disk);
    println!("Android namespace NSID   : {:?}", s.android_nsid);
    println!("Config partition GUID    : {:?}", s.config_partition_guid);
    println!("Boot entry index         : {:?}",
        s.boot_entry_index.map(|i| format!("Boot{:04X}", i)));
    println!("Active A/B slot          : {:?}", s.active_slot);
    if let Some(p) = &s.gpu_plan {
        println!("GPU mode                 : {}", p.mode.as_str());
        if let Some(label) = &p.gpu_label {
            println!("GPU device               : {}", label);
        }
        for w in &p.warnings {
            println!("  ! {}", w);
        }
    }

    // If we have a Boot#### index recorded, verify firmware still has it.
    if let Some(idx) = s.boot_entry_index {
        let name = boot_entry::boot_var_name(idx);
        match uefi_vars::read(&name, EFI_GLOBAL_VARIABLE_GUID) {
            Ok((_, bytes)) => println!("Firmware Boot{:04X}       : present ({} bytes)", idx, bytes.len()),
            Err(e) => println!("Firmware Boot{:04X}       : MISSING ({})", idx, e),
        }
        match uefi_vars::read("BootOrder", EFI_GLOBAL_VARIABLE_GUID) {
            Ok((_, bytes)) => {
                let order = boot_entry::decode_boot_order(&bytes);
                let position = order.iter().position(|&i| i == idx);
                println!("BootOrder position       : {:?} / {}", position, order.len());
            }
            Err(e) => println!("BootOrder                : unreadable ({})", e),
        }
    }

    0
}
