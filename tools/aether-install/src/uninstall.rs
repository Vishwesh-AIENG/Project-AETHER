// uninstall.rs -- `aether-install uninstall` subcommand.
//
// Removes AETHER from a machine WITHOUT touching the Windows boot manager:
//   1. Read install state to find Boot#### index and ESP files.
//   2. Remove Boot#### variable.
//   3. Remove AETHER from BootOrder.
//   4. Delete \EFI\AETHER\ directory on the ESP.
//   5. Optionally delete the Android NVMe namespace.
//   6. Delete the install-state.json file.
//
// What we never touch:
//   - The Windows Boot Manager entry in BootOrder.
//   - The Windows EFI files in \EFI\Microsoft\.
//   - Any partition that is not the AETHER Android namespace.

use crate::boot_entry::{self, BOOT_VAR_ATTRS, EFI_GLOBAL_VARIABLE_GUID};
use crate::cli::CliArgs;
use crate::install_state::InstallState;
use crate::uefi_vars;

pub fn run(args: &CliArgs) -> i32 {
    println!("aether-install uninstall");
    println!("========================");
    if !args.apply {
        println!("(dry-run -- pass --apply to actually remove AETHER)");
        println!();
    }

    let state = match InstallState::load() {
        Ok(Some(s)) => s,
        Ok(None) => {
            println!("No AETHER install detected on this machine.");
            println!("(install state file {:?} does not exist)", InstallState::path());
            return 0;
        }
        Err(e) => {
            eprintln!("could not read install state: {}", e);
            return 5;
        }
    };

    println!("Current install:");
    println!("  install_id   : {}", state.install_id);
    println!("  version      : {}", state.version);
    println!("  installed_at : {}", state.installed_at);
    println!("  boot_entry   : {:?}", state.boot_entry_index);
    println!("  ESP mount    : {}", state.esp_mount);
    println!("  target disk  : {}", state.target_disk);
    println!();

    // Step 1+2: remove Boot#### entry --
    if let Some(idx) = state.boot_entry_index {
        let name = boot_entry::boot_var_name(idx);
        if args.apply {
            match uefi_vars::delete(&name, EFI_GLOBAL_VARIABLE_GUID) {
                Ok(()) => println!("[1/5] removed {}", name),
                Err(e) => {
                    eprintln!("[1/5] remove {} FAILED: {}", name, e);
                    return 6;
                }
            }
        } else {
            println!("[1/5] [plan] remove {}", name);
        }

        // Step 2: BootOrder cleanup.
        match uefi_vars::read("BootOrder", EFI_GLOBAL_VARIABLE_GUID) {
            Ok((_, bytes)) => {
                let cur = boot_entry::decode_boot_order(&bytes);
                let next = boot_entry::boot_order_remove(&cur, idx);
                if args.apply {
                    let nb = boot_entry::encode_boot_order(&next);
                    match uefi_vars::write("BootOrder", EFI_GLOBAL_VARIABLE_GUID, BOOT_VAR_ATTRS, &nb) {
                        Ok(()) => println!("[2/5] BootOrder: {:?} -> {:?}", cur, next),
                        Err(e) => {
                            eprintln!("[2/5] update BootOrder FAILED: {}", e);
                            return 7;
                        }
                    }
                } else {
                    println!("[2/5] [plan] BootOrder {:?} -> {:?}", cur, next);
                }
            }
            Err(e) => println!("[2/5] could not read BootOrder ({}); skipping cleanup", e),
        }
    } else {
        println!("[1/5] no Boot#### entry recorded; skipping");
        println!("[2/5] BootOrder unchanged");
    }

    // Step 3: delete \EFI\AETHER\ on ESP --
    let aether_dir = format!("{}\\EFI\\AETHER", state.esp_mount.trim_end_matches('\\'));
    if args.apply {
        match std::fs::remove_dir_all(&aether_dir) {
            Ok(()) => println!("[3/5] deleted {}", aether_dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                println!("[3/5] {} already absent", aether_dir),
            Err(e) => {
                eprintln!("[3/5] delete {} FAILED: {}", aether_dir, e);
                return 8;
            }
        }
    } else {
        println!("[3/5] [plan] delete {}", aether_dir);
    }

    // Step 4: Android NVMe namespace --
    if let Some(nsid) = state.android_nsid {
        if args.apply {
            println!("[4/5] [stub] would run: nvme delete-ns {} --namespace-id={}",
                state.target_disk, nsid);
        } else {
            println!("[4/5] [plan] delete NVMe namespace NSID={} on {}", nsid, state.target_disk);
        }
    } else {
        println!("[4/5] no Android namespace recorded");
    }

    // Step 5: state file --
    if args.apply {
        match InstallState::delete() {
            Ok(()) => println!("[5/5] removed install state file"),
            Err(e) => {
                eprintln!("[5/5] could not remove state file: {}", e);
                return 9;
            }
        }
    } else {
        println!("[5/5] [plan] delete {:?}", InstallState::path());
    }

    println!();
    println!("Done. Reboot to confirm Windows boots normally.");
    0
}
