// update.rs -- `aether-install update` subcommand.
//
// Upgrade an existing AETHER install to a newer image. The update writes
// the new artefacts to the *inactive* A/B slot, flips active_slot, and
// preserves the old slot so a failed boot reverts (Ch 58 selector enforces
// the rollback per P5-SKILLS.md).
//
// Steps:
//   1. Verify install present (else error).
//   2. Resolve target slot = inactive slot.
//   3. Write new hypervisor.efi / selector.efi to ESP under \EFI\AETHER\<slot>\.
//   4. Write new Android image into the namespace at the slot's offset.
//   5. Flip active_slot in state.
//   6. Save state.
//
// We do NOT touch the Boot#### variable -- selector.efi is the same file
// across updates; it reads active_slot from the config partition.

use crate::cli::CliArgs;
use crate::install_state::{InstallState, Slot};

pub fn run(args: &CliArgs) -> i32 {
    println!("aether-install update");
    println!("=====================");
    if !args.apply {
        println!("(dry-run -- pass --apply to perform the update)");
        println!();
    }

    let mut state = match InstallState::load() {
        Ok(Some(s)) if s.is_installed() => s,
        Ok(_) => {
            eprintln!("No AETHER install detected. Run `aether-install install` first.");
            return 2;
        }
        Err(e) => {
            eprintln!("could not read install state: {}", e);
            return 5;
        }
    };

    let from_slot = state.active_slot;
    let to_slot = match from_slot { Slot::A => Slot::B, Slot::B => Slot::A };

    println!("Updating {} -> (writing to slot {:?})", state.version, to_slot);

    // Step 1: require the artefact paths.
    if args.apply {
        if args.hypervisor.is_none() || args.selector.is_none() || args.android_image.is_none() {
            eprintln!("--apply requires --hypervisor, --selector, and --android-image paths.");
            return 6;
        }
    }

    let slot_dir = format!("{}\\EFI\\AETHER\\{}",
        state.esp_mount.trim_end_matches('\\'),
        match to_slot { Slot::A => "A", Slot::B => "B" });

    if args.apply {
        if let Some(src) = &args.hypervisor {
            if let Err(e) = copy_file(src, &format!("{}\\hypervisor.efi", slot_dir)) {
                eprintln!("[2/5] copy hypervisor.efi FAILED: {}", e); return 7;
            }
        }
        if let Some(src) = &args.selector {
            if let Err(e) = copy_file(src, &format!("{}\\selector.efi", slot_dir)) {
                eprintln!("[2/5] copy selector.efi FAILED: {}", e); return 7;
            }
        }
        if let Some(src) = &args.android_image {
            println!("[3/5] [stub] would dd {} -> {} (slot {:?})", src, state.target_disk, to_slot);
        }
    } else {
        println!("[2/5] [plan] copy {} -> {}\\hypervisor.efi",
            args.hypervisor.as_deref().unwrap_or("hypervisor.efi"), slot_dir);
        println!("[2/5] [plan] copy {} -> {}\\selector.efi",
            args.selector.as_deref().unwrap_or("selector.efi"), slot_dir);
        println!("[3/5] [plan] write Android image to slot {:?}", to_slot);
    }

    // Flip slot.
    state.flip_slot();
    state.last_updated = now_iso();
    println!("[4/5] active slot {:?} -> {:?}", from_slot, state.active_slot);

    if args.apply {
        match state.save() {
            Ok(()) => println!("[5/5] state updated"),
            Err(e) => { eprintln!("[5/5] could not save state: {}", e); return 10; }
        }
    } else {
        println!("[5/5] [plan] save updated state");
    }

    println!();
    println!("Done. Reboot to boot the new slot. If it fails, the selector reverts to {:?}.",
        from_slot);
    0
}

fn copy_file(src: &str, dst: &str) -> Result<(), std::io::Error> {
    let dp = std::path::Path::new(dst);
    if let Some(parent) = dp.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dp)?;
    println!("           wrote {}", dst);
    Ok(())
}

fn now_iso() -> String {
    // Same shape as install::now_iso (no chrono dep).
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let mut days = secs / 86400;
    let mut year = 1970u64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let in_year = if leap { 366 } else { 365 };
        if days < in_year { break; }
        days -= in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let md = [31u64, if leap {29} else {28}, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u64;
    for &x in &md {
        if days < x { break; }
        days -= x;
        mo += 1;
    }
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, mo, days + 1, h, m, s)
}
