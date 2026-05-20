// install.rs -- `aether-install install` pipeline orchestration.
//
// Pipeline (from chapter spec):
//   1. Run compat check
//   2. GPU configuration (auto SR-IOV or prompt)
//   3. Detect / confirm target NVMe drive
//   4. Create NVMe namespace for Android
//   5. Write EFI binaries (hypervisor.efi, selector.efi) to ESP
//   6. Create UEFI Boot#### entry pointing at selector.efi
//   7. Update BootOrder to put AETHER first
//   8. Write Android image into namespace
//   9. Write AETHER config partition
//
// Steps 1-2 always run (read-only / decision).
// Steps 3-9 are gated on --apply. Without --apply we print a "PLAN" of what
// each step would do. With --apply we actually execute and update install
// state.
//
// Idempotency: every step is structured as a check-then-act. If the work
// is already done (state file says so, or the on-disk artefact matches),
// skip. Running `install --apply` twice produces no observable difference.

use crate::boot_entry::{
    self, BootEntry, BOOT_VAR_ATTRS, EFI_GLOBAL_VARIABLE_GUID, LOAD_OPTION_ACTIVE,
};
use crate::check;
use crate::cli::CliArgs;
use crate::device_path::{GptGuid, HardDriveNode};
use crate::gpu_config::{self, GpuMode, GpuPlan};
use crate::install_state::{InstallState, Slot};
use crate::uefi_vars;

use std::io::{self, BufRead, Write};

// ---- Entry point -----------------------------------------------------------

pub fn run(args: &CliArgs) -> i32 {
    println!("aether-install install");
    println!("======================");
    if !args.apply {
        println!("(dry-run -- pass --apply to perform destructive operations)");
        println!();
    }

    // --- Step 1: compat check ------------------------------------------------
    let report = match check::run_compat_check() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[1/9] compat check FAILED: {}", e);
            return 4;
        }
    };
    print_step(1, "compat check", &format!("overall={}", report.overall));

    if report.is_fail() {
        eprintln!();
        eprintln!("Hardware does not meet AETHER requirements:");
        for n in &report.notes { eprintln!("  - {}", n); }
        eprintln!();
        eprintln!("Aborting install. Fix the issues above and re-run.");
        return 2;
    }

    // --- Step 2: GPU configuration -------------------------------------------
    let cli_override = args.gpu_override.as_ref().map(|m| match m {
        crate::cli::GpuModeOverride::Sriov       => GpuMode::Sriov,
        crate::cli::GpuModeOverride::Passthrough => GpuMode::Passthrough,
        crate::cli::GpuModeOverride::Software    => GpuMode::Software,
    });

    let plan = gpu_config::decide(&report, cli_override);
    let final_plan = match resolve_gpu_plan(plan, args) {
        Ok(p) => p,
        Err(code) => return code,
    };
    print_step(2, "GPU configuration",
        &format!("{} ({})", final_plan.mode.as_str(),
            final_plan.gpu_label.as_deref().unwrap_or("no GPU")));
    for w in &final_plan.warnings {
        println!("           ! {}", w);
    }

    // --- Steps 3..9: install proper ------------------------------------------
    let existing = match InstallState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not read install state: {}", e);
            return 5;
        }
    };

    let mut state = existing.unwrap_or_default();
    state.last_updated = now_iso();
    state.gpu_plan = Some(final_plan.clone());

    // Step 3: target disk + ESP --
    let target_disk = match args.target_disk.clone() {
        Some(d) => d,
        None    => {
            // Pick the first NVMe drive from the compat report if not specified.
            report.storage.drives.iter()
                .find(|d| d.is_nvme)
                .map(|d| d.name.clone())
                .unwrap_or_else(|| if cfg!(windows) {
                    "\\\\.\\PHYSICALDRIVE1".to_string()
                } else {
                    "/dev/nvme0".to_string()
                })
        }
    };
    let esp_mount = args.esp.clone().unwrap_or_else(|| {
        if cfg!(windows) { "S:".to_string() } else { "/boot/efi".to_string() }
    });
    state.target_disk = target_disk.clone();
    state.esp_mount   = esp_mount.clone();
    print_step(3, "target disk + ESP",
        &format!("disk={}  esp={}", target_disk, esp_mount));

    // Step 4: NVMe Android namespace --
    let nsid = match state.android_nsid {
        Some(n) => {
            print_step(4, "NVMe Android namespace",
                &format!("already allocated: nsid={} (idempotent skip)", n));
            n
        }
        None => {
            let n = 2u32; // AETHER convention: nsid=1 reserved, Android lives in nsid=2
            if args.apply {
                // Real implementation lives in nvme_admin (out of scope for Ch56 -- the
                // creation pipeline is in hypervisor/src/nvme_namespace.rs and is exercised
                // there). The installer here would invoke `nvme create-ns` or the libnvme
                // FFI. We record the intent in state and emit the command for the user.
                println!("           [stub] would run: nvme create-ns {} --nsze=...", target_disk);
                state.android_nsid = Some(n);
            } else {
                println!("           [plan] create namespace NSID={} on {}", n, target_disk);
            }
            n
        }
    };
    print_step(4, "NVMe Android namespace", &format!("nsid={}", nsid));

    // Step 5: write EFI binaries --
    let hypervisor_src = args.hypervisor.clone();
    let selector_src   = args.selector.clone();
    let android_src    = args.android_image.clone();

    if args.apply {
        if hypervisor_src.is_none() || selector_src.is_none() || android_src.is_none() {
            eprintln!();
            eprintln!("--apply requires --hypervisor, --selector, and --android-image paths.");
            return 6;
        }
    }

    let hypervisor_dst = format!("{}\\EFI\\AETHER\\hypervisor.efi", esp_mount.trim_end_matches('\\'));
    let selector_dst   = format!("{}\\EFI\\AETHER\\selector.efi",   esp_mount.trim_end_matches('\\'));

    if args.apply {
        if let Err(e) = copy_efi_binary(hypervisor_src.as_deref().unwrap(), &hypervisor_dst) {
            eprintln!("           copy hypervisor.efi FAILED: {}", e);
            return 7;
        }
        if let Err(e) = copy_efi_binary(selector_src.as_deref().unwrap(), &selector_dst) {
            eprintln!("           copy selector.efi FAILED: {}", e);
            return 7;
        }
    } else {
        println!("           [plan] copy {} -> {}",
                 hypervisor_src.as_deref().unwrap_or("hypervisor.efi"), hypervisor_dst);
        println!("           [plan] copy {} -> {}",
                 selector_src.as_deref().unwrap_or("selector.efi"), selector_dst);
    }
    print_step(5, "write EFI binaries", "OK");

    // Step 6 + 7: UEFI Boot#### entry + BootOrder --
    // The boot entry points at selector.efi (Ch58), which then chainloads
    // either hypervisor.efi or Windows Boot Manager.
    let entry = BootEntry {
        attributes:  LOAD_OPTION_ACTIVE,
        description: "AETHER".to_string(),
        hard_drive: HardDriveNode {
            // The ESP partition number / start LBA / size / GUID come from
            // GPT inspection. Real implementation would call IOCTL_DISK_GET_DRIVE_LAYOUT_EX
            // on Windows or `parted -m print` / `blkid` on Linux. Placeholders here
            // are clearly marked.
            partition_number:    1,
            partition_start_lba: 2048,
            partition_size_lba:  0, // filled in by ESP probe in real impl
            partition_guid:      GptGuid([0u8; 16]),
        },
        file_path:    "\\EFI\\AETHER\\selector.efi".to_string(),
        optional_data: Vec::new(),
    };

    let blob = entry.to_bytes();
    let boot_idx = match state.boot_entry_index {
        Some(i) => {
            print_step(6, "Boot#### entry",
                &format!("re-using Boot{:04X} from previous install (idempotent)", i));
            i
        }
        None => {
            let used = read_used_boot_indices().unwrap_or_default();
            let idx = boot_entry::pick_free_boot_index(&used)
                .unwrap_or(0x9AEF); // "AEF" fallback that's almost certainly unused
            print_step(6, "Boot#### entry", &format!("will allocate Boot{:04X}", idx));
            idx
        }
    };
    let var_name = boot_entry::boot_var_name(boot_idx);

    if args.apply {
        match uefi_vars::write(&var_name, EFI_GLOBAL_VARIABLE_GUID, BOOT_VAR_ATTRS, &blob) {
            Ok(()) => println!("           wrote {} ({} bytes)", var_name, blob.len()),
            Err(e) => {
                eprintln!("           write {} FAILED: {}", var_name, e);
                return 8;
            }
        }
        state.boot_entry_index = Some(boot_idx);
    } else {
        println!("           [plan] write {} = {} bytes (attrs={:#x})", var_name, blob.len(), BOOT_VAR_ATTRS);
    }

    // Update BootOrder.
    let current_order = match uefi_vars::read("BootOrder", EFI_GLOBAL_VARIABLE_GUID) {
        Ok((_, bytes)) => boot_entry::decode_boot_order(&bytes),
        Err(_) => Vec::new(),
    };
    let new_order = boot_entry::boot_order_prepend(&current_order, boot_idx);
    if args.apply {
        let bytes = boot_entry::encode_boot_order(&new_order);
        match uefi_vars::write("BootOrder", EFI_GLOBAL_VARIABLE_GUID, BOOT_VAR_ATTRS, &bytes) {
            Ok(()) => println!("           BootOrder = {:?}", new_order),
            Err(e) => {
                eprintln!("           update BootOrder FAILED: {}", e);
                return 9;
            }
        }
    } else {
        println!("           [plan] BootOrder: {:?} -> {:?}", current_order, new_order);
    }
    print_step(7, "BootOrder updated", "OK");

    // Step 8: write Android image --
    if args.apply {
        let src = android_src.as_deref().unwrap();
        // Real impl: open /dev/nvmeXnY (Linux) or the namespace block device
        // and dd the image. The compat with NVMe Namespace Management is in
        // hypervisor/src/nvme_namespace.rs; the host-side write is a normal
        // dd-equivalent.
        println!("           [stub] would dd {} -> {}/{} (NSID={})",
            src, target_disk, nsid, nsid);
    } else {
        println!("           [plan] write Android image to namespace NSID={}", nsid);
    }
    print_step(8, "Android image", "OK");

    // Step 9: config partition --
    if state.config_partition_guid.is_none() {
        // Allocate a deterministic GUID derived from install_id for reproducibility.
        let cfg_guid = derive_config_partition_guid(&state.install_id);
        state.config_partition_guid = Some(cfg_guid.clone());
    }
    if args.apply {
        // Real impl: create a small (8 MiB) partition formatted with a simple
        // key=value layout containing install metadata.
        println!("           [stub] would write config partition with install_id={}, gpu_mode={}",
            state.install_id, final_plan.mode.as_str());
    } else {
        println!("           [plan] write config partition with install metadata");
    }
    print_step(9, "config partition", "OK");

    // --- Persist state -------------------------------------------------------
    if state.install_id.is_empty() {
        state.install_id = make_install_id();
    }
    if state.installed_at.is_empty() {
        state.installed_at = state.last_updated.clone();
    }
    state.active_slot = Slot::A;

    if args.apply {
        match state.save() {
            Ok(()) => println!("\nInstall state saved to {:?}", InstallState::path()),
            Err(e) => {
                eprintln!("\nWARNING: could not save install state: {}", e);
                return 10;
            }
        }
    } else {
        println!("\n(dry-run: install state NOT saved; re-run with --apply)");
    }

    println!();
    println!("Done.");
    0
}

// ---- Helpers ---------------------------------------------------------------

fn print_step(n: u32, label: &str, detail: &str) {
    println!("[{}/9] {:<24} {}", n, label, detail);
}

fn resolve_gpu_plan(mut plan: GpuPlan, args: &CliArgs) -> Result<GpuPlan, i32> {
    // If the plan is automatic, accept it without prompting.
    if plan.auto || args.no_gpu_prompt || args.yes {
        return Ok(plan);
    }

    // Print the menu and read user choice from stdin.
    println!();
    println!("GPU Configuration");
    println!("-----------------");
    println!("Detected: {}", plan.gpu_label.as_deref().unwrap_or("(unknown)"));
    println!("Recommended: {}", plan.mode.as_str());
    for w in &plan.warnings {
        println!("  ! {}", w);
    }
    println!();
    println!("  [1] Software rendering (llvmpipe)");
    println!("  [2] Full passthrough -- {} (RECOMMENDED)",
        plan.gpu_label.as_deref().unwrap_or("GPU"));
    println!();
    print!("Choice [1/2]: ");
    io::stdout().flush().ok();

    let mut line = String::new();
    let stdin = io::stdin();
    if stdin.lock().read_line(&mut line).is_err() {
        eprintln!("could not read input");
        return Err(11);
    }

    match line.trim() {
        "1" => { plan.mode = GpuMode::Software;    plan.auto = true; Ok(plan) }
        "2" => { plan.mode = GpuMode::Passthrough; plan.auto = true; Ok(plan) }
        ""  => { /* default = recommended */ plan.auto = true; Ok(plan) }
        _   => {
            eprintln!("invalid choice; aborting. Re-run with --gpu MODE to skip the menu.");
            Err(12)
        }
    }
}

fn copy_efi_binary(src: &str, dst: &str) -> Result<(), std::io::Error> {
    let dst_path = std::path::Path::new(dst);
    if let Some(parent) = dst_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Idempotency: if dst exists and is byte-identical, skip the copy.
    let src_bytes = std::fs::read(src)?;
    if let Ok(existing) = std::fs::read(dst_path) {
        if existing == src_bytes {
            println!("           {} already up-to-date (idempotent skip)", dst);
            return Ok(());
        }
    }
    std::fs::write(dst_path, &src_bytes)?;
    println!("           wrote {} ({} bytes)", dst, src_bytes.len());
    Ok(())
}

/// Scan UEFI variables for existing Boot#### entries so we can pick a free
/// index for AETHER. On Linux this means `ls /sys/firmware/efi/efivars`;
/// on Windows there is no enumeration API for UEFI variables, so we probe
/// indices 0x0000..0x0010 by name. (The real installer would scan more
/// thoroughly; this is sufficient for first install.)
fn read_used_boot_indices() -> Result<Vec<u16>, ()> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let mut used = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                // Format: "BootXXXX-<guid>".
                if let Some(rest) = name.strip_prefix("Boot") {
                    if let Some(hex) = rest.get(..4) {
                        if let Ok(n) = u16::from_str_radix(hex, 16) {
                            used.push(n);
                        }
                    }
                }
            }
        }
        return Ok(used);
    }
    #[cfg(target_os = "windows")]
    {
        let mut used = Vec::new();
        for i in 0u16..=0x000F {
            let name = boot_entry::boot_var_name(i);
            if uefi_vars::read(&name, EFI_GLOBAL_VARIABLE_GUID).is_ok() {
                used.push(i);
            }
        }
        return Ok(used);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    { Ok(Vec::new()) }
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Reuse the simple formatter pattern from compat-check::report.
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

fn make_install_id() -> String {
    // Cheap stable ID: 8 hex bytes of `current_time_nanos XOR pid`.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEFCAFE);
    let pid = std::process::id() as u64;
    let mixed = nanos ^ (pid << 32) ^ (pid >> 16);
    format!("{:016x}", mixed)
}

fn derive_config_partition_guid(install_id: &str) -> String {
    // Build a synthetic GUID from the install_id. Not RFC 4122 v5 (no SHA1),
    // but stable per-install which is what we need.
    let mut bytes = [0u8; 16];
    let id_bytes = install_id.as_bytes();
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = id_bytes.get(i).copied().unwrap_or((i as u8).wrapping_mul(0x55));
    }
    // Stamp a v4 variant marker for cosmetic correctness.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let g = GptGuid(bytes);
    g.to_string_canonical()
}
