// installer.rs — thin async wrapper around the aether-install CLI.
//
// We don't link aether-install as a library because (a) it shells out itself,
// (b) we want the GUI to survive an installer panic and (c) we want users to
// be able to read the exact CLI invocation we ran from the log pane.
//
// The model here is:
//   * spawn aether-install with the right args + a captured stdout/stderr pipe
//   * a background thread drains the pipes line-by-line into a Mutex<Vec<String>>
//   * the GUI polls that buffer once per frame and renders it
//   * exit status surfaces through an AtomicI32 the UI checks

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Where the bundled `aether-install.exe` lives, relative to this binary.
/// At install time we expect both to sit next to each other under
/// `%ProgramFiles%\AETHER\` (or in the same `target/release` folder during
/// dev). Override with the `AETHER_INSTALL_PATH` environment variable.
pub fn aether_install_exe() -> PathBuf {
    if let Ok(p) = std::env::var("AETHER_INSTALL_PATH") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().ok();
    let dir = exe.as_ref().and_then(|p| p.parent()).map(Path::to_path_buf);
    let mut candidate = dir.unwrap_or_else(|| PathBuf::from("."));
    candidate.push(if cfg!(windows) { "aether-install.exe" } else { "aether-install" });
    candidate
}

#[derive(Debug, Default)]
pub struct CompatReport {
    pub passed: bool,
    pub summary: String,
    pub raw_json: String,
}

/// Run `aether-install check --json` synchronously. Cheap (read-only), so
/// we block the UI for the few hundred ms it takes.
pub fn run_compat_check() -> CompatReport {
    let exe = aether_install_exe();
    let out = Command::new(&exe).args(["--json", "check"]).output();
    let Ok(out) = out else {
        return CompatReport {
            passed: false,
            summary: format!("Could not run {}: not found.", exe.display()),
            raw_json: String::new(),
        };
    };
    let json = String::from_utf8_lossy(&out.stdout).to_string();
    let passed = out.status.success();
    let summary = if passed {
        "Compatibility check passed.".to_string()
    } else {
        format!("Compatibility check failed (exit {}).",
                out.status.code().unwrap_or(-1))
    };
    CompatReport { passed, summary, raw_json: json }
}

/// Backing store for an in-progress install. Shared between the worker
/// thread and the UI; UI must only read.
#[derive(Default)]
pub struct InstallProgress {
    pub lines:    Mutex<Vec<String>>,
    pub finished: AtomicBool,
    pub exit:     AtomicI32,
}

impl InstallProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(InstallProgress {
            lines:    Mutex::new(Vec::new()),
            finished: AtomicBool::new(false),
            exit:     AtomicI32::new(0),
        })
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

/// Inputs the user supplied across the wizard steps.
pub struct InstallParams {
    pub target_disk:    String,
    pub hypervisor_efi: PathBuf,
    pub selector_efi:   PathBuf,
    pub android_image:  PathBuf,
    pub esp_mount:      Option<String>,
    pub setup_config:   PathBuf,
    pub apply:          bool,
}

/// Spawn the install. Returns immediately; UI polls `progress`.
pub fn spawn_install(params: InstallParams) -> Arc<InstallProgress> {
    let progress = InstallProgress::new();
    let prog_for_thread = progress.clone();
    thread::spawn(move || {
        let exe = aether_install_exe();
        let mut cmd = Command::new(&exe);
        if params.apply { cmd.arg("--apply"); }
        cmd.arg("--yes")
           .arg("install")
           .arg("--hypervisor").arg(&params.hypervisor_efi)
           .arg("--selector").arg(&params.selector_efi)
           .arg("--android-image").arg(&params.android_image)
           .arg("--target-disk").arg(&params.target_disk);
        if let Some(esp) = &params.esp_mount { cmd.arg("--esp").arg(esp); }
        // setup-config.json: we pass it via environment because the CLI
        // already has an established flag surface and adding a new flag
        // touches release-tested code paths. The CLI's install.rs reads
        // AETHER_SETUP_CONFIG_JSON if set and copies that file into the ESP
        // root alongside hypervisor.efi.
        cmd.env("AETHER_SETUP_CONFIG_JSON", &params.setup_config);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let push = |p: &InstallProgress, s: String| {
            if let Ok(mut v) = p.lines.lock() { v.push(s); }
        };

        push(&prog_for_thread,
             format!("$ {} {}", exe.display(),
                     cmd.get_args()
                        .map(|a| a.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(" ")));

        let child = cmd.spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                push(&prog_for_thread,
                     format!("ERROR: could not spawn aether-install: {}", e));
                prog_for_thread.exit.store(-1, Ordering::Release);
                prog_for_thread.finished.store(true, Ordering::Release);
                return;
            }
        };

        // Drain stdout on this thread; stderr on a helper.
        if let Some(stderr) = child.stderr.take() {
            let prog2 = prog_for_thread.clone();
            thread::spawn(move || {
                let r = BufReader::new(stderr);
                for line in r.lines().map_while(|l| l.ok()) {
                    push(&prog2, format!("[err] {}", line));
                }
            });
        }
        if let Some(stdout) = child.stdout.take() {
            let r = BufReader::new(stdout);
            for line in r.lines().map_while(|l| l.ok()) {
                push(&prog_for_thread, line);
            }
        }

        let status = child.wait();
        let code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
        prog_for_thread.exit.store(code, Ordering::Release);
        prog_for_thread.finished.store(true, Ordering::Release);
        push(&prog_for_thread, format!("--- aether-install exited with {} ---", code));
    });
    progress
}
