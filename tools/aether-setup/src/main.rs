// aether-setup — Windows GUI installer for AETHER.
//
// What this is:
//   The downloadable .exe a user double-clicks to install AETHER on their PC.
//   Walks them through compatibility, disk selection, first-boot preferences
//   (language / keyboard / timezone / bridge / sensor profile) — the choices
//   that would otherwise be made by ch59's GOP-framebuffer wizard at first
//   AETHER boot — then invokes the existing `aether-install` CLI as a
//   subprocess to do the actual destructive work.
//
// What this is NOT:
//   * A replacement for aether-install. The CLI is still the canonical
//     install pipeline; this binary just drives it.
//   * The hypervisor-side ch59 wizard. That still exists; this one
//     pre-populates the AETHER config partition so ch59 can early-out on
//     first boot.
//
// Design rules (mirror aether-install's):
//   * Dry-run is the default. The Confirm screen has a clear "Apply" button.
//   * Never disables Secure Boot. Tells the user the shim+MOK enrollment
//     path; the actual MOK work is in ch57 / aether-install secure_boot.rs.
//   * No outbound network. The whole UI is offline; if a future screen
//     needs documentation, it links to a local HTML page on the ESP.
//   * Idempotent. Closing the app and reopening it resumes from where the
//     user left off (state file at %ProgramData%\AETHER\setup-state.json).

// Disable the Windows console window on release builds — this is a GUI app.
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

mod app;
mod installer;
mod hwlist;
mod setup_config;
mod steps;
mod theme;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("AETHER Setup")
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "AETHER Setup",
        options,
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::SetupApp::new()))
        }),
    )
}
