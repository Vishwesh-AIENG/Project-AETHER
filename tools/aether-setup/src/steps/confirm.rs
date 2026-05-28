// confirm.rs — final review screen. Shows exactly what will happen and
// requires an explicit click on either "Dry Run" or "Apply" before the
// next step kicks off the install.

use crate::{app::SetupApp, installer::{self, InstallParams}, setup_config::SETUP_CONFIG_FILENAME, theme};
use std::io::Write;

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    let disk = app.selected_disk_index
        .and_then(|i| app.disks_cache.as_ref().and_then(|d| d.get(i)))
        .cloned();

    ui.group(|ui| {
        ui.set_max_width(640.0);
        ui.label(egui::RichText::new("Target").color(theme::ACCENT).strong());
        match &disk {
            Some(d) => {
                ui.label(format!("{}", d.device_path));
                ui.label(egui::RichText::new(format!("{} — {}", d.model, d.size_human()))
                    .color(theme::SUBTLE));
            }
            None => { ui.label(egui::RichText::new("(none)").color(theme::ERR)); }
        }
    });

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.set_max_width(640.0);
        ui.label(egui::RichText::new("First-boot preferences").color(theme::ACCENT).strong());
        ui.label(format!("Language:        {}", app.config.language));
        ui.label(format!("Keyboard layout: {}", app.config.keyboard_layout));
        ui.label(format!("Time zone:       {}", app.config.timezone));
        ui.label(format!("Bridge mode:     {:?}", app.config.bridge_mode));
        ui.label(format!("Sensor profile:  {:?}", app.config.sensor_profile));
    });

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.set_max_width(640.0);
        ui.label(egui::RichText::new("Artifacts").color(theme::ACCENT).strong());
        ui.label(format!("Hypervisor:    {}", app.hypervisor_efi.display()));
        ui.label(format!("Boot selector: {}", app.selector_efi.display()));
        ui.label(format!("Android image: {}", app.android_image.display()));
    });

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        ui.selectable_value(&mut app.apply, false, "Dry run (no disk writes)");
        ui.selectable_value(&mut app.apply, true,  "Apply (write to disk)");
    });
    if app.apply {
        ui.label(egui::RichText::new(
            "⚠ Apply will modify partition metadata on the selected disk \
             and add an AETHER UEFI boot entry.").color(theme::ERR));
    } else {
        ui.label(egui::RichText::new(
            "Dry run prints the plan but writes nothing.").color(theme::SUBTLE));
    }

    if let (None, Some(d)) = (&app.install, disk) {
        ui.add_space(12.0);
        if ui.button(if app.apply { "Begin install" } else { "Run dry-run" }).clicked() {
            // Write setup-config.json to a temp path; the installer
            // subprocess copies it into the ESP via AETHER_SETUP_CONFIG_JSON.
            let cfg_path = match write_setup_config(app) {
                Ok(p) => p,
                Err(e) => {
                    // Show the error inline rather than panicking — the
                    // user can fix permissions and click again.
                    ui.colored_label(theme::ERR, format!("Could not write {}: {}", SETUP_CONFIG_FILENAME, e));
                    return;
                }
            };
            app.install = Some(installer::spawn_install(InstallParams {
                target_disk:    d.device_path.clone(),
                hypervisor_efi: app.hypervisor_efi.clone(),
                selector_efi:   app.selector_efi.clone(),
                android_image:  app.android_image.clone(),
                esp_mount:      None,
                setup_config:   cfg_path,
                apply:          app.apply,
            }));
            // Bounce to the Progress step.
            app.step = crate::steps::Step::Progress;
        }
    }
}

fn write_setup_config(app: &SetupApp) -> std::io::Result<std::path::PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("aether-setup");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(SETUP_CONFIG_FILENAME);
    let mut f = std::fs::File::create(&path)?;
    f.write_all(app.config.to_json().as_bytes())?;
    Ok(path)
}
