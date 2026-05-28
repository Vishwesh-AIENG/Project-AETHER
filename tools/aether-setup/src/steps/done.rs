use crate::{app::SetupApp, theme};

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    if !app.apply {
        ui.label(egui::RichText::new("Dry run complete.").color(theme::ACCENT)
            .size(22.0).strong());
        ui.add_space(8.0);
        ui.label("Nothing was written to disk. Go back to Review and pick \
                  Apply to perform a real install.");
        return;
    }

    ui.label(egui::RichText::new("AETHER is installed.").color(theme::OK)
        .size(22.0).strong());
    ui.add_space(12.0);

    ui.group(|ui| {
        ui.set_max_width(640.0);
        ui.label(egui::RichText::new("Next steps").color(theme::ACCENT).strong());
        ui.label("1. Reboot the PC. The AETHER boot selector takes over.");
        ui.label("2. On the first run, Secure Boot will prompt you to enrol \
                  the AETHER MOK key. Choose Enrol from MokManager.");
        ui.label("3. After enrolment the device reboots once more and lands \
                  directly in your new Android environment.");
    });

    ui.add_space(12.0);
    ui.label(egui::RichText::new(
        "Your first-boot preferences have already been written, so the \
         in-firmware setup wizard is skipped."
    ).color(theme::SUBTLE));
}
