use crate::{app::SetupApp, theme};

pub fn draw(ui: &mut egui::Ui, _app: &mut SetupApp) {
    ui.label("This installer turns this PC into an AETHER device.");
    ui.add_space(8.0);
    ui.label(egui::RichText::new(
        "AETHER is a Type-1 hypervisor that boots a complete Android \
         environment directly on your hardware — no host OS, no detectable \
         fingerprint, full app compatibility.").color(theme::TEXT));
    ui.add_space(16.0);

    ui.group(|ui| {
        ui.set_max_width(620.0);
        ui.label(egui::RichText::new("Before you continue:").color(theme::ACCENT).strong());
        ui.add_space(4.0);
        ui.label("• AETHER installs into its own NVMe namespace and does not modify Windows.");
        ui.label("• Secure Boot stays enabled — the installer uses the shim + MOK path.");
        ui.label("• An EFI System Partition with at least 512 MB free is required.");
        ui.label("• You will be asked to confirm a destructive action before anything is written.");
    });

    ui.add_space(16.0);
    ui.label(egui::RichText::new("Press Next to begin.").color(theme::SUBTLE));
}
