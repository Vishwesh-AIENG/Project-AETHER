use crate::{app::SetupApp, theme};

const EULA_TEXT: &str = "\
AETHER is provided under the Apache License 2.0. The hypervisor, installer, \
and bundled tooling are open source; the AOSP-derived Android image follows \
its upstream licensing.\n\n\
By installing AETHER you confirm that:\n\
  • You are the owner or authorised administrator of this device.\n\
  • You understand this installer creates a new NVMe namespace and a new \
    UEFI boot entry, and that these changes can be reverted later via \
    aether-install uninstall.\n\
  • AETHER does not collect telemetry. No data leaves this device as a \
    result of the install or first-boot configuration.\n\n\
Full license text ships in this directory as LICENSE.txt.";

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
        ui.label(egui::RichText::new(EULA_TEXT).color(theme::TEXT));
    });
    ui.add_space(12.0);
    ui.checkbox(&mut app.eula_accepted,
                "I have read and accept the AETHER license terms.");
    if !app.eula_accepted {
        ui.add_space(4.0);
        ui.label(egui::RichText::new("(check the box to continue)").color(theme::SUBTLE));
    }
}
