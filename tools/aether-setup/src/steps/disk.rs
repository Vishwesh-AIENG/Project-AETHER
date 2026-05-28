use crate::{app::SetupApp, hwlist, theme};

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    ui.label("Pick the physical disk that will host the AETHER namespace. \
              The Windows partitions on the chosen disk are not touched — \
              AETHER installs into a new, separate NVMe namespace.");
    ui.add_space(12.0);

    if app.disks_cache.is_none() {
        app.disks_cache = Some(hwlist::enumerate());
    }
    let disks = app.disks_cache.as_ref().expect("just populated");

    if disks.is_empty() {
        ui.label(egui::RichText::new(
            "No disks detected. Run this installer as Administrator and \
             ensure the target disk is connected.").color(theme::ERR));
        if ui.button("Re-scan").clicked() { app.disks_cache = None; }
        return;
    }

    egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
        for (i, d) in disks.iter().enumerate() {
            let selected = app.selected_disk_index == Some(i);
            let frame = egui::Frame::group(ui.style()).inner_margin(10.0);
            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    let chosen = ui.selectable_label(
                        selected,
                        egui::RichText::new(&d.device_path).size(15.0));
                    if chosen.clicked() { app.selected_disk_index = Some(i); }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&d.kind).color(theme::SUBTLE));
                        ui.label(egui::RichText::new(d.size_human()).color(theme::TEXT));
                    });
                });
                ui.label(egui::RichText::new(&d.model).color(theme::SUBTLE));
            });
            ui.add_space(4.0);
        }
    });

    ui.add_space(8.0);
    if ui.button("Re-scan").clicked() {
        app.disks_cache = None;
        app.selected_disk_index = None;
    }
}
