use crate::{app::SetupApp, installer, theme};

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    ui.label("Verifying that this machine can run AETHER. \
              The same check is available on the command line as \
              `aether-install check`.");
    ui.add_space(12.0);

    if app.compat.is_none() {
        if ui.button("Run compatibility check").clicked() {
            app.compat = Some(installer::run_compat_check());
        }
        return;
    }
    let report = app.compat.as_ref().expect("just checked");

    let (color, head) = if report.passed {
        (theme::OK, "Compatible.")
    } else {
        (theme::ERR, "Not compatible.")
    };
    ui.label(egui::RichText::new(head).color(color).size(20.0).strong());
    ui.add_space(4.0);
    ui.label(egui::RichText::new(&report.summary).color(theme::TEXT));
    ui.add_space(12.0);

    ui.collapsing("Raw report (JSON)", |ui| {
        egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
            ui.add(egui::TextEdit::multiline(&mut report.raw_json.as_str())
                .desired_width(f32::INFINITY)
                .code_editor());
        });
    });

    ui.add_space(8.0);
    if ui.button("Re-run").clicked() {
        app.compat = None;
    }
}
