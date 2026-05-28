// progress.rs — streams the live aether-install output into a log pane.

use crate::{app::SetupApp, theme};
use std::sync::atomic::Ordering;

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    let Some(install) = app.install.clone() else {
        ui.label(egui::RichText::new(
            "No install in progress. Go back to Review and start one."
        ).color(theme::ERR));
        return;
    };

    let lines = install.snapshot();
    let finished = install.finished.load(Ordering::Acquire);
    let exit = install.exit.load(Ordering::Acquire);

    if finished {
        let (color, head) = if exit == 0 {
            (theme::OK, format!("aether-install finished (exit {}).", exit))
        } else {
            (theme::ERR, format!("aether-install failed (exit {}).", exit))
        };
        ui.label(egui::RichText::new(head).color(color).strong());
    } else {
        ui.label(egui::RichText::new("Installing — please don't close this window…")
            .color(theme::ACCENT));
        ui.spinner();
    }
    ui.add_space(8.0);

    let mut buf = lines.join("\n");
    egui::ScrollArea::vertical()
        .max_height(400.0)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.add(egui::TextEdit::multiline(&mut buf)
                .desired_width(f32::INFINITY)
                .desired_rows(18)
                .code_editor());
        });

    if finished && exit != 0 {
        ui.add_space(8.0);
        ui.label(egui::RichText::new(
            "Read the log above to identify the failing step. The install is \
             idempotent — fix the cause and re-run this installer."
        ).color(theme::SUBTLE));
    }
}
