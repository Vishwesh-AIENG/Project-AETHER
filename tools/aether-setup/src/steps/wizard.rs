// wizard.rs — the screen that mirrors the hypervisor's ch59 setup wizard.
//
// Everything the user picks here gets written to setup-config.json which
// the hypervisor reads on first boot and short-circuits its GOP-framebuffer
// wizard with — so the user only ever sees one wizard, this one.

use crate::{app::SetupApp, setup_config::{
    BridgeModeDefault, SensorProfile, LANGUAGES, KEYBOARDS, TIMEZONES,
}, theme};

pub fn draw(ui: &mut egui::Ui, app: &mut SetupApp) {
    ui.label("Pick the defaults your new AETHER device will boot with. You \
              can change any of these later from the AETHER Manager Android \
              app (ch63) or from Recovery Mode.");
    ui.add_space(16.0);

    egui::Grid::new("wizard_grid")
        .num_columns(2)
        .spacing([24.0, 14.0])
        .show(ui, |ui| {
            // Language --------------------------------------------------------
            ui.label("Language");
            egui::ComboBox::from_id_salt("language")
                .selected_text(language_display(&app.config.language))
                .width(280.0)
                .show_ui(ui, |ui| {
                    for (code, display) in LANGUAGES {
                        ui.selectable_value(&mut app.config.language,
                                            (*code).to_string(),
                                            *display);
                    }
                });
            ui.end_row();

            // Keyboard layout -------------------------------------------------
            ui.label("Keyboard layout");
            egui::ComboBox::from_id_salt("keyboard")
                .selected_text(&app.config.keyboard_layout)
                .width(280.0)
                .show_ui(ui, |ui| {
                    for kb in KEYBOARDS {
                        ui.selectable_value(&mut app.config.keyboard_layout,
                                            (*kb).to_string(), *kb);
                    }
                });
            ui.end_row();

            // Time zone -------------------------------------------------------
            ui.label("Time zone");
            egui::ComboBox::from_id_salt("timezone")
                .selected_text(&app.config.timezone)
                .width(280.0)
                .show_ui(ui, |ui| {
                    for tz in TIMEZONES {
                        ui.selectable_value(&mut app.config.timezone,
                                            (*tz).to_string(), *tz);
                    }
                });
            ui.end_row();

            // Bridge mode -----------------------------------------------------
            ui.label("Phone Bridge default");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut app.config.bridge_mode,
                                    BridgeModeDefault::Off, "Off");
                ui.selectable_value(&mut app.config.bridge_mode,
                                    BridgeModeDefault::On,  "On");
            });
            ui.end_row();

            // Sensor profile --------------------------------------------------
            ui.label("Sensor profile");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut app.config.sensor_profile,
                                    SensorProfile::Stationary, "Stationary");
                ui.selectable_value(&mut app.config.sensor_profile,
                                    SensorProfile::InHand,     "In hand");
                ui.selectable_value(&mut app.config.sensor_profile,
                                    SensorProfile::Driving,    "Driving");
            });
            ui.end_row();
        });

    ui.add_space(14.0);
    ui.label(egui::RichText::new(
        "These choices will be written into the AETHER config partition as \
         setup-config.json. The hypervisor reads them on first boot."
    ).color(theme::SUBTLE));
}

fn language_display(code: &str) -> String {
    LANGUAGES.iter().find(|(c, _)| *c == code)
        .map(|(_, d)| (*d).to_string())
        .unwrap_or_else(|| code.to_string())
}
