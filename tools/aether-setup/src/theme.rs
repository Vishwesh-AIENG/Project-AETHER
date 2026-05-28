// theme.rs — visual identity. Dark slate background, AETHER amber accent,
// monospace mono. Single entry point so the entire app gets one consistent
// look without per-widget styling at the call site.

use egui::{Color32, Stroke, Visuals};

pub const ACCENT: Color32 = Color32::from_rgb(0xFF, 0xC1, 0x07); // AETHER amber
pub const BG:     Color32 = Color32::from_rgb(0x0E, 0x12, 0x18); // near-black slate
pub const PANEL:  Color32 = Color32::from_rgb(0x14, 0x1A, 0x22);
pub const TEXT:   Color32 = Color32::from_rgb(0xE8, 0xE8, 0xE8);
pub const SUBTLE: Color32 = Color32::from_rgb(0x8A, 0x95, 0xA5);
pub const ERR:    Color32 = Color32::from_rgb(0xE5, 0x4B, 0x4B);
pub const OK:     Color32 = Color32::from_rgb(0x4C, 0xC2, 0x7C);

pub fn install(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = BG;
    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.inactive.bg_fill = PANEL;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x1E, 0x26, 0x32);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0x2A, 0x33, 0x40);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.selection.bg_fill = ACCENT.linear_multiply(0.4);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.override_text_color = Some(TEXT);
    ctx.set_visuals(visuals);

    let mut style: egui::Style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(12.0, 10.0);
    style.spacing.button_padding = egui::vec2(16.0, 8.0);
    ctx.set_style(style);
}
