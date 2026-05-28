// app.rs — top-level state machine. Holds every value the user has chosen
// so far plus enough metadata to decide whether the "Next" button is
// enabled on the current step.

use crate::hwlist::Disk;
use crate::installer::{CompatReport, InstallProgress};
use crate::setup_config::SetupConfig;
use crate::steps::Step;
use crate::theme;
use std::path::PathBuf;
use std::sync::Arc;

pub struct SetupApp {
    pub step: Step,
    pub eula_accepted: bool,

    /// Disk enumeration is cached on first visit to the Disk step.
    pub disks_cache: Option<Vec<Disk>>,
    pub selected_disk_index: Option<usize>,

    /// Compatibility report cached on first visit to the Compat step.
    pub compat: Option<CompatReport>,

    /// ch59 selections — what the user picked on the Wizard step.
    pub config: SetupConfig,

    /// Bundled artifact paths — sit next to the installer .exe by default.
    /// Users rarely change these; we expose them on the Confirm step for
    /// transparency.
    pub hypervisor_efi: PathBuf,
    pub selector_efi:   PathBuf,
    pub android_image:  PathBuf,

    /// Live install handle once the user clicks "Apply" on the Confirm
    /// step. None before that.
    pub install: Option<Arc<InstallProgress>>,

    /// User intent — Apply (destructive) vs Dry Run.
    pub apply: bool,
}

impl SetupApp {
    pub fn new() -> Self {
        let next_to = |name: &str| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join(name)))
                .unwrap_or_else(|| PathBuf::from(name))
        };
        Self {
            step: Step::Welcome,
            eula_accepted: false,
            disks_cache: None,
            selected_disk_index: None,
            compat: None,
            config: SetupConfig::defaults(),
            hypervisor_efi: next_to("hypervisor.efi"),
            selector_efi:   next_to("selector.efi"),
            android_image:  next_to("android.img"),
            install: None,
            apply: false,
        }
    }

    pub fn can_advance(&self) -> bool {
        match self.step {
            Step::Welcome  => true,
            Step::Eula     => self.eula_accepted,
            Step::Compat   => self.compat.as_ref().map(|c| c.passed).unwrap_or(false),
            Step::Disk     => self.selected_disk_index.is_some(),
            Step::Wizard   => true, // every field has a default
            Step::Confirm  => self.install.is_none(), // disable while running
            Step::Progress => {
                self.install.as_ref()
                    .map(|p| p.finished.load(std::sync::atomic::Ordering::Acquire))
                    .unwrap_or(false)
            }
            Step::Done => true,
        }
    }

    pub fn go_next(&mut self) {
        self.step = match self.step {
            Step::Welcome  => Step::Eula,
            Step::Eula     => Step::Compat,
            Step::Compat   => Step::Disk,
            Step::Disk     => Step::Wizard,
            Step::Wizard   => Step::Confirm,
            Step::Confirm  => Step::Progress,
            Step::Progress => Step::Done,
            Step::Done     => Step::Done,
        };
    }

    pub fn go_back(&mut self) {
        // Never reverse out of Progress / Done — those are point-of-no-return.
        self.step = match self.step {
            Step::Eula     => Step::Welcome,
            Step::Compat   => Step::Eula,
            Step::Disk     => Step::Compat,
            Step::Wizard   => Step::Disk,
            Step::Confirm  => Step::Wizard,
            other          => other,
        };
    }
}

impl eframe::App for SetupApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Sidebar shows the step list; central panel shows the active step.
        egui::SidePanel::left("steps")
            .resizable(false)
            .exact_width(220.0)
            .show(ctx, |ui| {
                ui.add_space(20.0);
                ui.heading(egui::RichText::new("AETHER Setup").color(theme::ACCENT));
                ui.add_space(8.0);
                ui.label(egui::RichText::new(env!("CARGO_PKG_VERSION")).color(theme::SUBTLE));
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);
                draw_sidebar_steps(ui, self.step);
            });

        egui::TopBottomPanel::bottom("nav")
            .resizable(false)
            .show_separator_line(true)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if matches!(self.step, Step::Eula | Step::Compat | Step::Disk | Step::Wizard | Step::Confirm) {
                        if ui.button("◀ Back").clicked() { self.go_back(); }
                    }
                    ui.add_space(8.0);
                    if matches!(self.step, Step::Welcome) {
                        if ui.button("Quit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = match self.step {
                            Step::Confirm  => if self.apply { "Apply ▶" } else { "Dry Run ▶" },
                            Step::Progress => "Continue ▶",
                            Step::Done     => "Reboot",
                            _              => "Next ▶",
                        };
                        let enabled = self.can_advance();
                        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                            if matches!(self.step, Step::Done) {
                                // Reboot is a privileged action; we let the
                                // user do it themselves with the documented
                                // shutdown command rather than calling
                                // ExitWindowsEx() from a GUI app.
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                return;
                            }
                            self.go_next();
                        }
                    });
                });
                ui.add_space(8.0);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);
            ui.heading(self.step.title());
            ui.add_space(4.0);
            ui.label(egui::RichText::new(format!("Step {} of {}",
                self.step.ordinal(), Step::total())).color(theme::SUBTLE));
            ui.add_space(20.0);

            match self.step {
                Step::Welcome  => crate::steps::welcome::draw(ui, self),
                Step::Eula     => crate::steps::eula::draw(ui, self),
                Step::Compat   => crate::steps::compat::draw(ui, self),
                Step::Disk     => crate::steps::disk::draw(ui, self),
                Step::Wizard   => crate::steps::wizard::draw(ui, self),
                Step::Confirm  => crate::steps::confirm::draw(ui, self),
                Step::Progress => {
                    crate::steps::progress::draw(ui, self);
                    // While the worker thread is running, request a repaint
                    // every 250 ms so the log pane stays live without
                    // pegging the CPU.
                    ctx.request_repaint_after(std::time::Duration::from_millis(250));
                }
                Step::Done     => crate::steps::done::draw(ui, self),
            }
        });
    }
}

fn draw_sidebar_steps(ui: &mut egui::Ui, current: Step) {
    let steps = [
        Step::Welcome, Step::Eula, Step::Compat, Step::Disk,
        Step::Wizard, Step::Confirm, Step::Progress, Step::Done,
    ];
    for s in steps {
        let label = format!("{}. {}", s.ordinal(), s.title());
        let color = if s == current { theme::ACCENT }
                    else if s.ordinal() < current.ordinal() { theme::OK }
                    else { theme::SUBTLE };
        ui.label(egui::RichText::new(label).color(color).size(14.0));
        ui.add_space(4.0);
    }
}
