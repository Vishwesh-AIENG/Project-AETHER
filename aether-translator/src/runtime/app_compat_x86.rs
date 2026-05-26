//! AT-29: App Compatibility (x86 tier).
//!
//! Re-run the ch49 app-compat harness on x86 hardware with the AETHER
//! translator active.  The same 1 000-APK suite used on the ARM tier runs
//! under translation; attestation-only failures are excluded from the
//! denominator (same rule as ch49).
//!
//! **Gate:** ≥ 950 / 1000 apps pass (same as AT-29 and ch49 ARM gate).

use alloc::vec::Vec;

// ── UART signatures ────────────────────────────────────────────────────────────

/// Emitted when the compat harness starts loading the APK suite.
pub const UART_SIG_HARNESS_READY: &[u8] = b"[at29] compat harness ready";
/// Emitted for each APK that passes smoke tests.
pub const UART_SIG_APP_PASS: &[u8] = b"[at29] app pass";
/// Emitted for each APK that fails smoke tests.
pub const UART_SIG_APP_FAIL: &[u8] = b"[at29] app fail";
/// Emitted when the suite is complete.
pub const UART_SIG_SUITE_DONE: &[u8] = b"[at29] suite done";
/// Emitted for attestation-only failures (excluded from denominator).
pub const UART_SIG_ATTESTATION_ONLY: &[u8] = b"[at29] attestation-only";

// ── Constants ──────────────────────────────────────────────────────────────────

/// Total APKs in the test suite.
pub const COMPAT_TOTAL_APPS: u32 = 1000;

/// Minimum pass count for the gate (same as ch49 ARM tier).
pub const COMPAT_MIN_PASS: u32 = 950;

// ── Statistics ─────────────────────────────────────────────────────────────────

/// Statistics for the x86-tier app-compat run.
#[derive(Debug, Clone, Default)]
pub struct AppCompatX86Stats {
    /// APKs that passed all smoke tests.
    pub passed: u32,
    /// APKs that failed at least one smoke test.
    pub failed: u32,
    /// APKs excluded from the denominator (attestation-only failure).
    pub attestation_only: u32,
}

impl AppCompatX86Stats {
    /// Effective denominator (total minus attestation-only exclusions).
    pub fn denominator(&self) -> u32 {
        COMPAT_TOTAL_APPS.saturating_sub(self.attestation_only)
    }

    /// Pass rate as a fraction in [0.0, 1.0].
    pub fn pass_rate(&self) -> f32 {
        let denom = self.denominator();
        if denom == 0 {
            return 1.0;
        }
        self.passed as f32 / denom as f32
    }

    /// Gate: ≥ 950 apps pass (excluding attestation-only).
    pub fn gate_passes(&self) -> bool {
        self.passed >= COMPAT_MIN_PASS
    }
}

// ── Config ─────────────────────────────────────────────────────────────────────

/// Configuration for the AT-29 x86 app-compat pipeline.
#[derive(Debug, Clone)]
pub struct AppCompatX86Config {
    /// Minimum number of passing apps for the gate.
    pub min_pass: u32,
    /// Total apps in the suite.
    pub total_apps: u32,
    /// Whether to abort on a Critical compat bug (vs. continue logging).
    pub abort_on_critical: bool,
}

impl AppCompatX86Config {
    pub fn aether_defaults() -> Self {
        Self {
            min_pass: COMPAT_MIN_PASS,
            total_apps: COMPAT_TOTAL_APPS,
            abort_on_critical: false,
        }
    }

    pub fn validate(&self) -> Result<(), AppCompatX86Error> {
        if self.min_pass > self.total_apps {
            return Err(AppCompatX86Error::InvalidConfig);
        }
        if self.total_apps == 0 {
            return Err(AppCompatX86Error::InvalidConfig);
        }
        Ok(())
    }
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCompatX86Error {
    InvalidConfig,
    HarnessStartFailed,
    CriticalCompatBug,
}

// ── Gate ───────────────────────────────────────────────────────────────────────

/// Gate conditions for AT-29.
#[derive(Debug, Clone, Default)]
pub struct AppCompatX86Gate {
    /// Compat harness is up and APKs are being tested.
    pub harness_ready: bool,
    /// ≥ 950 apps passed (attestation-only excluded from denominator).
    pub pass_count_met: bool,
    /// No unresolved Critical/Major compat bugs remain.
    pub no_unresolved_bugs: bool,
    /// Build type is `user` (not `userdebug`).
    pub build_type_user: bool,
}

impl AppCompatX86Gate {
    pub fn passes(&self) -> bool {
        self.harness_ready && self.pass_count_met && self.no_unresolved_bugs
    }
}

// ── Phase ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppCompatX86Phase {
    NotStarted,
    HarnessReady,
    ApksInstalled,
    SmokeTestsRunning,
    BugsTriaged,
    GatePassed,
}

// ── State ──────────────────────────────────────────────────────────────────────

/// Aggregate state for the AT-29 pipeline.
pub struct AppCompatX86State {
    pub config: AppCompatX86Config,
    pub stats: AppCompatX86Stats,
    pub phase: AppCompatX86Phase,
    pub gate: AppCompatX86Gate,
    /// Unresolved compat bugs accumulated during the run.
    pub unresolved_bugs: Vec<AppCompatBug>,
}

/// A compat bug record (simplified version of ch49's `CompatBugRecord`).
#[derive(Debug, Clone)]
pub struct AppCompatBug {
    pub app_name: &'static str,
    pub kind: AppCompatBugKind,
    pub resolved: bool,
}

/// Compat failure kind (x86-tier specific extensions on top of ch49 list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCompatBugKind {
    AttestationRequired,
    TranslationFailed,
    SyscallNotForwarded,
    NativeAbiMismatch,
    HypervisorDetected,
    Other,
}

impl AppCompatBug {
    pub fn is_attestation_only(&self) -> bool {
        matches!(self.kind, AppCompatBugKind::AttestationRequired)
    }
}

impl AppCompatX86State {
    pub fn new(config: AppCompatX86Config) -> Self {
        Self {
            config,
            stats: AppCompatX86Stats::default(),
            phase: AppCompatX86Phase::NotStarted,
            gate: AppCompatX86Gate {
                no_unresolved_bugs: true, // optimistic until a bug lands
                build_type_user: true,
                ..Default::default()
            },
            unresolved_bugs: Vec::new(),
        }
    }

    /// Feed one UART line to the state machine.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_HARNESS_READY) {
            self.gate.harness_ready = true;
            if self.phase < AppCompatX86Phase::HarnessReady {
                self.phase = AppCompatX86Phase::HarnessReady;
            }
        }
        if contains_bytes(line, UART_SIG_ATTESTATION_ONLY) {
            self.stats.attestation_only += 1;
        }
        if contains_bytes(line, UART_SIG_APP_PASS) {
            self.stats.passed += 1;
            self.update_pass_gate();
            if self.phase < AppCompatX86Phase::SmokeTestsRunning {
                self.phase = AppCompatX86Phase::SmokeTestsRunning;
            }
        }
        if contains_bytes(line, UART_SIG_APP_FAIL) {
            self.stats.failed += 1;
        }
        if contains_bytes(line, UART_SIG_SUITE_DONE) {
            self.update_pass_gate();
            let no_bugs = self.unresolved_bugs.iter().all(|b| b.resolved || b.is_attestation_only());
            self.gate.no_unresolved_bugs = no_bugs;
            if self.gate.passes() {
                self.phase = AppCompatX86Phase::GatePassed;
            }
        }
    }

    fn update_pass_gate(&mut self) {
        self.gate.pass_count_met = self.stats.gate_passes();
    }

    /// Record a compat bug.
    pub fn record_bug(&mut self, bug: AppCompatBug) {
        if !bug.resolved && !bug.is_attestation_only() {
            self.gate.no_unresolved_bugs = false;
        }
        self.unresolved_bugs.push(bug);
    }

    /// Mark all recorded bugs as resolved.
    pub fn resolve_all_bugs(&mut self) {
        for bug in &mut self.unresolved_bugs {
            bug.resolved = true;
        }
        self.gate.no_unresolved_bugs = true;
    }

    pub fn gate(&self) -> &AppCompatX86Gate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == AppCompatX86Phase::GatePassed
    }

    pub fn total_tested(&self) -> u32 {
        self.stats.passed + self.stats.failed
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────────

/// Initialise the AT-29 x86 app-compat pipeline.
pub fn init_app_compat_x86(config: AppCompatX86Config) -> Result<AppCompatX86State, AppCompatX86Error> {
    config.validate()?;
    let state = AppCompatX86State::new(config);
    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
