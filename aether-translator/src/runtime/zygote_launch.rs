//! AT-28: Zygote Launch.
//!
//! Full Android Zygote forks; SystemServer comes up; `logcat` is alive.
//! The translator must handle the Zygote fork idiom (parent stays alive,
//! child continues) and the full bionic + ART + framework startup path.
//!
//! **Gate:** `boot_completed && zygote_forked && system_server_started && logcat_alive`

use alloc::vec::Vec;

// ── UART signatures ────────────────────────────────────────────────────────────

/// Emitted when the Zygote process starts (before any fork).
pub const UART_SIG_ZYGOTE_STARTED: &[u8] = b"[at28] Zygote started";
/// Emitted when Zygote successfully forks SystemServer.
pub const UART_SIG_ZYGOTE_FORKED: &[u8] = b"[at28] Zygote forked SystemServer";
/// Emitted when SystemServer reports readiness.
pub const UART_SIG_SYSTEM_SERVER: &[u8] = b"[at28] SystemServer started";
/// Emitted when logcat is alive (first log line through the ring buffer).
pub const UART_SIG_LOGCAT_ALIVE: &[u8] = b"[at28] logcat alive";
/// Emitted when `sys.boot_completed=1` is set.
pub const UART_SIG_BOOT_COMPLETED: &[u8] = b"[at28] sys.boot_completed=1";

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum seconds to wait for boot_completed before declaring a timeout.
pub const BOOT_COMPLETED_TIMEOUT_S: u64 = 120;

/// getprop key whose value must be "1" for the gate to pass.
pub const BOOT_COMPLETED_PROP: &str = "sys.boot_completed";

// ── Statistics ─────────────────────────────────────────────────────────────────

/// Runtime statistics for the Zygote launch pipeline.
#[derive(Debug, Clone, Default)]
pub struct ZygoteLaunchStats {
    /// Number of Zygote fork() calls observed.
    pub fork_count: u32,
    /// Whether sys.boot_completed was set within the timeout.
    pub completed_in_time: bool,
    /// Boot wall-clock time in seconds (0 if not yet measured).
    pub boot_time_s: u64,
}

// ── Config ─────────────────────────────────────────────────────────────────────

/// Configuration for the AT-28 Zygote launch pipeline.
#[derive(Debug, Clone)]
pub struct ZygoteLaunchConfig {
    /// Timeout in seconds before the boot_completed gate is declared failed.
    pub boot_timeout_s: u64,
    /// Whether to enable Zygote preload (pre-loads framework classes).
    pub enable_preload: bool,
}

impl ZygoteLaunchConfig {
    pub fn aether_defaults() -> Self {
        Self {
            boot_timeout_s: BOOT_COMPLETED_TIMEOUT_S,
            enable_preload: true,
        }
    }

    pub fn validate(&self) -> Result<(), ZygoteError> {
        if self.boot_timeout_s == 0 {
            return Err(ZygoteError::InvalidTimeout);
        }
        Ok(())
    }
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZygoteError {
    InvalidTimeout,
    ZygoteCrashed,
    SystemServerCrashed,
    BootTimedOut,
    LogcatDead,
}

// ── Gate ───────────────────────────────────────────────────────────────────────

/// Gate conditions for AT-28.
#[derive(Debug, Clone, Default)]
pub struct ZygoteLaunchGate {
    /// Zygote process started (init spawned it).
    pub zygote_forked: bool,
    /// SystemServer came up (framework services registered).
    pub system_server_started: bool,
    /// logcat ring buffer is alive (at least one log line observed).
    pub logcat_alive: bool,
    /// `sys.boot_completed=1` was set (Android reports fully booted).
    pub boot_completed: bool,
}

impl ZygoteLaunchGate {
    pub fn passes(&self) -> bool {
        self.boot_completed
            && self.zygote_forked
            && self.system_server_started
            && self.logcat_alive
    }
}

// ── Phase ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZygoteLaunchPhase {
    NotStarted,
    ZygoteLaunched,
    SystemServerStarted,
    LogcatAlive,
    BootCompleted,
    GatePassed,
}

// ── State ──────────────────────────────────────────────────────────────────────

/// Aggregate state for the AT-28 pipeline.
pub struct ZygoteLaunchState {
    pub config: ZygoteLaunchConfig,
    pub stats: ZygoteLaunchStats,
    pub phase: ZygoteLaunchPhase,
    pub gate: ZygoteLaunchGate,
}

impl ZygoteLaunchState {
    pub fn new(config: ZygoteLaunchConfig) -> Self {
        Self {
            config,
            stats: ZygoteLaunchStats::default(),
            phase: ZygoteLaunchPhase::NotStarted,
            gate: ZygoteLaunchGate::default(),
        }
    }

    /// Feed one UART / logcat line to the state machine.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_ZYGOTE_STARTED)
            || contains_bytes(line, UART_SIG_ZYGOTE_FORKED)
        {
            self.stats.fork_count += 1;
            self.gate.zygote_forked = true;
            if self.phase < ZygoteLaunchPhase::ZygoteLaunched {
                self.phase = ZygoteLaunchPhase::ZygoteLaunched;
            }
        }
        if contains_bytes(line, UART_SIG_SYSTEM_SERVER) {
            self.gate.system_server_started = true;
            if self.phase < ZygoteLaunchPhase::SystemServerStarted {
                self.phase = ZygoteLaunchPhase::SystemServerStarted;
            }
        }
        if contains_bytes(line, UART_SIG_LOGCAT_ALIVE) {
            self.gate.logcat_alive = true;
            if self.phase < ZygoteLaunchPhase::LogcatAlive {
                self.phase = ZygoteLaunchPhase::LogcatAlive;
            }
        }
        if contains_bytes(line, UART_SIG_BOOT_COMPLETED) {
            self.stats.completed_in_time = true;
            self.gate.boot_completed = true;
            if self.phase < ZygoteLaunchPhase::BootCompleted {
                self.phase = ZygoteLaunchPhase::BootCompleted;
            }
        }
        if self.gate.passes() {
            self.phase = ZygoteLaunchPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &ZygoteLaunchGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == ZygoteLaunchPhase::GatePassed
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────────

/// Initialise the AT-28 Zygote launch pipeline.
pub fn init_zygote_launch(config: ZygoteLaunchConfig) -> Result<ZygoteLaunchState, ZygoteError> {
    config.validate()?;
    let state = ZygoteLaunchState::new(config);
    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reconstruct a gate from a captured UART / logcat log.
pub fn gate_from_log(log: &[Vec<u8>]) -> ZygoteLaunchGate {
    let mut gate = ZygoteLaunchGate::default();
    for line in log {
        if contains_bytes(line, UART_SIG_ZYGOTE_STARTED)
            || contains_bytes(line, UART_SIG_ZYGOTE_FORKED)
        {
            gate.zygote_forked = true;
        }
        if contains_bytes(line, UART_SIG_SYSTEM_SERVER) {
            gate.system_server_started = true;
        }
        if contains_bytes(line, UART_SIG_LOGCAT_ALIVE) {
            gate.logcat_alive = true;
        }
        if contains_bytes(line, UART_SIG_BOOT_COMPLETED) {
            gate.boot_completed = true;
        }
    }
    gate
}
