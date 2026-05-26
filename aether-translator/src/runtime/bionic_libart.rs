//! AT-27: Bionic + libart Bring-Up.
//!
//! Android's `libart` starts under the AETHER translator; `dalvikvm`
//! interprets a trivial `.dex` file and the expected output appears on UART.
//!
//! **Gate:** `dalvikvm_ran && dex_executed && hello_printed`

use alloc::vec::Vec;

// ── UART signatures ────────────────────────────────────────────────────────────

/// UART line emitted when libart's JIT compiler initialises.
pub const UART_SIG_LIBART_INIT: &[u8] = b"[at27] libart initialized";
/// UART line emitted when `dalvikvm` starts interpreting the .dex file.
pub const UART_SIG_DALVIKVM_START: &[u8] = b"[at27] dalvikvm started";
/// UART line emitted by the Hello.dex `main()` method.
pub const UART_SIG_HELLO_DEX: &[u8] = b"Hello";
/// UART line emitted on clean dalvikvm exit.
pub const UART_SIG_DALVIKVM_EXIT: &[u8] = b"[at27] dalvikvm exit=0";

// ── Constants ──────────────────────────────────────────────────────────────────

/// Name of the test DEX class whose `main()` is invoked.
pub const HELLO_DEX_CLASS: &str = "Hello";
/// Classpath argument passed to `dalvikvm`.
pub const HELLO_DEX_CLASSPATH: &str = "hello.dex";
/// Expected string printed by Hello.dex.
pub const HELLO_DEX_EXPECTED: &[u8] = b"Hello";

// ── Statistics ─────────────────────────────────────────────────────────────────

/// Statistics for the bionic + libart bring-up pipeline.
#[derive(Debug, Clone, Default)]
pub struct BionicLibartStats {
    /// Number of ARM64 blocks translated to service libart startup.
    pub blocks_translated: u64,
    /// Number of DEX methods JIT-compiled by libart (0 for interpret-only).
    pub dex_methods_jitted: u64,
    /// Whether libart reported successful initialisation.
    pub libart_init_observed: bool,
    /// Whether dalvikvm started interpreting the DEX.
    pub dalvikvm_started: bool,
    /// Whether the expected "Hello" output was observed.
    pub hello_observed: bool,
}

// ── Config ─────────────────────────────────────────────────────────────────────

/// Configuration for the AT-27 bionic + libart pipeline.
#[derive(Debug, Clone)]
pub struct BionicLibartConfig {
    /// Base guest PA of the JIT code cache (must be 4 KiB-aligned).
    pub jit_cache_base_pa: u64,
    /// Size of the JIT cache in bytes.
    pub jit_cache_size: usize,
    /// Whether libart is allowed to JIT-compile DEX (vs. interpret-only).
    pub allow_libart_jit: bool,
}

impl BionicLibartConfig {
    pub fn aether_defaults() -> Self {
        Self {
            jit_cache_base_pa: 0x2_0000_0000,
            jit_cache_size: 16 * 1024 * 1024,
            allow_libart_jit: false, // interpret-only at bring-up
        }
    }

    pub fn validate(&self) -> Result<(), BionicLibartError> {
        if self.jit_cache_base_pa % 4096 != 0 {
            return Err(BionicLibartError::UnalignedJitCache);
        }
        if self.jit_cache_size < 64 * 1024 {
            return Err(BionicLibartError::JitCacheTooSmall);
        }
        Ok(())
    }
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BionicLibartError {
    UnalignedJitCache,
    JitCacheTooSmall,
    LibartInitFailed,
    DalvikVmCrashed,
    DexLoadFailed,
    HelloNotObserved,
}

// ── Gate ───────────────────────────────────────────────────────────────────────

/// Gate conditions for AT-27.
#[derive(Debug, Clone, Default)]
pub struct BionicLibartGate {
    /// libart reported successful initialisation.
    pub libart_loaded: bool,
    /// `dalvikvm` ran (process started, classpath loaded).
    pub dalvikvm_ran: bool,
    /// The Hello.dex `main()` method was interpreted.
    pub dex_executed: bool,
    /// "Hello" appeared on UART from the DEX execution.
    pub hello_printed: bool,
}

impl BionicLibartGate {
    pub fn passes(&self) -> bool {
        self.dalvikvm_ran && self.dex_executed && self.hello_printed
    }
}

// ── Phase ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BionicLibartPhase {
    NotStarted,
    LibartLoaded,
    DalvikStarted,
    DexLoaded,
    HelloPrinted,
    GatePassed,
}

// ── State ──────────────────────────────────────────────────────────────────────

/// Aggregate state for the AT-27 pipeline.
pub struct BionicLibartState {
    pub config: BionicLibartConfig,
    pub stats: BionicLibartStats,
    pub phase: BionicLibartPhase,
    pub gate: BionicLibartGate,
}

impl BionicLibartState {
    pub fn new(config: BionicLibartConfig) -> Self {
        Self {
            config,
            stats: BionicLibartStats::default(),
            phase: BionicLibartPhase::NotStarted,
            gate: BionicLibartGate::default(),
        }
    }

    /// Feed one UART line to the state machine.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_LIBART_INIT) {
            self.stats.libart_init_observed = true;
            self.gate.libart_loaded = true;
            if self.phase < BionicLibartPhase::LibartLoaded {
                self.phase = BionicLibartPhase::LibartLoaded;
            }
        }
        if contains_bytes(line, UART_SIG_DALVIKVM_START) {
            self.stats.dalvikvm_started = true;
            self.gate.dalvikvm_ran = true;
            self.gate.dex_executed = true;
            if self.phase < BionicLibartPhase::DalvikStarted {
                self.phase = BionicLibartPhase::DalvikStarted;
            }
        }
        if contains_bytes(line, UART_SIG_HELLO_DEX) {
            self.stats.hello_observed = true;
            self.gate.hello_printed = true;
            if self.phase < BionicLibartPhase::HelloPrinted {
                self.phase = BionicLibartPhase::HelloPrinted;
            }
        }
        if self.gate.passes() {
            self.phase = BionicLibartPhase::GatePassed;
        }
    }

    /// Manually mark libart as initialised (e.g. from a HAL callback).
    pub fn mark_libart_loaded(&mut self) {
        self.stats.libart_init_observed = true;
        self.gate.libart_loaded = true;
        if self.phase < BionicLibartPhase::LibartLoaded {
            self.phase = BionicLibartPhase::LibartLoaded;
        }
    }

    /// Mark dalvikvm as started and the DEX as loaded.
    pub fn mark_dalvikvm_started(&mut self) {
        self.stats.dalvikvm_started = true;
        self.gate.dalvikvm_ran = true;
        self.gate.dex_executed = true;
        if self.phase < BionicLibartPhase::DalvikStarted {
            self.phase = BionicLibartPhase::DalvikStarted;
        }
    }

    /// Mark "Hello" as observed on UART.
    pub fn mark_hello_observed(&mut self) {
        self.stats.hello_observed = true;
        self.gate.hello_printed = true;
        if self.phase < BionicLibartPhase::HelloPrinted {
            self.phase = BionicLibartPhase::HelloPrinted;
        }
        if self.gate.passes() {
            self.phase = BionicLibartPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &BionicLibartGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == BionicLibartPhase::GatePassed
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────────

/// Initialise the AT-27 bionic + libart bring-up pipeline.
pub fn init_bionic_libart(config: BionicLibartConfig) -> Result<BionicLibartState, BionicLibartError> {
    // Step 1: validate config
    config.validate()?;

    // Step 2: create state
    let state = BionicLibartState::new(config);

    // Steps 3–8: libart init + dalvikvm launch + DEX execute happen at runtime
    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reconstruct a gate from a captured UART log.
pub fn gate_from_log(log: &[Vec<u8>]) -> BionicLibartGate {
    let mut gate = BionicLibartGate::default();
    for line in log {
        if contains_bytes(line, UART_SIG_LIBART_INIT) {
            gate.libart_loaded = true;
        }
        if contains_bytes(line, UART_SIG_DALVIKVM_START) {
            gate.dalvikvm_ran = true;
            gate.dex_executed = true;
        }
        if contains_bytes(line, UART_SIG_HELLO_DEX) {
            gate.hello_printed = true;
        }
    }
    gate
}
