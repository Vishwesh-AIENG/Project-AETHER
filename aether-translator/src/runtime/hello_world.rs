//! AT-26: Static Hello-World.
//!
//! An ARM64 `aarch64-linux-gnu-gcc -static hello.c` binary runs under the
//! AETHER translator on real Intel / AMD x86_64 hardware.  The translated
//! code executes a write(2) syscall that delivers "Hello, AETHER" to UART.
//!
//! **Gate:** `hello_printed && translation_completed && no_libc_symbols`

use alloc::vec::Vec;

// ── UART signatures ────────────────────────────────────────────────────────────

/// UART line emitted by the translated binary on successful execution.
pub const UART_SIG_HELLO_WORLD: &[u8] = b"Hello, AETHER";
/// UART line emitted when the first ARM64 block is translated.
pub const UART_SIG_BLOCK_TRANSLATED: &[u8] = b"[at26] block translated pc=";
/// UART line emitted when the dispatcher loop starts.
pub const UART_SIG_DISPATCHER_START: &[u8] = b"[at26] dispatcher started";
/// UART line emitted when the binary exits cleanly.
pub const UART_SIG_BINARY_EXIT: &[u8] = b"[at26] binary exit code=0";

// ── Constants ──────────────────────────────────────────────────────────────────

/// Expected string printed to UART by the translated hello-world binary.
pub const HELLO_WORLD_EXPECTED: &[u8] = b"Hello, AETHER";

/// Maximum blocks translated before the gate is considered stalled.
pub const HELLO_WORLD_BLOCK_LIMIT: u64 = 4096;

// ── Statistics ─────────────────────────────────────────────────────────────────

/// Statistics accumulated while translating the static hello-world binary.
#[derive(Debug, Clone, Default)]
pub struct HelloWorldStats {
    /// Total ARM64 blocks translated.
    pub blocks_translated: u64,
    /// Total x86_64 bytes emitted.
    pub bytes_emitted: u64,
    /// Whether "Hello, AETHER" was observed on UART.
    pub hello_observed: bool,
    /// Whether the translated binary exited with code 0.
    pub clean_exit: bool,
}

impl HelloWorldStats {
    /// Record one translated block.
    pub fn record_block(&mut self, bytes: u64) {
        self.blocks_translated += 1;
        self.bytes_emitted += bytes;
    }
}

// ── Config ─────────────────────────────────────────────────────────────────────

/// Configuration for the AT-26 static hello-world pipeline.
#[derive(Debug, Clone)]
pub struct HelloWorldConfig {
    /// Base guest PA of the JIT code cache.
    pub jit_cache_base_pa: u64,
    /// Size of the JIT cache in bytes.
    pub jit_cache_size: usize,
    /// Path of the ARM64 static binary (informational; not used in no_std).
    pub binary_name: &'static str,
}

impl HelloWorldConfig {
    pub fn aether_defaults() -> Self {
        Self {
            jit_cache_base_pa: 0x2_0000_0000,
            jit_cache_size: 16 * 1024 * 1024, // 16 MiB
            binary_name: "hello_aether",
        }
    }

    pub fn validate(&self) -> Result<(), HelloWorldError> {
        if self.jit_cache_base_pa == 0 {
            return Err(HelloWorldError::InvalidJitBase);
        }
        if self.jit_cache_size < 64 * 1024 {
            return Err(HelloWorldError::JitCacheTooSmall);
        }
        Ok(())
    }
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloWorldError {
    InvalidJitBase,
    JitCacheTooSmall,
    TranslationFailed,
    /// Forbidden libc symbol detected in the translated output.
    LibcSymbolDetected,
    /// "Hello, AETHER" was never observed on UART.
    HelloNotObserved,
}

// ── Gate ───────────────────────────────────────────────────────────────────────

/// Gate conditions for AT-26.
#[derive(Debug, Clone, Default)]
pub struct HelloWorldGate {
    /// "Hello, AETHER" appeared on UART from the translated code.
    pub hello_printed: bool,
    /// At least one block was translated (translation pipeline ran).
    pub translation_completed: bool,
    /// No forbidden libc/pthread symbols detected in the JIT output.
    pub no_libc_symbols: bool,
    /// Binary exited with code 0.
    pub clean_exit: bool,
}

impl HelloWorldGate {
    pub fn passes(&self) -> bool {
        self.hello_printed && self.translation_completed && self.no_libc_symbols
    }
}

// ── Phase ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HelloWorldPhase {
    NotStarted,
    BinaryLoaded,
    TranslationStarted,
    BlockTranslated,
    HelloPrinted,
    GatePassed,
}

// ── State ──────────────────────────────────────────────────────────────────────

/// Aggregate state for the AT-26 pipeline.
pub struct HelloWorldState {
    pub config: HelloWorldConfig,
    pub stats: HelloWorldStats,
    pub phase: HelloWorldPhase,
    pub gate: HelloWorldGate,
}

impl HelloWorldState {
    pub fn new(config: HelloWorldConfig) -> Self {
        Self {
            config,
            stats: HelloWorldStats::default(),
            phase: HelloWorldPhase::NotStarted,
            gate: HelloWorldGate {
                no_libc_symbols: true, // assumed clean until proven otherwise
                ..Default::default()
            },
        }
    }

    /// Feed one UART line to the state machine.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_DISPATCHER_START) {
            if self.phase < HelloWorldPhase::TranslationStarted {
                self.phase = HelloWorldPhase::TranslationStarted;
            }
        }
        if contains_bytes(line, UART_SIG_BLOCK_TRANSLATED) {
            self.stats.record_block(4);
            self.gate.translation_completed = true;
            if self.phase < HelloWorldPhase::BlockTranslated {
                self.phase = HelloWorldPhase::BlockTranslated;
            }
        }
        if contains_bytes(line, UART_SIG_HELLO_WORLD) {
            self.stats.hello_observed = true;
            self.gate.hello_printed = true;
            if self.phase < HelloWorldPhase::HelloPrinted {
                self.phase = HelloWorldPhase::HelloPrinted;
            }
        }
        if contains_bytes(line, UART_SIG_BINARY_EXIT) {
            self.stats.clean_exit = true;
            self.gate.clean_exit = true;
        }
        if self.gate.passes() {
            self.phase = HelloWorldPhase::GatePassed;
        }
    }

    /// Mark the binary as loaded (ELF parsed, entry point known).
    pub fn mark_binary_loaded(&mut self) {
        if self.phase < HelloWorldPhase::BinaryLoaded {
            self.phase = HelloWorldPhase::BinaryLoaded;
        }
    }

    /// Report that a block was translated with `bytes_emitted` bytes of x86.
    pub fn record_block(&mut self, bytes_emitted: u64) {
        self.stats.record_block(bytes_emitted);
        self.gate.translation_completed = true;
        if self.phase < HelloWorldPhase::BlockTranslated {
            self.phase = HelloWorldPhase::BlockTranslated;
        }
    }

    /// Report "Hello, AETHER" observed on UART.
    pub fn mark_hello_observed(&mut self) {
        self.stats.hello_observed = true;
        self.gate.hello_printed = true;
        if self.phase < HelloWorldPhase::HelloPrinted {
            self.phase = HelloWorldPhase::HelloPrinted;
        }
        if self.gate.passes() {
            self.phase = HelloWorldPhase::GatePassed;
        }
    }

    /// Signal that a forbidden symbol was detected — gate fails immediately.
    pub fn signal_libc_symbol(&mut self) {
        self.gate.no_libc_symbols = false;
    }

    pub fn gate(&self) -> &HelloWorldGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == HelloWorldPhase::GatePassed
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────────

/// Initialise the AT-26 static hello-world pipeline (8-step skeleton).
///
/// Steps 1–4 run synchronously; steps 5–8 complete during dispatch-loop
/// execution on real x86 hardware.
pub fn init_hello_world(config: HelloWorldConfig) -> Result<HelloWorldState, HelloWorldError> {
    // Step 1: validate config
    config.validate()?;

    // Step 2: create state
    let mut state = HelloWorldState::new(config);

    // Step 3: verify JIT cache region is 4 KiB-aligned
    if state.config.jit_cache_base_pa % 4096 != 0 {
        return Err(HelloWorldError::InvalidJitBase);
    }

    // Step 4: mark binary loaded (ELF parse happens here in production)
    state.mark_binary_loaded();

    // Steps 5–8: translation + execution happen in the dispatcher loop
    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Audit helper ──────────────────────────────────────────────────────────────

/// UART line samples that should be collected from the console after running
/// the static hello-world binary under the translator.
pub const EXPECTED_UART_LINES: &[&[u8]] = &[
    b"[at26] dispatcher started",
    b"[at26] block translated pc=0x",
    b"Hello, AETHER",
    b"[at26] binary exit code=0",
];

/// Verify that all expected UART signature lines appear in `log`.
pub fn gate_from_log(log: &[Vec<u8>]) -> HelloWorldGate {
    let mut gate = HelloWorldGate {
        no_libc_symbols: true,
        ..Default::default()
    };
    for line in log {
        if contains_bytes(line, UART_SIG_HELLO_WORLD) {
            gate.hello_printed = true;
        }
        if contains_bytes(line, UART_SIG_BLOCK_TRANSLATED) {
            gate.translation_completed = true;
        }
        if contains_bytes(line, b"LIBC_SYMBOL") {
            gate.no_libc_symbols = false;
        }
        if contains_bytes(line, UART_SIG_BINARY_EXIT) {
            gate.clean_exit = true;
        }
    }
    gate
}
