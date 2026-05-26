//! AT-30: Performance Benchmarks.
//!
//! Geekbench / PCMark Android on the AETHER translator (x86 hardware) vs.
//! native ARM (Snapdragon X) and native x86 (Android-x86 reference).
//!
//! **Gate:**
//! - Integer geomean ≥ 70 % of native ARM
//! - SIMD geomean ≥ 80 % of native ARM
//! - JS (V8) benchmark ≥ 60 % of native ARM

// ── UART signatures ────────────────────────────────────────────────────────────

/// Emitted when the benchmark harness starts.
pub const UART_SIG_BENCH_START: &[u8] = b"[at30] benchmark started";
/// Emitted with integer benchmark score (geomean).
pub const UART_SIG_INT_SCORE: &[u8] = b"[at30] int_score=";
/// Emitted with SIMD benchmark score (geomean).
pub const UART_SIG_SIMD_SCORE: &[u8] = b"[at30] simd_score=";
/// Emitted with JS (V8) benchmark score.
pub const UART_SIG_JS_SCORE: &[u8] = b"[at30] js_score=";
/// Emitted when all benchmark suites complete.
pub const UART_SIG_BENCH_DONE: &[u8] = b"[at30] benchmark done";

// ── Gate thresholds (from AT-30 spec) ─────────────────────────────────────────

/// Minimum translated/native ratio for integer geomean.
pub const PERF_INT_THRESHOLD: f32 = 0.70;
/// Minimum translated/native ratio for SIMD geomean.
pub const PERF_SIMD_THRESHOLD: f32 = 0.80;
/// Minimum translated/native ratio for JS (V8) benchmark.
pub const PERF_JS_THRESHOLD: f32 = 0.60;

// ── Score record ──────────────────────────────────────────────────────────────

/// A single benchmark result: translated score vs. native ARM baseline.
#[derive(Debug, Clone, Copy, Default)]
pub struct BenchScore {
    /// Score achieved by the AETHER translator on x86 hardware.
    pub translated: f32,
    /// Baseline score on native ARM (Snapdragon X).
    pub native_arm: f32,
}

impl BenchScore {
    pub fn new(translated: f32, native_arm: f32) -> Self {
        Self { translated, native_arm }
    }

    /// Ratio translated / native_arm.  Returns 0.0 if native_arm is zero.
    pub fn ratio(&self) -> f32 {
        if self.native_arm == 0.0 {
            return 0.0;
        }
        self.translated / self.native_arm
    }

    /// Whether this category meets `threshold`.
    pub fn meets(&self, threshold: f32) -> bool {
        self.ratio() >= threshold
    }
}

// ── Statistics ─────────────────────────────────────────────────────────────────

/// Statistics for the AT-30 benchmark run.
#[derive(Debug, Clone, Default)]
pub struct PerfBenchStats {
    /// Integer workload geomean score (translated vs. native).
    pub int_score: BenchScore,
    /// SIMD workload geomean score.
    pub simd_score: BenchScore,
    /// JS (V8) benchmark score.
    pub js_score: BenchScore,
    /// Number of individual benchmark sub-tests completed.
    pub subtests_completed: u32,
}

impl PerfBenchStats {
    /// Overall geomean ratio across all three categories.
    ///
    /// Requires `f32::powf`, which is std-only. The AT-30 host-side test
    /// harness pulls this in via the default `std` feature; the no_std
    /// hypervisor link path never calls it (the gate is decided from the
    /// per-category ratios, not the geomean).
    #[cfg(feature = "std")]
    pub fn overall_geomean_ratio(&self) -> f32 {
        let i = self.int_score.ratio();
        let s = self.simd_score.ratio();
        let j = self.js_score.ratio();
        if i <= 0.0 || s <= 0.0 || j <= 0.0 {
            return 0.0;
        }
        (i * s * j).powf(1.0 / 3.0)
    }
}

// ── Config ─────────────────────────────────────────────────────────────────────

/// Configuration for the AT-30 performance benchmark pipeline.
#[derive(Debug, Clone)]
pub struct PerfBenchConfig {
    /// Minimum integer ratio for the gate.
    pub int_threshold: f32,
    /// Minimum SIMD ratio for the gate.
    pub simd_threshold: f32,
    /// Minimum JS ratio for the gate.
    pub js_threshold: f32,
    /// Native ARM baseline scores (provided by the operator from Snapdragon X run).
    pub native_arm_int: f32,
    pub native_arm_simd: f32,
    pub native_arm_js: f32,
}

impl PerfBenchConfig {
    pub fn aether_defaults() -> Self {
        Self {
            int_threshold: PERF_INT_THRESHOLD,
            simd_threshold: PERF_SIMD_THRESHOLD,
            js_threshold: PERF_JS_THRESHOLD,
            // Placeholder baselines — overridden with real Snapdragon X scores before running.
            native_arm_int: 1.0,
            native_arm_simd: 1.0,
            native_arm_js: 1.0,
        }
    }

    pub fn validate(&self) -> Result<(), PerfBenchError> {
        if self.int_threshold <= 0.0 || self.int_threshold > 1.0 {
            return Err(PerfBenchError::InvalidThreshold);
        }
        if self.simd_threshold <= 0.0 || self.simd_threshold > 1.0 {
            return Err(PerfBenchError::InvalidThreshold);
        }
        if self.js_threshold <= 0.0 || self.js_threshold > 1.0 {
            return Err(PerfBenchError::InvalidThreshold);
        }
        if self.native_arm_int <= 0.0 || self.native_arm_simd <= 0.0 || self.native_arm_js <= 0.0 {
            return Err(PerfBenchError::InvalidBaseline);
        }
        Ok(())
    }
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfBenchError {
    InvalidThreshold,
    InvalidBaseline,
    BenchmarkFailed,
    IntGateFailed,
    SimdGateFailed,
    JsGateFailed,
}

// ── Gate ───────────────────────────────────────────────────────────────────────

/// Gate conditions for AT-30.
#[derive(Debug, Clone, Default)]
pub struct PerfBenchGate {
    /// Integer geomean ≥ 70 % of native ARM.
    pub int_gate: bool,
    /// SIMD geomean ≥ 80 % of native ARM.
    pub simd_gate: bool,
    /// JS (V8) benchmark ≥ 60 % of native ARM.
    pub js_gate: bool,
    /// All three benchmark suites completed.
    pub all_suites_done: bool,
}

impl PerfBenchGate {
    pub fn passes(&self) -> bool {
        self.int_gate && self.simd_gate && self.js_gate && self.all_suites_done
    }
}

// ── Phase ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PerfBenchPhase {
    NotStarted,
    BenchmarkStarted,
    IntResultsIn,
    SimdResultsIn,
    JsResultsIn,
    GatePassed,
}

// ── State ──────────────────────────────────────────────────────────────────────

/// Aggregate state for the AT-30 benchmark pipeline.
pub struct PerfBenchState {
    pub config: PerfBenchConfig,
    pub stats: PerfBenchStats,
    pub phase: PerfBenchPhase,
    pub gate: PerfBenchGate,
}

impl PerfBenchState {
    pub fn new(config: PerfBenchConfig) -> Self {
        Self {
            config,
            stats: PerfBenchStats::default(),
            phase: PerfBenchPhase::NotStarted,
            gate: PerfBenchGate::default(),
        }
    }

    /// Feed one UART line to the state machine.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_BENCH_START) {
            if self.phase < PerfBenchPhase::BenchmarkStarted {
                self.phase = PerfBenchPhase::BenchmarkStarted;
            }
        }
        if contains_bytes(line, UART_SIG_INT_SCORE) {
            if let Some(score) = parse_f32_after(line, UART_SIG_INT_SCORE) {
                self.record_int_score(score);
            }
        }
        if contains_bytes(line, UART_SIG_SIMD_SCORE) {
            if let Some(score) = parse_f32_after(line, UART_SIG_SIMD_SCORE) {
                self.record_simd_score(score);
            }
        }
        if contains_bytes(line, UART_SIG_JS_SCORE) {
            if let Some(score) = parse_f32_after(line, UART_SIG_JS_SCORE) {
                self.record_js_score(score);
            }
        }
        if contains_bytes(line, UART_SIG_BENCH_DONE) {
            self.gate.all_suites_done = true;
            if self.gate.passes() {
                self.phase = PerfBenchPhase::GatePassed;
            }
        }
    }

    /// Record an integer benchmark score (translated hardware result).
    pub fn record_int_score(&mut self, translated: f32) {
        self.stats.int_score = BenchScore::new(translated, self.config.native_arm_int);
        self.gate.int_gate = self.stats.int_score.meets(self.config.int_threshold);
        self.stats.subtests_completed += 1;
        if self.phase < PerfBenchPhase::IntResultsIn {
            self.phase = PerfBenchPhase::IntResultsIn;
        }
    }

    /// Record a SIMD benchmark score.
    pub fn record_simd_score(&mut self, translated: f32) {
        self.stats.simd_score = BenchScore::new(translated, self.config.native_arm_simd);
        self.gate.simd_gate = self.stats.simd_score.meets(self.config.simd_threshold);
        self.stats.subtests_completed += 1;
        if self.phase < PerfBenchPhase::SimdResultsIn {
            self.phase = PerfBenchPhase::SimdResultsIn;
        }
    }

    /// Record a JS (V8) benchmark score.
    pub fn record_js_score(&mut self, translated: f32) {
        self.stats.js_score = BenchScore::new(translated, self.config.native_arm_js);
        self.gate.js_gate = self.stats.js_score.meets(self.config.js_threshold);
        self.stats.subtests_completed += 1;
        if self.phase < PerfBenchPhase::JsResultsIn {
            self.phase = PerfBenchPhase::JsResultsIn;
        }
        if self.gate.passes() {
            self.phase = PerfBenchPhase::GatePassed;
        }
    }

    /// Manually mark all suites as done (used in test harness).
    pub fn mark_suites_done(&mut self) {
        self.gate.all_suites_done = true;
        if self.gate.passes() {
            self.phase = PerfBenchPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &PerfBenchGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.phase == PerfBenchPhase::GatePassed
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────────

/// Initialise the AT-30 performance benchmark pipeline.
pub fn init_perf_bench(config: PerfBenchConfig) -> Result<PerfBenchState, PerfBenchError> {
    config.validate()?;
    let state = PerfBenchState::new(config);
    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Parse an ASCII decimal float immediately after `prefix` in `line`.
/// Returns `None` if the prefix is absent or the suffix isn't a valid float.
fn parse_f32_after(line: &[u8], prefix: &[u8]) -> Option<f32> {
    let pos = line.windows(prefix.len()).position(|w| w == prefix)?;
    let tail = &line[pos + prefix.len()..];
    // Collect ASCII digits and '.'
    let end = tail.iter().position(|&b| !b.is_ascii_digit() && b != b'.').unwrap_or(tail.len());
    let s = core::str::from_utf8(&tail[..end]).ok()?;
    s.parse::<f32>().ok()
}
