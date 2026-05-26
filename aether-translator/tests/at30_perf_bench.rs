//! AT-30: Performance Benchmarks — test suite.
//!
//! Gate:
//! - Integer geomean ≥ 70 % of native ARM (Snapdragon X)
//! - SIMD geomean ≥ 80 % of native ARM
//! - JS (V8) benchmark ≥ 60 % of native ARM

use aether_translator::runtime::perf_bench::{
    init_perf_bench, BenchScore, PerfBenchConfig, PerfBenchError, PerfBenchPhase, PerfBenchState,
    PERF_INT_THRESHOLD, PERF_JS_THRESHOLD, PERF_SIMD_THRESHOLD, UART_SIG_BENCH_DONE,
    UART_SIG_BENCH_START, UART_SIG_INT_SCORE, UART_SIG_JS_SCORE, UART_SIG_SIMD_SCORE,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at30_int_threshold_is_70_pct() {
    assert!((PERF_INT_THRESHOLD - 0.70).abs() < f32::EPSILON);
}

#[test]
fn at30_simd_threshold_is_80_pct() {
    assert!((PERF_SIMD_THRESHOLD - 0.80).abs() < f32::EPSILON);
}

#[test]
fn at30_js_threshold_is_60_pct() {
    assert!((PERF_JS_THRESHOLD - 0.60).abs() < f32::EPSILON);
}

#[test]
fn at30_uart_sigs_non_empty() {
    assert!(!UART_SIG_BENCH_START.is_empty());
    assert!(!UART_SIG_INT_SCORE.is_empty());
    assert!(!UART_SIG_SIMD_SCORE.is_empty());
    assert!(!UART_SIG_JS_SCORE.is_empty());
    assert!(!UART_SIG_BENCH_DONE.is_empty());
}

// ── BenchScore ────────────────────────────────────────────────────────────────

#[test]
fn at30_bench_score_ratio_exact() {
    let s = BenchScore::new(700.0, 1000.0);
    assert!((s.ratio() - 0.70).abs() < 1e-5);
}

#[test]
fn at30_bench_score_meets_threshold() {
    let s = BenchScore::new(800.0, 1000.0); // 80 % → meets 70 % threshold
    assert!(s.meets(PERF_INT_THRESHOLD));
}

#[test]
fn at30_bench_score_fails_threshold() {
    let s = BenchScore::new(690.0, 1000.0); // 69 % < 70 %
    assert!(!s.meets(PERF_INT_THRESHOLD));
}

#[test]
fn at30_bench_score_zero_native_returns_zero() {
    let s = BenchScore::new(500.0, 0.0);
    assert_eq!(s.ratio(), 0.0);
    assert!(!s.meets(PERF_INT_THRESHOLD));
}

// ── Config ────────────────────────────────────────────────────────────────────

#[test]
fn at30_config_aether_defaults_valid() {
    let cfg = PerfBenchConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
}

#[test]
fn at30_config_zero_int_threshold_invalid() {
    let cfg = PerfBenchConfig {
        int_threshold: 0.0,
        simd_threshold: 0.80,
        js_threshold: 0.60,
        native_arm_int: 1.0,
        native_arm_simd: 1.0,
        native_arm_js: 1.0,
    };
    assert_eq!(cfg.validate(), Err(PerfBenchError::InvalidThreshold));
}

#[test]
fn at30_config_threshold_above_one_invalid() {
    let cfg = PerfBenchConfig {
        int_threshold: 1.1,
        simd_threshold: 0.80,
        js_threshold: 0.60,
        native_arm_int: 1.0,
        native_arm_simd: 1.0,
        native_arm_js: 1.0,
    };
    assert_eq!(cfg.validate(), Err(PerfBenchError::InvalidThreshold));
}

#[test]
fn at30_config_zero_baseline_invalid() {
    let cfg = PerfBenchConfig {
        int_threshold: 0.70,
        simd_threshold: 0.80,
        js_threshold: 0.60,
        native_arm_int: 0.0,
        native_arm_simd: 1.0,
        native_arm_js: 1.0,
    };
    assert_eq!(cfg.validate(), Err(PerfBenchError::InvalidBaseline));
}

// ── Init pipeline ──────────────────────────────────────────────────────────────

#[test]
fn at30_init_pipeline_succeeds() {
    let state = init_perf_bench(PerfBenchConfig::aether_defaults()).unwrap();
    assert_eq!(state.phase, PerfBenchPhase::NotStarted);
}

// ── record_*_score ────────────────────────────────────────────────────────────

#[test]
fn at30_record_int_score_above_threshold() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(750.0); // 75 % ≥ 70 %
    assert!(state.gate().int_gate);
    assert_eq!(state.phase, PerfBenchPhase::IntResultsIn);
}

#[test]
fn at30_record_int_score_below_threshold_fails_gate() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(650.0); // 65 % < 70 %
    assert!(!state.gate().int_gate);
}

#[test]
fn at30_record_simd_score_above_threshold() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_simd_score(850.0); // 85 % ≥ 80 %
    assert!(state.gate().simd_gate);
    assert_eq!(state.phase, PerfBenchPhase::SimdResultsIn);
}

#[test]
fn at30_record_js_score_above_threshold() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_js_score(650.0); // 65 % ≥ 60 %
    assert!(state.gate().js_gate);
    assert_eq!(state.phase, PerfBenchPhase::JsResultsIn);
}

#[test]
fn at30_gate_passes_after_all_three_suites() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(750.0);   // 75 %
    state.record_simd_score(850.0);  // 85 %
    state.record_js_score(650.0);    // 65 %
    state.mark_suites_done();
    assert!(state.gate().passes(), "all three categories above threshold → gate passes");
    assert_eq!(state.phase, PerfBenchPhase::GatePassed);
    assert!(state.is_gate_passed());
}

#[test]
fn at30_gate_fails_if_int_below_threshold() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(600.0);   // 60 % < 70 % ← fails
    state.record_simd_score(850.0);
    state.record_js_score(650.0);
    state.mark_suites_done();
    assert!(!state.gate().passes());
}

#[test]
fn at30_gate_fails_without_suites_done() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(750.0);
    state.record_simd_score(850.0);
    state.record_js_score(650.0);
    // did NOT call mark_suites_done()
    assert!(!state.gate().passes());
}

// ── process_line ──────────────────────────────────────────────────────────────

#[test]
fn at30_process_bench_start_line() {
    let mut state = init_perf_bench(PerfBenchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at30] benchmark started");
    assert_eq!(state.phase, PerfBenchPhase::BenchmarkStarted);
}

#[test]
fn at30_process_full_uart_sequence() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.process_line(b"[at30] benchmark started");
    state.process_line(b"[at30] int_score=750.0");
    state.process_line(b"[at30] simd_score=850.0");
    state.process_line(b"[at30] js_score=650.0");
    state.process_line(b"[at30] benchmark done");
    assert!(state.gate().passes(), "UART sequence must drive gate to passed");
    assert_eq!(state.phase, PerfBenchPhase::GatePassed);
}

// ── overall_geomean_ratio ──────────────────────────────────────────────────────

#[test]
fn at30_overall_geomean_all_at_threshold() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(700.0);
    state.record_simd_score(800.0);
    state.record_js_score(600.0);
    let gm = state.stats.overall_geomean_ratio();
    // geomean(0.7, 0.8, 0.6) ≈ 0.6974...
    assert!(gm > 0.69 && gm < 0.71, "geomean should be ~0.697, got {gm}");
}

#[test]
fn at30_overall_geomean_zero_when_no_scores() {
    let state = init_perf_bench(PerfBenchConfig::aether_defaults()).unwrap();
    assert_eq!(state.stats.overall_geomean_ratio(), 0.0);
}

#[test]
fn at30_subtests_completed_counter() {
    let cfg = PerfBenchConfig {
        native_arm_int: 1000.0,
        native_arm_simd: 1000.0,
        native_arm_js: 1000.0,
        ..PerfBenchConfig::aether_defaults()
    };
    let mut state = init_perf_bench(cfg).unwrap();
    state.record_int_score(750.0);
    state.record_simd_score(850.0);
    state.record_js_score(650.0);
    assert_eq!(state.stats.subtests_completed, 3);
}
