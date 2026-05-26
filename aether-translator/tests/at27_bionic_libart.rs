//! AT-27: Bionic + libart Bring-Up — test suite.
//!
//! Gate: `dalvikvm -classpath hello.dex Hello` prints "Hello" via translated
//! libart; `dalvikvm_ran && dex_executed && hello_printed`.

use aether_translator::runtime::bionic_libart::{
    gate_from_log, init_bionic_libart, BionicLibartConfig, BionicLibartError, BionicLibartGate,
    BionicLibartPhase, BionicLibartState, HELLO_DEX_CLASS, HELLO_DEX_CLASSPATH,
    HELLO_DEX_EXPECTED, UART_SIG_DALVIKVM_EXIT, UART_SIG_DALVIKVM_START, UART_SIG_HELLO_DEX,
    UART_SIG_LIBART_INIT,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at27_hello_dex_class_name() {
    assert_eq!(HELLO_DEX_CLASS, "Hello");
}

#[test]
fn at27_hello_dex_classpath() {
    assert_eq!(HELLO_DEX_CLASSPATH, "hello.dex");
}

#[test]
fn at27_hello_dex_expected_output() {
    assert_eq!(HELLO_DEX_EXPECTED, b"Hello");
}

#[test]
fn at27_uart_sigs_non_empty() {
    assert!(!UART_SIG_LIBART_INIT.is_empty());
    assert!(!UART_SIG_DALVIKVM_START.is_empty());
    assert!(!UART_SIG_HELLO_DEX.is_empty());
    assert!(!UART_SIG_DALVIKVM_EXIT.is_empty());
}

// ── Config ────────────────────────────────────────────────────────────────────

#[test]
fn at27_config_aether_defaults_valid() {
    let cfg = BionicLibartConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
}

#[test]
fn at27_config_unaligned_jit_base_invalid() {
    let cfg = BionicLibartConfig {
        jit_cache_base_pa: 0x1001, // not 4 KiB-aligned
        jit_cache_size: 16 * 1024 * 1024,
        allow_libart_jit: false,
    };
    assert_eq!(cfg.validate(), Err(BionicLibartError::UnalignedJitCache));
}

#[test]
fn at27_config_tiny_cache_invalid() {
    let cfg = BionicLibartConfig {
        jit_cache_base_pa: 0x2_0000_0000,
        jit_cache_size: 1024,
        allow_libart_jit: false,
    };
    assert_eq!(cfg.validate(), Err(BionicLibartError::JitCacheTooSmall));
}

#[test]
fn at27_default_config_interpret_only() {
    // Interpret-only at bring-up per AT-27 spec
    let cfg = BionicLibartConfig::aether_defaults();
    assert!(!cfg.allow_libart_jit, "AT-27 uses interpret-only at bring-up");
}

// ── Init pipeline ──────────────────────────────────────────────────────────────

#[test]
fn at27_init_pipeline_succeeds() {
    let state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    assert_eq!(state.phase, BionicLibartPhase::NotStarted);
}

// ── State machine ──────────────────────────────────────────────────────────────

#[test]
fn at27_process_libart_init_line() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"[at27] libart initialized");
    assert!(state.gate().libart_loaded);
    assert_eq!(state.phase, BionicLibartPhase::LibartLoaded);
}

#[test]
fn at27_process_dalvikvm_start_line() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"[at27] dalvikvm started");
    assert!(state.gate().dalvikvm_ran);
    assert!(state.gate().dex_executed);
    assert!(state.phase >= BionicLibartPhase::DalvikStarted);
}

#[test]
fn at27_process_hello_line() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"Hello");
    assert!(state.gate().hello_printed);
}

#[test]
fn at27_gate_passes_after_full_sequence() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"[at27] libart initialized");
    state.process_line(b"[at27] dalvikvm started");
    state.process_line(b"Hello");
    assert!(state.gate().passes(), "gate must pass after full dalvikvm sequence");
    assert_eq!(state.phase, BionicLibartPhase::GatePassed);
    assert!(state.is_gate_passed());
}

#[test]
fn at27_gate_fails_without_hello() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"[at27] libart initialized");
    state.process_line(b"[at27] dalvikvm started");
    assert!(!state.gate().passes());
}

#[test]
fn at27_gate_fails_without_dalvikvm() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.process_line(b"Hello");
    assert!(!state.gate().passes());
}

// ── Manual state helpers ───────────────────────────────────────────────────────

#[test]
fn at27_mark_libart_loaded() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.mark_libart_loaded();
    assert!(state.gate().libart_loaded);
    assert_eq!(state.phase, BionicLibartPhase::LibartLoaded);
}

#[test]
fn at27_mark_dalvikvm_started() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.mark_dalvikvm_started();
    assert!(state.gate().dalvikvm_ran);
    assert!(state.gate().dex_executed);
}

#[test]
fn at27_mark_hello_observed_triggers_gate() {
    let mut state = init_bionic_libart(BionicLibartConfig::aether_defaults()).unwrap();
    state.mark_dalvikvm_started();
    state.mark_hello_observed();
    assert!(state.gate().passes());
    assert!(state.is_gate_passed());
}

// ── gate_from_log ─────────────────────────────────────────────────────────────

#[test]
fn at27_gate_from_log_full() {
    let log: Vec<Vec<u8>> = vec![
        b"[at27] libart initialized".to_vec(),
        b"[at27] dalvikvm started".to_vec(),
        b"Hello".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(gate.passes());
}

#[test]
fn at27_gate_from_log_missing_hello() {
    let log: Vec<Vec<u8>> = vec![
        b"[at27] libart initialized".to_vec(),
        b"[at27] dalvikvm started".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(!gate.passes());
}
