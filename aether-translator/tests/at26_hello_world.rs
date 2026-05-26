//! AT-26: Static Hello-World — test suite.
//!
//! Gate: static ARM64 binary translated and executed on x86; "Hello, AETHER"
//! observed on UART; no forbidden libc symbols; translator ran at least one block.

use aether_translator::runtime::hello_world::{
    gate_from_log, init_hello_world, HelloWorldConfig, HelloWorldError, HelloWorldGate,
    HelloWorldPhase, HelloWorldState, EXPECTED_UART_LINES, HELLO_WORLD_BLOCK_LIMIT,
    HELLO_WORLD_EXPECTED, UART_SIG_BINARY_EXIT, UART_SIG_BLOCK_TRANSLATED,
    UART_SIG_DISPATCHER_START, UART_SIG_HELLO_WORLD,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at26_hello_world_expected_string() {
    assert_eq!(
        HELLO_WORLD_EXPECTED,
        b"Hello, AETHER",
        "expected UART string must match AT-26 spec"
    );
}

#[test]
fn at26_block_limit_nonzero() {
    assert!(HELLO_WORLD_BLOCK_LIMIT > 0);
}

#[test]
fn at26_uart_sigs_non_empty() {
    assert!(!UART_SIG_HELLO_WORLD.is_empty());
    assert!(!UART_SIG_BLOCK_TRANSLATED.is_empty());
    assert!(!UART_SIG_DISPATCHER_START.is_empty());
    assert!(!UART_SIG_BINARY_EXIT.is_empty());
}

#[test]
fn at26_expected_uart_lines_four_entries() {
    assert_eq!(EXPECTED_UART_LINES.len(), 4, "AT-26 expects 4 UART signature lines");
}

// ── Config ────────────────────────────────────────────────────────────────────

#[test]
fn at26_config_aether_defaults_valid() {
    let cfg = HelloWorldConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
}

#[test]
fn at26_config_zero_jit_base_invalid() {
    let cfg = HelloWorldConfig {
        jit_cache_base_pa: 0,
        jit_cache_size: 16 * 1024 * 1024,
        binary_name: "hello",
    };
    assert_eq!(cfg.validate(), Err(HelloWorldError::InvalidJitBase));
}

#[test]
fn at26_config_tiny_cache_invalid() {
    let cfg = HelloWorldConfig {
        jit_cache_base_pa: 0x2_0000_0000,
        jit_cache_size: 1024, // too small
        binary_name: "hello",
    };
    assert_eq!(cfg.validate(), Err(HelloWorldError::JitCacheTooSmall));
}

// ── Init pipeline ──────────────────────────────────────────────────────────────

#[test]
fn at26_init_pipeline_succeeds() {
    let state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    assert!(state.phase >= HelloWorldPhase::BinaryLoaded);
}

#[test]
fn at26_init_starts_with_clean_no_libc_flag() {
    let state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    assert!(state.gate().no_libc_symbols, "gate starts optimistically clean");
}

// ── State machine ──────────────────────────────────────────────────────────────

#[test]
fn at26_process_dispatcher_start_line() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.process_line(b"[at26] dispatcher started");
    assert!(state.phase >= HelloWorldPhase::TranslationStarted);
}

#[test]
fn at26_process_block_translated_line() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.process_line(b"[at26] block translated pc=0x401000");
    assert!(state.gate().translation_completed);
    assert!(state.phase >= HelloWorldPhase::BlockTranslated);
}

#[test]
fn at26_process_hello_world_line() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.process_line(b"Hello, AETHER");
    assert!(state.gate().hello_printed);
    assert!(state.phase >= HelloWorldPhase::HelloPrinted);
}

#[test]
fn at26_gate_passes_after_full_sequence() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.process_line(b"[at26] dispatcher started");
    state.process_line(b"[at26] block translated pc=0x401000");
    state.process_line(b"Hello, AETHER");
    assert!(state.gate().passes(), "gate must pass after full translation sequence");
    assert_eq!(state.phase, HelloWorldPhase::GatePassed);
}

#[test]
fn at26_gate_fails_without_hello() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    // block translated but hello never printed
    state.process_line(b"[at26] block translated pc=0x401000");
    assert!(!state.gate().passes());
}

#[test]
fn at26_gate_fails_with_libc_symbol() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.process_line(b"[at26] block translated pc=0x401000");
    state.process_line(b"Hello, AETHER");
    state.signal_libc_symbol();
    assert!(!state.gate().passes(), "libc symbol must fail the gate");
}

// ── record_block helper ────────────────────────────────────────────────────────

#[test]
fn at26_record_block_increments_counter() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.record_block(64);
    state.record_block(128);
    assert_eq!(state.stats.blocks_translated, 2);
    assert_eq!(state.stats.bytes_emitted, 192);
}

#[test]
fn at26_mark_hello_observed_advances_phase() {
    let mut state = init_hello_world(HelloWorldConfig::aether_defaults()).unwrap();
    state.record_block(32);
    state.mark_hello_observed();
    assert!(state.gate().hello_printed);
    assert_eq!(state.phase, HelloWorldPhase::GatePassed);
    assert!(state.is_gate_passed());
}

// ── gate_from_log ─────────────────────────────────────────────────────────────

#[test]
fn at26_gate_from_log_full_sequence() {
    let log: Vec<Vec<u8>> = vec![
        b"[at26] dispatcher started".to_vec(),
        b"[at26] block translated pc=0x401000".to_vec(),
        b"Hello, AETHER".to_vec(),
        b"[at26] binary exit code=0".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(gate.passes());
}

#[test]
fn at26_gate_from_log_no_hello_fails() {
    let log: Vec<Vec<u8>> = vec![
        b"[at26] dispatcher started".to_vec(),
        b"[at26] block translated pc=0x401000".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(!gate.passes());
}

#[test]
fn at26_gate_from_log_libc_symbol_fails() {
    let log: Vec<Vec<u8>> = vec![
        b"[at26] block translated pc=0x401000".to_vec(),
        b"Hello, AETHER".to_vec(),
        b"LIBC_SYMBOL malloc detected".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(!gate.no_libc_symbols);
    assert!(!gate.passes());
}
