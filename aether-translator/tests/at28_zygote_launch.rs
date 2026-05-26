//! AT-28: Zygote Launch — test suite.
//!
//! Gate: `boot_completed && zygote_forked && system_server_started && logcat_alive`
//! (equivalent to `getprop sys.boot_completed=1` on x86 hardware).

use aether_translator::runtime::zygote_launch::{
    gate_from_log, init_zygote_launch, ZygoteError, ZygoteLaunchConfig, ZygoteLaunchGate,
    ZygoteLaunchPhase, ZygoteLaunchState, BOOT_COMPLETED_PROP, BOOT_COMPLETED_TIMEOUT_S,
    UART_SIG_BOOT_COMPLETED, UART_SIG_LOGCAT_ALIVE, UART_SIG_SYSTEM_SERVER,
    UART_SIG_ZYGOTE_FORKED, UART_SIG_ZYGOTE_STARTED,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at28_boot_completed_prop_name() {
    assert_eq!(BOOT_COMPLETED_PROP, "sys.boot_completed");
}

#[test]
fn at28_boot_timeout_nonzero() {
    assert!(BOOT_COMPLETED_TIMEOUT_S > 0);
}

#[test]
fn at28_uart_sigs_non_empty() {
    assert!(!UART_SIG_ZYGOTE_STARTED.is_empty());
    assert!(!UART_SIG_ZYGOTE_FORKED.is_empty());
    assert!(!UART_SIG_SYSTEM_SERVER.is_empty());
    assert!(!UART_SIG_LOGCAT_ALIVE.is_empty());
    assert!(!UART_SIG_BOOT_COMPLETED.is_empty());
}

// ── Config ────────────────────────────────────────────────────────────────────

#[test]
fn at28_config_aether_defaults_valid() {
    let cfg = ZygoteLaunchConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
    assert!(cfg.enable_preload);
    assert_eq!(cfg.boot_timeout_s, BOOT_COMPLETED_TIMEOUT_S);
}

#[test]
fn at28_config_zero_timeout_invalid() {
    let cfg = ZygoteLaunchConfig {
        boot_timeout_s: 0,
        enable_preload: true,
    };
    assert_eq!(cfg.validate(), Err(ZygoteError::InvalidTimeout));
}

// ── Init pipeline ──────────────────────────────────────────────────────────────

#[test]
fn at28_init_pipeline_succeeds() {
    let state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    assert_eq!(state.phase, ZygoteLaunchPhase::NotStarted);
}

// ── State machine ──────────────────────────────────────────────────────────────

#[test]
fn at28_process_zygote_started_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    assert!(state.gate().zygote_forked);
    assert_eq!(state.phase, ZygoteLaunchPhase::ZygoteLaunched);
    assert_eq!(state.stats.fork_count, 1);
}

#[test]
fn at28_process_zygote_forked_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote forked SystemServer");
    assert!(state.gate().zygote_forked);
}

#[test]
fn at28_process_system_server_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] SystemServer started");
    assert!(state.gate().system_server_started);
    assert_eq!(state.phase, ZygoteLaunchPhase::SystemServerStarted);
}

#[test]
fn at28_process_logcat_alive_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] logcat alive");
    assert!(state.gate().logcat_alive);
    assert_eq!(state.phase, ZygoteLaunchPhase::LogcatAlive);
}

#[test]
fn at28_process_boot_completed_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] sys.boot_completed=1");
    assert!(state.gate().boot_completed);
    assert!(state.stats.completed_in_time);
    assert_eq!(state.phase, ZygoteLaunchPhase::BootCompleted);
}

#[test]
fn at28_gate_passes_after_full_sequence() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    state.process_line(b"[at28] SystemServer started");
    state.process_line(b"[at28] logcat alive");
    state.process_line(b"[at28] sys.boot_completed=1");
    assert!(state.gate().passes(), "gate must pass after full boot sequence");
    assert_eq!(state.phase, ZygoteLaunchPhase::GatePassed);
    assert!(state.is_gate_passed());
}

#[test]
fn at28_gate_fails_without_boot_completed() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    state.process_line(b"[at28] SystemServer started");
    state.process_line(b"[at28] logcat alive");
    assert!(!state.gate().passes());
}

#[test]
fn at28_gate_fails_without_zygote() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] SystemServer started");
    state.process_line(b"[at28] logcat alive");
    state.process_line(b"[at28] sys.boot_completed=1");
    assert!(!state.gate().passes());
}

#[test]
fn at28_gate_fails_without_system_server() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    state.process_line(b"[at28] logcat alive");
    state.process_line(b"[at28] sys.boot_completed=1");
    assert!(!state.gate().passes());
}

#[test]
fn at28_gate_fails_without_logcat() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    state.process_line(b"[at28] SystemServer started");
    state.process_line(b"[at28] sys.boot_completed=1");
    assert!(!state.gate().passes());
}

#[test]
fn at28_fork_count_increments_per_zygote_line() {
    let mut state = init_zygote_launch(ZygoteLaunchConfig::aether_defaults()).unwrap();
    state.process_line(b"[at28] Zygote started");
    state.process_line(b"[at28] Zygote forked SystemServer");
    assert_eq!(state.stats.fork_count, 2);
}

// ── gate_from_log ─────────────────────────────────────────────────────────────

#[test]
fn at28_gate_from_log_full() {
    let log: Vec<Vec<u8>> = vec![
        b"[at28] Zygote started".to_vec(),
        b"[at28] SystemServer started".to_vec(),
        b"[at28] logcat alive".to_vec(),
        b"[at28] sys.boot_completed=1".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(gate.passes());
}

#[test]
fn at28_gate_from_log_missing_logcat_fails() {
    let log: Vec<Vec<u8>> = vec![
        b"[at28] Zygote started".to_vec(),
        b"[at28] SystemServer started".to_vec(),
        b"[at28] sys.boot_completed=1".to_vec(),
    ];
    let gate = gate_from_log(&log);
    assert!(!gate.passes());
}

#[test]
fn at28_gate_from_log_empty_fails() {
    let gate = gate_from_log(&[]);
    assert!(!gate.passes());
}
