//! AT-29: App Compatibility (x86 tier) — test suite.
//!
//! Gate: ≥ 950 / 1000 apps pass (attestation-only excluded from denominator),
//! same threshold as the ARM-tier ch49 gate.

use aether_translator::runtime::app_compat_x86::{
    init_app_compat_x86, AppCompatBug, AppCompatBugKind, AppCompatX86Config, AppCompatX86Error,
    AppCompatX86Phase, AppCompatX86State, COMPAT_MIN_PASS, COMPAT_TOTAL_APPS,
    UART_SIG_APP_FAIL, UART_SIG_APP_PASS, UART_SIG_ATTESTATION_ONLY, UART_SIG_HARNESS_READY,
    UART_SIG_SUITE_DONE,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at29_total_apps_is_1000() {
    assert_eq!(COMPAT_TOTAL_APPS, 1000, "suite size must be 1000 per AT-29 spec");
}

#[test]
fn at29_min_pass_is_950() {
    assert_eq!(COMPAT_MIN_PASS, 950, "minimum pass count must be 950 per AT-29 spec");
}

#[test]
fn at29_uart_sigs_non_empty() {
    assert!(!UART_SIG_HARNESS_READY.is_empty());
    assert!(!UART_SIG_APP_PASS.is_empty());
    assert!(!UART_SIG_APP_FAIL.is_empty());
    assert!(!UART_SIG_SUITE_DONE.is_empty());
    assert!(!UART_SIG_ATTESTATION_ONLY.is_empty());
}

// ── Config ────────────────────────────────────────────────────────────────────

#[test]
fn at29_config_aether_defaults_valid() {
    let cfg = AppCompatX86Config::aether_defaults();
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.min_pass, COMPAT_MIN_PASS);
    assert_eq!(cfg.total_apps, COMPAT_TOTAL_APPS);
}

#[test]
fn at29_config_min_pass_exceeds_total_invalid() {
    let cfg = AppCompatX86Config {
        min_pass: 1001,
        total_apps: 1000,
        abort_on_critical: false,
    };
    assert_eq!(cfg.validate(), Err(AppCompatX86Error::InvalidConfig));
}

#[test]
fn at29_config_zero_total_invalid() {
    let cfg = AppCompatX86Config {
        min_pass: 0,
        total_apps: 0,
        abort_on_critical: false,
    };
    assert_eq!(cfg.validate(), Err(AppCompatX86Error::InvalidConfig));
}

// ── Init pipeline ──────────────────────────────────────────────────────────────

#[test]
fn at29_init_pipeline_succeeds() {
    let state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    assert_eq!(state.phase, AppCompatX86Phase::NotStarted);
}

#[test]
fn at29_init_starts_with_no_unresolved_bugs() {
    let state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    assert!(state.gate().no_unresolved_bugs);
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[test]
fn at29_stats_pass_rate_950_of_1000() {
    let cfg = AppCompatX86Config::aether_defaults();
    let mut state = init_app_compat_x86(cfg).unwrap();
    // Simulate 950 passes, 50 failures
    for _ in 0..950 {
        state.process_line(b"[at29] app pass");
    }
    for _ in 0..50 {
        state.process_line(b"[at29] app fail");
    }
    assert!(state.stats.gate_passes(), "950 passes must satisfy the gate");
    assert!((state.stats.pass_rate() - 0.95).abs() < 0.001);
}

#[test]
fn at29_stats_pass_rate_949_fails() {
    let cfg = AppCompatX86Config::aether_defaults();
    let mut state = init_app_compat_x86(cfg).unwrap();
    for _ in 0..949 {
        state.process_line(b"[at29] app pass");
    }
    assert!(!state.stats.gate_passes(), "949 passes must not satisfy the gate");
}

#[test]
fn at29_attestation_only_excluded_from_denominator() {
    let cfg = AppCompatX86Config::aether_defaults();
    let mut state = init_app_compat_x86(cfg).unwrap();
    // 20 attestation-only exclusions → denominator = 980
    for _ in 0..20 {
        state.process_line(b"[at29] attestation-only");
    }
    assert_eq!(state.stats.denominator(), 980);
}

#[test]
fn at29_pass_rate_zero_with_no_tests() {
    let cfg = AppCompatX86Config::aether_defaults();
    let state = init_app_compat_x86(cfg).unwrap();
    assert!(!state.stats.gate_passes());
}

// ── State machine ──────────────────────────────────────────────────────────────

#[test]
fn at29_process_harness_ready_line() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    state.process_line(b"[at29] compat harness ready");
    assert!(state.gate().harness_ready);
    assert_eq!(state.phase, AppCompatX86Phase::HarnessReady);
}

#[test]
fn at29_process_app_pass_advances_phase() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    state.process_line(b"[at29] compat harness ready");
    state.process_line(b"[at29] app pass");
    assert_eq!(state.stats.passed, 1);
    assert!(state.phase >= AppCompatX86Phase::SmokeTestsRunning);
}

#[test]
fn at29_gate_passes_after_full_run() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    state.process_line(b"[at29] compat harness ready");
    for _ in 0..950 {
        state.process_line(b"[at29] app pass");
    }
    for _ in 0..50 {
        state.process_line(b"[at29] app fail");
    }
    state.process_line(b"[at29] suite done");
    assert!(state.gate().passes(), "gate must pass after 950/1000 apps pass");
    assert_eq!(state.phase, AppCompatX86Phase::GatePassed);
    assert!(state.is_gate_passed());
}

#[test]
fn at29_gate_fails_with_unresolved_bug() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    state.process_line(b"[at29] compat harness ready");
    for _ in 0..950 {
        state.process_line(b"[at29] app pass");
    }
    state.record_bug(AppCompatBug {
        app_name: "com.example.app",
        kind: AppCompatBugKind::TranslationFailed,
        resolved: false,
    });
    state.process_line(b"[at29] suite done");
    assert!(!state.gate().no_unresolved_bugs);
    assert!(!state.gate().passes());
}

#[test]
fn at29_gate_passes_after_resolving_bugs() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    state.process_line(b"[at29] compat harness ready");
    for _ in 0..950 {
        state.process_line(b"[at29] app pass");
    }
    state.record_bug(AppCompatBug {
        app_name: "com.example.app",
        kind: AppCompatBugKind::TranslationFailed,
        resolved: false,
    });
    state.resolve_all_bugs();
    state.process_line(b"[at29] suite done");
    assert!(state.gate().no_unresolved_bugs);
    assert!(state.gate().passes());
}

// ── Bug record ────────────────────────────────────────────────────────────────

#[test]
fn at29_attestation_only_bug_is_not_unresolved() {
    let bug = AppCompatBug {
        app_name: "com.example.attest",
        kind: AppCompatBugKind::AttestationRequired,
        resolved: false,
    };
    assert!(bug.is_attestation_only());
}

#[test]
fn at29_translation_failed_bug_is_not_attestation_only() {
    let bug = AppCompatBug {
        app_name: "com.example.crash",
        kind: AppCompatBugKind::TranslationFailed,
        resolved: false,
    };
    assert!(!bug.is_attestation_only());
}

#[test]
fn at29_total_tested_counts_pass_plus_fail() {
    let mut state = init_app_compat_x86(AppCompatX86Config::aether_defaults()).unwrap();
    for _ in 0..10 {
        state.process_line(b"[at29] app pass");
    }
    for _ in 0..5 {
        state.process_line(b"[at29] app fail");
    }
    assert_eq!(state.total_tested(), 15);
}
