//! AT-21: AOT Pre-Translation — test suite.

use aether_translator::runtime::aot::{
    init_aot_pretranslation, AotConfig, AotError, AotPhase, AotQueue, AotStats,
    AOT_DEFAULT_LIBRARIES, AOT_P99_TARGET_MS, AOT_QUEUE_CAPACITY,
};

// ── Library list ──────────────────────────────────────────────────────────────

#[test]
fn at21_default_library_count_is_21() {
    assert_eq!(
        AOT_DEFAULT_LIBRARIES.len(),
        21,
        "AOT_DEFAULT_LIBRARIES must have exactly 21 entries (ch52)"
    );
}

#[test]
fn at21_library_list_contains_libart() {
    assert!(
        AOT_DEFAULT_LIBRARIES.contains(&"libart"),
        "AOT library list must include libart"
    );
}

#[test]
fn at21_library_list_contains_libvulkan() {
    assert!(AOT_DEFAULT_LIBRARIES.contains(&"libvulkan"));
}

#[test]
fn at21_library_list_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for &lib in AOT_DEFAULT_LIBRARIES {
        assert!(seen.insert(lib), "duplicate library: {lib}");
    }
}

// ── AotQueue ──────────────────────────────────────────────────────────────────

#[test]
fn at21_queue_enqueue_and_pop() {
    let mut q = AotQueue::new(8);
    q.enqueue(0, 0x1000).unwrap();
    q.enqueue(1, 0x2000).unwrap();
    assert_eq!(q.len(), 2);
    let item = q.pop().unwrap();
    assert_eq!(item.lib_idx, 0);
    assert_eq!(item.guest_pc, 0x1000);
}

#[test]
fn at21_queue_full_returns_error() {
    let mut q = AotQueue::new(2);
    q.enqueue(0, 0x1000).unwrap();
    q.enqueue(1, 0x2000).unwrap();
    assert_eq!(q.enqueue(2, 0x3000), Err(AotError::QueueFull));
}

#[test]
fn at21_queue_invalid_lib_idx_returns_error() {
    let mut q = AotQueue::new(8);
    let oob = AOT_DEFAULT_LIBRARIES.len(); // one past last valid
    assert_eq!(q.enqueue(oob, 0x1000), Err(AotError::LibraryNotFound));
}

#[test]
fn at21_queue_capacity_constant() {
    assert_eq!(AOT_QUEUE_CAPACITY, 64, "queue capacity must match ch52 spec");
}

// ── AotStats / p99 ────────────────────────────────────────────────────────────

#[test]
fn at21_p99_target_constant() {
    assert_eq!(AOT_P99_TARGET_MS, 33, "p99 target must be 33 ms per ch52");
}

#[test]
fn at21_p99_no_samples_returns_max() {
    let mut s = AotStats::default();
    assert_eq!(s.p99_frame_ms(), u64::MAX);
}

#[test]
fn at21_p99_single_sample() {
    let mut s = AotStats::default();
    s.record_frame_ms(20);
    assert_eq!(s.p99_frame_ms(), 20);
}

#[test]
fn at21_p99_gate_passes_below_target() {
    let mut s = AotStats::default();
    // 100 frames all at 10 ms — p99 should be 10 ms < 33 ms
    for _ in 0..100 {
        s.record_frame_ms(10);
    }
    assert!(s.gate_passes(33));
}

#[test]
fn at21_p99_gate_fails_above_target() {
    let mut s = AotStats::default();
    // 100 frames all at 40 ms — p99 should be 40 ms > 33 ms
    for _ in 0..100 {
        s.record_frame_ms(40);
    }
    assert!(!s.gate_passes(33));
}

#[test]
fn at21_p99_99th_percentile_correct() {
    let mut s = AotStats::default();
    // 1 outlier at 5 ms, then 99 frames at 40 ms.
    // After sorting (N=100): indices 0..97 = 40ms, index 98 = 40ms, index 99 = 40ms
    // idx = (100 * 99 / 100).saturating_sub(1) = 98 → samples[98] = 40 ms.
    s.record_frame_ms(5);
    for _ in 0..99 {
        s.record_frame_ms(40);
    }
    assert_eq!(s.p99_frame_ms(), 40);
}

// ── AotConfig / AotState ─────────────────────────────────────────────────────

#[test]
fn at21_config_aether_defaults_valid() {
    let cfg = AotConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.queue_capacity, AOT_QUEUE_CAPACITY);
    assert_eq!(cfg.p99_target_ms, AOT_P99_TARGET_MS);
}

#[test]
fn at21_init_pipeline_succeeds() {
    let cfg = AotConfig::aether_defaults();
    let state = init_aot_pretranslation(cfg).unwrap();
    // After init: libraries scanned + work queued
    assert!(state.phase >= AotPhase::WorkQueued);
    assert!(state.gate().all_libs_queued);
}

#[test]
fn at21_gate_passes_after_good_frames() {
    let cfg = AotConfig::aether_defaults();
    let mut state = init_aot_pretranslation(cfg).unwrap();
    // Simulate 200 cold-app-launch frames all well under 33 ms
    for _ in 0..200 {
        state.record_frame_ms(15);
    }
    assert!(state.gate().passes(), "gate must pass after frames under p99 target");
    assert_eq!(state.phase, AotPhase::GatePassed);
}

#[test]
fn at21_gate_fails_if_no_frames_recorded() {
    let cfg = AotConfig::aether_defaults();
    let state = init_aot_pretranslation(cfg).unwrap();
    // No frames recorded → p99 = u64::MAX > 33 ms
    assert!(!state.gate().p99_met);
    assert!(!state.gate().passes());
}

#[test]
fn at21_blocks_pretranslated_counter_increments() {
    let cfg = AotConfig::aether_defaults();
    let mut state = init_aot_pretranslation(cfg).unwrap();
    for i in 0..10u64 {
        state.record_frame_ms(i + 1);
    }
    assert_eq!(state.stats.blocks_pretranslated, 10);
}
