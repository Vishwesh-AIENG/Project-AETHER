//! AT-23: Self-Modifying Code Handling — test suite.

use aether_translator::runtime::smc_handler::{
    init_smc_handler, RxPageRange, SmcConfig, SmcError, SmcPhase, SmcState, SmcWatcher,
};

// ── RxPageRange ───────────────────────────────────────────────────────────────

#[test]
fn at23_rx_range_contains_pa() {
    let r = RxPageRange::new(0x1000, 0x2000);
    assert!(r.contains_pa(0x1000));
    assert!(r.contains_pa(0x1FFF));
    assert!(!r.contains_pa(0x2000));
    assert!(!r.contains_pa(0x0FFF));
}

#[test]
fn at23_rx_range_overlaps() {
    let r = RxPageRange::new(0x1000, 0x2000);
    // fault PA 0x1800 length 0x100 → overlaps [0x1000, 0x2000)
    assert!(r.overlaps(0x1800, 0x100));
    // fault PA 0x0800 length 0x100 → does NOT overlap
    assert!(!r.overlaps(0x0800, 0x100));
    // fault PA 0x1F00 length 0x200 → partially overlaps
    assert!(r.overlaps(0x1F00, 0x200));
}

#[test]
fn at23_rx_range_add_guest_pc_dedup() {
    let mut r = RxPageRange::new(0x1000, 0x2000);
    r.add_guest_pc(0x1000);
    r.add_guest_pc(0x1000); // duplicate
    r.add_guest_pc(0x1100);
    assert_eq!(r.guest_pcs.len(), 2);
}

// ── SmcWatcher ────────────────────────────────────────────────────────────────

#[test]
fn at23_watcher_register_and_fault() {
    let mut w = SmcWatcher::new();
    let mut r = RxPageRange::new(0x1000, 0x2000);
    r.add_guest_pc(0x1000);
    r.add_guest_pc(0x1100);
    w.register_rx_range(r).unwrap();

    let to_invalidate = w.on_write_fault(0x1400, 0x100);
    assert_eq!(to_invalidate.len(), 2);
    assert!(to_invalidate.contains(&0x1000));
    assert!(to_invalidate.contains(&0x1100));
    assert_eq!(w.stats.write_faults_caught, 1);
    assert_eq!(w.stats.blocks_invalidated, 2);
}

#[test]
fn at23_watcher_fault_outside_range_no_invalidation() {
    let mut w = SmcWatcher::new();
    let mut r = RxPageRange::new(0x1000, 0x2000);
    r.add_guest_pc(0x1000);
    w.register_rx_range(r).unwrap();

    let to_invalidate = w.on_write_fault(0x3000, 0x100);
    assert!(to_invalidate.is_empty());
    assert_eq!(w.stats.blocks_invalidated, 0);
}

#[test]
fn at23_watcher_duplicate_range_returns_error() {
    let mut w = SmcWatcher::new();
    let r1 = RxPageRange::new(0x1000, 0x2000);
    let r2 = RxPageRange::new(0x1000, 0x2000); // exact duplicate
    w.register_rx_range(r1).unwrap();
    assert_eq!(w.register_rx_range(r2), Err(SmcError::PageAlreadyRx));
}

#[test]
fn at23_watcher_bind_block_to_range() {
    let mut w = SmcWatcher::new();
    let r = RxPageRange::new(0x1000, 0x2000);
    w.register_rx_range(r).unwrap();

    w.bind_block_to_range(0x1050, 0x1050).unwrap();
    w.bind_block_to_range(0x1200, 0x1200).unwrap();

    let invalidated = w.on_write_fault(0x1000, 0x1000);
    assert_eq!(invalidated.len(), 2);
}

#[test]
fn at23_watcher_bind_to_nonexistent_range_fails() {
    let mut w = SmcWatcher::new();
    let r = RxPageRange::new(0x1000, 0x2000);
    w.register_rx_range(r).unwrap();

    assert_eq!(
        w.bind_block_to_range(0x5000, 0x5000),
        Err(SmcError::InvalidRange)
    );
}

#[test]
fn at23_watcher_stale_execution_recorded() {
    let mut w = SmcWatcher::new();
    assert_eq!(w.stats.stale_executions, 0);
    w.record_stale_execution();
    assert_eq!(w.stats.stale_executions, 1);
}

// ── SmcState / Gate ───────────────────────────────────────────────────────────

#[test]
fn at23_config_aether_defaults_wx_strict() {
    let cfg = SmcConfig::aether_defaults();
    assert!(cfg.wx_strict);
}

#[test]
fn at23_init_pipeline_phase() {
    let cfg = SmcConfig::aether_defaults();
    let state = init_smc_handler(cfg).unwrap();
    assert_eq!(state.phase, SmcPhase::WxEnforced);
    assert!(state.gate().wx_enforced);
    assert!(!state.gate().fault_handler_installed);
}

#[test]
fn at23_gate_passes_after_range_registered_and_no_stale() {
    let cfg = SmcConfig::aether_defaults();
    let mut state = init_smc_handler(cfg).unwrap();

    let mut r = RxPageRange::new(0x1000, 0x2000);
    r.add_guest_pc(0x1000);
    state.register_rx_range(r).unwrap();

    assert!(state.gate().fault_handler_installed);
    assert!(state.gate().zero_stale_translations);
    assert!(state.gate().passes());
    assert_eq!(state.phase, SmcPhase::GatePassed);
}

#[test]
fn at23_gate_fails_after_stale_execution() {
    let cfg = SmcConfig::aether_defaults();
    let mut state = init_smc_handler(cfg).unwrap();
    let r = RxPageRange::new(0x1000, 0x2000);
    state.register_rx_range(r).unwrap();

    state.record_stale_execution();
    assert!(!state.gate().zero_stale_translations);
    assert!(!state.gate().passes());
}

#[test]
fn at23_write_fault_returns_pcs_and_clears_range() {
    let cfg = SmcConfig::aether_defaults();
    let mut state = init_smc_handler(cfg).unwrap();

    let mut r = RxPageRange::new(0x4000, 0x5000);
    r.add_guest_pc(0x4000);
    r.add_guest_pc(0x4100);
    state.register_rx_range(r).unwrap();

    let pcs = state.on_write_fault(0x4000, 0x1000);
    assert_eq!(pcs.len(), 2);

    // After invalidation the range is cleared — second fault yields nothing
    let pcs2 = state.on_write_fault(0x4000, 0x1000);
    assert!(pcs2.is_empty());
}

#[test]
fn at23_range_count_correct() {
    let cfg = SmcConfig::aether_defaults();
    let mut state = init_smc_handler(cfg).unwrap();
    assert_eq!(state.watcher.range_count(), 0);
    state
        .register_rx_range(RxPageRange::new(0x1000, 0x2000))
        .unwrap();
    state
        .register_rx_range(RxPageRange::new(0x3000, 0x4000))
        .unwrap();
    assert_eq!(state.watcher.range_count(), 2);
}
