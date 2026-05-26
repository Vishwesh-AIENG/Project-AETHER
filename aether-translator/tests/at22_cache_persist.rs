//! AT-22: JIT Cache Persistence — test suite.

use aether_translator::runtime::cache_persist::{
    crc32_iso, init_cache_persist, CachePersistConfig, CachePersistError, CachePersistPhase,
    CachePersistStats, CachePersistEntry, NvmeSpillQueue,
    CACHE_PERSIST_NVME_LBA_BASE, CACHE_PERSIST_QUEUE_DEPTH, CACHE_PERSIST_TARGET_REDUCTION_PCT,
};

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn at22_nvme_lba_base_nonzero() {
    assert_ne!(CACHE_PERSIST_NVME_LBA_BASE, 0);
}

#[test]
fn at22_queue_depth_constant() {
    assert_eq!(CACHE_PERSIST_QUEUE_DEPTH, 64);
}

#[test]
fn at22_target_reduction_constant() {
    assert_eq!(CACHE_PERSIST_TARGET_REDUCTION_PCT, 80);
}

// ── CRC-32 ────────────────────────────────────────────────────────────────────

#[test]
fn at22_crc32_known_value() {
    // CRC-32/ISO-HDLC of b"123456789" = 0xCBF43926
    let crc = crc32_iso(b"123456789");
    assert_eq!(crc, 0xCBF4_3926, "CRC-32 must match ISO-HDLC reference");
}

#[test]
fn at22_crc32_empty_input() {
    let crc = crc32_iso(b"");
    assert_eq!(crc, 0x0000_0000);
}

#[test]
fn at22_crc32_deterministic() {
    let a = crc32_iso(b"hello world");
    let b = crc32_iso(b"hello world");
    assert_eq!(a, b);
}

// ── CachePersistEntry ─────────────────────────────────────────────────────────

#[test]
fn at22_entry_new_fields() {
    let e = CachePersistEntry::new(0xDEAD_BEEF, 256, 0xCAFE_BABE);
    assert_eq!(e.guest_pc, 0xDEAD_BEEF);
    assert_eq!(e.code_len, 256);
    assert_eq!(e.crc32, 0xCAFE_BABE);
}

// ── NvmeSpillQueue ────────────────────────────────────────────────────────────

#[test]
fn at22_spill_queue_enqueue_and_drain() {
    let mut q = NvmeSpillQueue::new(4);
    q.enqueue(CachePersistEntry::new(0x1000, 32, 0)).unwrap();
    q.enqueue(CachePersistEntry::new(0x2000, 64, 0)).unwrap();
    assert_eq!(q.len(), 2);
    let drained = q.drain();
    assert_eq!(drained.len(), 2);
    assert!(q.is_empty());
}

#[test]
fn at22_spill_queue_full_returns_error() {
    let mut q = NvmeSpillQueue::new(2);
    q.enqueue(CachePersistEntry::new(0x1000, 32, 0)).unwrap();
    q.enqueue(CachePersistEntry::new(0x2000, 64, 0)).unwrap();
    assert_eq!(
        q.enqueue(CachePersistEntry::new(0x3000, 96, 0)),
        Err(CachePersistError::NvmeQueueFull)
    );
}

// ── CachePersistStats ─────────────────────────────────────────────────────────

#[test]
fn at22_reduction_pct_zero_when_no_baseline() {
    let s = CachePersistStats::default();
    assert_eq!(s.reduction_pct(), 0);
}

#[test]
fn at22_reduction_pct_80_pct() {
    let s = CachePersistStats {
        cold_translations_without_cache: 1000,
        cold_translations_with_cache: 200,
        ..Default::default()
    };
    assert_eq!(s.reduction_pct(), 80);
}

#[test]
fn at22_reduction_pct_100_pct() {
    let s = CachePersistStats {
        cold_translations_without_cache: 500,
        cold_translations_with_cache: 0,
        ..Default::default()
    };
    assert_eq!(s.reduction_pct(), 100);
}

#[test]
fn at22_reduction_pct_below_target() {
    let s = CachePersistStats {
        cold_translations_without_cache: 100,
        cold_translations_with_cache: 50,
        ..Default::default()
    };
    // 50% reduction < 80% target
    assert!(s.reduction_pct() < 80);
}

// ── CachePersistConfig ────────────────────────────────────────────────────────

#[test]
fn at22_config_aether_defaults_valid() {
    let cfg = CachePersistConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
    assert!(cfg.spill_enabled);
}

#[test]
fn at22_config_zero_queue_depth_invalid() {
    let mut cfg = CachePersistConfig::aether_defaults();
    cfg.queue_depth = 0;
    assert_eq!(cfg.validate(), Err(CachePersistError::NvmeQueueFull));
}

// ── Full pipeline ─────────────────────────────────────────────────────────────

#[test]
fn at22_init_pipeline_succeeds() {
    let cfg = CachePersistConfig::aether_defaults();
    let state = init_cache_persist(cfg).unwrap();
    assert_eq!(state.phase, CachePersistPhase::NotStarted);
    assert!(!state.gate().passes());
}

#[test]
fn at22_spill_then_restore_gate() {
    let cfg = CachePersistConfig::aether_defaults();
    let mut state = init_cache_persist(cfg).unwrap();

    // Spill 4 blocks
    let dummy_code: Vec<u8> = (0..32u8).collect();
    for i in 0..4u64 {
        state.spill_block(0x1000 * (i + 1), &dummy_code).unwrap();
    }
    state.commit_spill();
    assert!(state.gate().cache_spilled);
    assert_eq!(state.phase, CachePersistPhase::BlocksSpilled);

    // Record restore
    state.record_restore(4);
    assert!(state.gate().cache_restored);

    // Feed translation counts: 1000 without cache, 200 with cache → 80% reduction
    state.record_translation_counts(1000, 200);
    assert!(state.gate().reduction_target_met);
    assert!(state.gate().passes());
    assert_eq!(state.phase, CachePersistPhase::GatePassed);
}

#[test]
fn at22_gate_fails_below_reduction_target() {
    let cfg = CachePersistConfig::aether_defaults();
    let mut state = init_cache_persist(cfg).unwrap();

    let dummy: Vec<u8> = vec![0u8; 16];
    state.spill_block(0x1000, &dummy).unwrap();
    state.commit_spill();
    state.record_restore(1);

    // Only 50% reduction → gate must not pass
    state.record_translation_counts(100, 50);
    assert!(!state.gate().reduction_target_met);
    assert!(!state.gate().passes());
}

#[test]
fn at22_spill_accumulates_block_count() {
    let cfg = CachePersistConfig::aether_defaults();
    let mut state = init_cache_persist(cfg).unwrap();
    let code: Vec<u8> = vec![0x90u8; 8];
    for i in 0..5u64 {
        state.spill_block(0x1000 * (i + 1), &code).unwrap();
    }
    assert_eq!(state.stats.blocks_spilled, 5);
}
