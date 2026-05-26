//! AT-16 tests: two-generation block cache.

use aether_translator::runtime::block_cache::BlockCache;

// ── Basic operations ──────────────────────────────────────────────────────────

#[test]
fn at16_insert_and_hit() {
    let mut cache = BlockCache::new(64);
    cache.insert(0x1000, 0, 32);
    let blk = cache.lookup(0x1000).expect("should hit");
    assert_eq!(blk.host_offset, 0);
    assert_eq!(blk.len, 32);
    assert_eq!(blk.guest_pc, 0x1000);
}

#[test]
fn at16_miss_returns_none() {
    let mut cache = BlockCache::new(64);
    assert!(cache.lookup(0xDEAD).is_none());
    assert_eq!(cache.stat_misses, 1);
}

#[test]
fn at16_invalidate_removes_entry() {
    let mut cache = BlockCache::new(64);
    cache.insert(0x2000, 64, 16);
    assert!(cache.lookup(0x2000).is_some());
    cache.invalidate(0x2000);
    assert!(cache.lookup(0x2000).is_none());
}

#[test]
fn at16_update_existing_entry() {
    let mut cache = BlockCache::new(64);
    cache.insert(0x3000, 0, 10);
    cache.insert(0x3000, 100, 20); // update
    let blk = cache.lookup(0x3000).unwrap();
    assert_eq!(blk.host_offset, 100);
    assert_eq!(blk.len, 20);
}

#[test]
fn at16_flush_all_clears_both_generations() {
    let mut cache = BlockCache::new(16);
    for i in 0..8u64 {
        cache.insert(i * 4, i as usize * 32, 32);
    }
    cache.flush_all();
    for i in 0..8u64 {
        assert!(cache.lookup(i * 4).is_none(), "entry {i} should be gone");
    }
}

// ── Hit rate gate ─────────────────────────────────────────────────────────────

#[test]
fn at16_hit_rate_gate_99pct() {
    // 1 000 unique PCs, 200 accesses each.
    // After warm-up (first 1 000 misses), the next 199 000 lookups are all hits.
    const N_PCS: u64 = 1_000;
    const ACCESSES_PER_PC: u64 = 200;

    let mut cache = BlockCache::new(2048); // capacity >> N_PCS

    // Warm-up: insert all blocks.
    for pc in (0..N_PCS).map(|i| i * 4) {
        cache.insert(pc, pc as usize, 16);
    }

    // Steady-state: look up every PC ACCESSES_PER_PC times.
    for _ in 0..ACCESSES_PER_PC {
        for pc in (0..N_PCS).map(|i| i * 4) {
            let result = cache.lookup(pc);
            assert!(result.is_some(), "PC 0x{pc:x} should be cached");
        }
    }

    let hit_rate = cache.hit_rate();
    assert!(
        hit_rate >= 0.99,
        "hit rate {hit_rate:.4} < 99 % gate (stat_hits={}, stat_misses={})",
        cache.stat_hits,
        cache.stat_misses
    );
}

// ── Generational eviction ────────────────────────────────────────────────────

#[test]
fn at16_generational_eviction_promotes_active() {
    // Small cache: force a generation rotation.
    let mut cache = BlockCache::new(8); // capacity=8, threshold=5 (70%)
    // Insert 6 entries to trigger rotation.
    for i in 0..6u64 {
        cache.insert(i * 4, i as usize, 4);
    }
    // After rotation, old entries are in old-gen.
    // Looking them up should promote them back.
    let gen_before = cache.generation();
    assert!(gen_before >= 1, "should have rotated at least once");

    // Entries 0..5 should still be findable (via old-gen lookup + promotion).
    for i in 0..6u64 {
        let hit = cache.lookup(i * 4);
        assert!(hit.is_some(), "entry {i} should be findable after rotation");
    }
}

#[test]
fn at16_stat_counters_monotone() {
    let mut cache = BlockCache::new(32);
    cache.insert(0xA000, 0, 8);
    let _ = cache.lookup(0xA000); // hit
    let _ = cache.lookup(0xB000); // miss
    let _ = cache.lookup(0xA000); // hit
    assert_eq!(cache.stat_hits, 2);
    assert_eq!(cache.stat_misses, 1);
}

#[test]
fn at16_load_factor_below_threshold_before_rotation() {
    let mut cache = BlockCache::new(16);
    // Insert fewer than 70% of capacity.
    for i in 0..10u64 {
        cache.insert(i * 4, i as usize, 4);
    }
    // load factor = 10/16 = 0.625 < 0.7, should not have rotated.
    assert_eq!(cache.generation(), 0, "should not have rotated yet");
}
