//! AT-18 tests: indirect-branch inline-cache chaining.

use aether_translator::runtime::branch_chain::{BranchChainTable, SETTLE_THRESHOLD};

// ── Basic settle mechanics ────────────────────────────────────────────────────

#[test]
fn at18_settle_after_threshold() {
    let mut table = BranchChainTable::new();
    let call_site = 0x4000u64;
    let target = 0x8000u64;

    for i in 0..SETTLE_THRESHOLD {
        let settled = table.record(call_site, target);
        if i + 1 < SETTLE_THRESHOLD {
            assert!(settled.is_none(), "should not settle before threshold (i={i})");
        } else {
            assert!(settled.is_some(), "should settle at threshold");
        }
    }

    let entry = table.get(call_site).unwrap();
    assert!(entry.settled);
    assert_eq!(entry.target_guest_pc, target);
    assert_eq!(entry.hit_count, SETTLE_THRESHOLD);
}

#[test]
fn at18_target_change_resets_counter() {
    let mut table = BranchChainTable::new();
    let call_site = 0x5000u64;

    // First target — SETTLE_THRESHOLD - 1 dispatches.
    for _ in 0..SETTLE_THRESHOLD - 1 {
        table.record(call_site, 0xAAAA);
    }
    // Switch target — should reset counter.
    table.record(call_site, 0xBBBB);

    let entry = table.get(call_site).unwrap();
    assert!(!entry.settled, "counter should have reset on target change");
    assert_eq!(entry.hit_count, 1);
    assert_eq!(entry.target_guest_pc, 0xBBBB);
}

#[test]
fn at18_multiple_call_sites_independent() {
    let mut table = BranchChainTable::new();
    let sites = [0x1000u64, 0x2000, 0x3000];
    let targets = [0xA000u64, 0xB000, 0xC000];

    for (&site, &target) in sites.iter().zip(targets.iter()) {
        for _ in 0..SETTLE_THRESHOLD {
            table.record(site, target);
        }
    }

    for (&site, &target) in sites.iter().zip(targets.iter()) {
        let entry = table.get(site).unwrap();
        assert!(entry.settled, "site 0x{site:x} should be settled");
        assert_eq!(entry.target_guest_pc, target);
    }
}

// ── Patchable gate ────────────────────────────────────────────────────────────

#[test]
fn at18_patchable_after_offsets_set() {
    let mut table = BranchChainTable::new();
    let call_site = 0x6000u64;
    let target = 0x9000u64;

    for _ in 0..SETTLE_THRESHOLD {
        table.record(call_site, target);
    }

    // Register host offsets.
    table.set_call_site_offset(call_site, 0x100);
    table.apply_patch(call_site, 0x200);

    let entry = table.get(call_site).unwrap();
    assert!(entry.is_patchable(), "entry should be patchable");
    assert_eq!(entry.host_call_site_offset, Some(0x100));
    assert_eq!(entry.host_target_offset, Some(0x200));
}

#[test]
fn at18_gate_passes_when_all_settled_are_patchable() {
    let mut table = BranchChainTable::new();
    // Settle one entry and register both offsets.
    let call_site = 0x7000u64;
    for _ in 0..SETTLE_THRESHOLD {
        table.record(call_site, 0xF000);
    }
    table.set_call_site_offset(call_site, 0x50);
    table.apply_patch(call_site, 0x150);

    assert!(table.gate_passes(), "gate should pass");
    assert_eq!(table.patches_applied, 1);
}

// ── Chain hit rate ────────────────────────────────────────────────────────────

#[test]
fn at18_direct_dispatches_counted_after_settle() {
    let mut table = BranchChainTable::new();
    let call_site = 0xA000u64;
    let target = 0xD000u64;

    // Settle the entry.
    for _ in 0..SETTLE_THRESHOLD {
        table.record(call_site, target);
    }

    // After settling, subsequent dispatches to the same site are "direct".
    // The current implementation counts them in direct_dispatches on re-record.
    // Record 10 more dispatches — they should all be direct.
    for _ in 0..10 {
        table.record(call_site, target);
    }

    let rate = table.chain_hit_rate();
    assert!(
        rate > 0.0,
        "chain hit rate should be positive after settle, got {rate}"
    );
}

// ── Settle-threshold constant ─────────────────────────────────────────────────

#[test]
fn at18_settle_threshold_value() {
    // Documented gate: within 2× native after N dispatches.
    // Threshold of 4 is the minimum for amortizing the lookup overhead.
    assert!(
        SETTLE_THRESHOLD >= 2 && SETTLE_THRESHOLD <= 16,
        "SETTLE_THRESHOLD={SETTLE_THRESHOLD} out of expected range [2,16]"
    );
}
