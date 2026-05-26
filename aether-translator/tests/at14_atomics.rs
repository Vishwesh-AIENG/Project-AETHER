//! AT-14 gate tests — LL/SC → LOCK CMPXCHG atomic lowering.

#![cfg(test)]

use aether_translator::backend::{AtomicLower, X86Encoder};
use aether_translator::backend::lower_atomic::{verify_lock_prefixes, count_lock_cmpxchg};
use aether_translator::ir::{IrBlock, BlockId, IrOp, IrValueId};
use aether_translator::ir::memory::{AtomicOp, LoadTy, StoreTy, MemOrder};
use aether_translator::regalloc::linear_scan::{AllocResult, Assignment};

// ── helper ──────────────────────────────────────────────────────────────────

fn make_alloc(pairs: &[(u32, Assignment)]) -> AllocResult {
    let mut r = AllocResult::default();
    for (id, a) in pairs {
        r.assignments.insert(*id, *a);
    }
    r
}

fn lower_ops(ops: Vec<IrOp>, alloc: &AllocResult) -> Vec<u8> {
    let mut blk = IrBlock::new(BlockId(0));
    blk.ops = ops;
    let mut enc = X86Encoder::new();
    AtomicLower::lower_block(&blk, alloc, &mut enc);
    enc.finish()
}

// ── AT-14: LOCK CMPXCHG presence ────────────────────────────────────────────

/// LOCK CMPXCHG is 0xF0 0x4? 0x0F 0xB1
#[test]
fn at14_lock_prefix_present_in_cas() {
    // AtomicCas: dst=v3, addr=v0(RAX), expected=v1(RCX), new=v2(RDX)
    let ops = vec![IrOp::AtomicCas {
        dst: IrValueId(3),
        addr: IrValueId(0),
        expected: IrValueId(1),
        new: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    // RAX=0, RCX=1, RDX=2 in ALLOCATABLE_GPRS indices
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)), // addr → ALLOCATABLE_GPRS[0]
        (1, Assignment::Gpr(1)), // expected → [1]
        (2, Assignment::Gpr(2)), // new → [2]
        (3, Assignment::Gpr(0)), // result → [0]
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "LOCK CMPXCHG must have 0xF0 prefix: {bytes:02X?}"
    );
}

#[test]
fn at14_lock_cmpxchg_count_one_per_cas() {
    let ops = vec![IrOp::AtomicCas {
        dst: IrValueId(3),
        addr: IrValueId(0),
        expected: IrValueId(1),
        new: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
        (3, Assignment::Gpr(0)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    let count = count_lock_cmpxchg(&bytes);
    assert_eq!(count, 1, "One CAS → one LOCK CMPXCHG, got {count}");
}

/// Two consecutive CAS operations → two LOCK CMPXCHG instructions.
#[test]
fn at14_two_cas_two_lock_cmpxchg() {
    let ops = vec![
        IrOp::AtomicCas {
            dst: IrValueId(10),
            addr: IrValueId(0),
            expected: IrValueId(1),
            new: IrValueId(2),
            order: MemOrder::SeqCst,
        },
        IrOp::AtomicCas {
            dst: IrValueId(11),
            addr: IrValueId(0),
            expected: IrValueId(3),
            new: IrValueId(4),
            order: MemOrder::SeqCst,
        },
    ];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(5)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
        (3, Assignment::Gpr(6)),
        (4, Assignment::Gpr(7)),
        (10, Assignment::Gpr(0)),
        (11, Assignment::Gpr(0)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    let count = count_lock_cmpxchg(&bytes);
    assert_eq!(count, 2, "Two CAS → two LOCK CMPXCHG, got {count}");
}

// ── AT-14: LoadExclusive / StoreExclusive ────────────────────────────────────

#[test]
fn at14_load_exclusive_emits_mov() {
    let ops = vec![IrOp::LoadExclusive {
        dst: IrValueId(0),
        addr: IrValueId(1),
        ty: LoadTy::U64,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(!bytes.is_empty(), "LoadExclusive must emit bytes");
    assert!(
        bytes.contains(&0x8B),
        "LoadExclusive must emit MOV (0x8B): {bytes:02X?}"
    );
}

#[test]
fn at14_store_exclusive_emits_lock_cmpxchg() {
    let ops = vec![IrOp::StoreExclusive {
        status: IrValueId(0),
        val: IrValueId(2),
        addr: IrValueId(1),
        ty: StoreTy::U64,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(1)), // status → RCX
        (1, Assignment::Gpr(0)), // addr → RAX
        (2, Assignment::Gpr(2)), // val → RDX
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "StoreExclusive must use LOCK CMPXCHG: {bytes:02X?}"
    );
}

// ── AT-14: AtomicRmw operations ───────────────────────────────────────────────

#[test]
fn at14_atomic_rmw_add_emits_lock_xadd() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Add,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        bytes.contains(&0xF0),
        "LOCK XADD must have LOCK prefix: {bytes:02X?}"
    );
    let has_xadd = bytes.windows(2).any(|w| w == [0x0F, 0xC1]);
    assert!(has_xadd, "LOCK XADD must have XADD opcode 0F C1: {bytes:02X?}");
}

#[test]
fn at14_atomic_rmw_xchg_emits_xchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Swp,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        bytes.contains(&0x87),
        "Swp must emit XCHG (0x87): {bytes:02X?}"
    );
}

#[test]
fn at14_atomic_rmw_eor_emits_lock_cmpxchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Eor,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "AtomicRmw Eor CAS loop must have LOCK prefix: {bytes:02X?}"
    );
}

#[test]
fn at14_atomic_rmw_set_emits_lock_cmpxchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Set,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "AtomicRmw Set CAS loop must have LOCK prefix: {bytes:02X?}"
    );
}

#[test]
fn at14_atomic_rmw_clr_emits_lock_cmpxchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Clr,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "AtomicRmw Clr CAS loop must have LOCK prefix: {bytes:02X?}"
    );
}

// ── AT-14: verify_lock_prefixes / count_lock_cmpxchg API ─────────────────────

#[test]
fn at14_verify_lock_prefixes_finds_0xf0() {
    let bytes = vec![0x48u8, 0x89, 0xC0, 0xF0, 0x48, 0x0F, 0xB1, 0x08];
    assert!(verify_lock_prefixes(&bytes));
}

#[test]
fn at14_verify_lock_prefixes_rejects_no_lock() {
    let bytes = vec![0x48u8, 0x89, 0xC0, 0x48, 0x01, 0xC8];
    assert!(!verify_lock_prefixes(&bytes));
}

#[test]
fn at14_count_lock_cmpxchg_zero_when_none() {
    let bytes = vec![0x48u8, 0x89, 0xC0];
    assert_eq!(count_lock_cmpxchg(&bytes), 0);
}

#[test]
fn at14_count_lock_cmpxchg_exact_pattern() {
    let bytes = vec![0xF0u8, 0x48, 0x0F, 0xB1, 0x08];
    assert_eq!(count_lock_cmpxchg(&bytes), 1);
}

#[test]
fn at14_count_lock_cmpxchg_two_in_sequence() {
    let bytes = vec![
        0xF0u8, 0x48, 0x0F, 0xB1, 0x08,
        0x90,
        0xF0, 0x48, 0x0F, 0xB1, 0x10,
    ];
    assert_eq!(count_lock_cmpxchg(&bytes), 2);
}

// ── AT-14: CAS retry loop structure ──────────────────────────────────────────

/// The retry loop must contain a JNE (0x75 rel8 or 0x0F 0x85 rel32) backward branch.
#[test]
fn at14_rmw_eor_has_backward_branch() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Eor,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    let has_jne = bytes.contains(&0x75)
        || bytes.windows(2).any(|w| w == [0x0F, 0x85]);
    assert!(
        has_jne,
        "CAS retry loop must have JNE backward branch: {bytes:02X?}"
    );
}

/// AtomicRmw Smin → CAS loop with LOCK CMPXCHG.
#[test]
fn at14_rmw_smin_has_lock_cmpxchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Smin,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "AtomicRmw Smin must use CAS loop: {bytes:02X?}"
    );
}

/// AtomicRmw Umax → CAS loop with LOCK CMPXCHG.
#[test]
fn at14_rmw_umax_has_lock_cmpxchg() {
    let ops = vec![IrOp::AtomicRmw {
        dst: IrValueId(0),
        op: AtomicOp::Umax,
        addr: IrValueId(1),
        val: IrValueId(2),
        order: MemOrder::SeqCst,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(0)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    assert!(
        verify_lock_prefixes(&bytes),
        "AtomicRmw Umax must use CAS loop: {bytes:02X?}"
    );
}

// ── AT-14: stress gate surrogate ─────────────────────────────────────────────

/// Surrogate for the 16-thread atomic stress gate: lower 64 consecutive CAS
/// operations and verify all have LOCK CMPXCHG.
#[test]
fn at14_stress_surrogate_64_cas_all_have_lock() {
    let mut ops = Vec::new();
    for i in 0u32..64 {
        ops.push(IrOp::AtomicCas {
            dst: IrValueId(100 + i),
            addr: IrValueId(0),
            expected: IrValueId(1),
            new: IrValueId(2),
            order: MemOrder::SeqCst,
        });
    }
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(5)),
        (1, Assignment::Gpr(1)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);
    let count = count_lock_cmpxchg(&bytes);
    assert_eq!(
        count, 64,
        "64 CAS ops must produce exactly 64 LOCK CMPXCHG, got {count}"
    );
}

/// Every CMPXCHG in the byte stream must be preceded by LOCK (0xF0).
#[test]
fn at14_no_naked_cmpxchg_allowed() {
    let ops = vec![IrOp::StoreExclusive {
        status: IrValueId(0),
        val: IrValueId(2),
        addr: IrValueId(1),
        ty: StoreTy::U64,
    }];
    let alloc = make_alloc(&[
        (0, Assignment::Gpr(1)),
        (1, Assignment::Gpr(0)),
        (2, Assignment::Gpr(2)),
    ]);
    let bytes = lower_ops(ops, &alloc);

    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == 0x0F && bytes[i + 1] == 0xB1 {
            let mut j = i;
            if j > 0 && (bytes[j - 1] & 0xF0) == 0x40 {
                j -= 1;
            }
            assert!(
                j > 0 && bytes[j - 1] == 0xF0,
                "Naked CMPXCHG at offset {i}: {bytes:02X?}"
            );
        }
    }
}
