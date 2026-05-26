//! AT-15 gate tests — JIT code buffer, self-modifying code, ICache coherency.

#![cfg(test)]

use aether_translator::backend::{CodeBuf, Protection};
use aether_translator::backend::code_buf::smcode_test_iteration;

// ── Basic emit / commit ──────────────────────────────────────────────────────

#[test]
fn at15_new_buf_is_empty() {
    let buf = CodeBuf::new(4096);
    assert_eq!(buf.written_len(), 0);
    assert_eq!(buf.n_committed_blocks(), 0);
}

#[test]
fn at15_emit_bytes_advances_written_len() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90, 0x90, 0x90]).unwrap(); // 3 × NOP
    assert_eq!(buf.written_len(), 3);
    assert_eq!(buf.n_committed_blocks(), 0);
}

#[test]
fn at15_alloc_block_then_commit_makes_block_committed() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x1000, &[0x90u8; 8]).unwrap();
    buf.commit();
    assert_eq!(buf.n_committed_blocks(), 1);
}

#[test]
fn at15_committed_bytes_match_emitted() {
    let code = [0x48u8, 0x31, 0xC0, 0xC3]; // XOR RAX,RAX; RET
    let mut buf = CodeBuf::new(4096);
    let off = buf.alloc_block(0x2000, &code).unwrap();
    buf.commit();
    let stored = buf.read_bytes(off, 4);
    assert_eq!(stored, &code);
}

#[test]
fn at15_two_blocks_committed() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x1000, &[0x90u8; 4]).unwrap();
    buf.alloc_block(0x1008, &[0xC3u8; 2]).unwrap();
    buf.commit();
    assert_eq!(buf.n_committed_blocks(), 2);
}

// ── Protection state machine ──────────────────────────────────────────────────

#[test]
fn at15_initial_protection_is_rw() {
    let buf = CodeBuf::new(4096);
    assert_eq!(buf.protection(), Protection::ReadWrite);
}

#[test]
fn at15_commit_promotes_to_rx() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    buf.commit();
    assert_eq!(buf.protection(), Protection::ReadExecute);
}

#[test]
fn at15_emit_after_commit_returns_to_rw() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    buf.commit();
    buf.emit(&[0x90u8]).unwrap();
    assert_eq!(buf.protection(), Protection::ReadWrite);
}

// ── Overflow / capacity ───────────────────────────────────────────────────────

#[test]
fn at15_capacity_at_least_as_large_as_requested() {
    let buf = CodeBuf::new(1024);
    assert!(buf.capacity() >= 1024);
}

#[test]
fn at15_overflow_returns_error() {
    let mut buf = CodeBuf::new(4);
    // First 4 bytes succeed
    buf.emit(&[0x90u8; 4]).unwrap();
    // 5th byte must fail
    let result = buf.emit(&[0x90u8]);
    assert!(result.is_err(), "emit past capacity must return Err");
}

// ── Block registry ────────────────────────────────────────────────────────────

#[test]
fn at15_lookup_guest_pc_finds_committed_block() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x3000, &[0x90u8; 4]).unwrap();
    buf.commit();
    let blk = buf.lookup_guest_pc(0x3000).next().expect("block must be found");
    assert_eq!(blk.guest_pc, 0x3000);
    assert_eq!(blk.len, 4);
    assert!(blk.committed);
}

#[test]
fn at15_uncommitted_block_not_returned_by_lookup() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x4000, &[0xC3u8]).unwrap();
    // not committed
    assert!(buf.lookup_guest_pc(0x4000).next().is_none());
}

#[test]
fn at15_multiple_blocks_lookup() {
    let mut buf = CodeBuf::new(4096);
    for pc in [0x1000u64, 0x2000, 0x3000] {
        buf.alloc_block(pc, &[0x90u8; 2]).unwrap();
    }
    buf.commit();
    assert!(buf.lookup_guest_pc(0x1000).next().is_some());
    assert!(buf.lookup_guest_pc(0x2000).next().is_some());
    assert!(buf.lookup_guest_pc(0x3000).next().is_some());
}

// ── Invalidation ─────────────────────────────────────────────────────────────

#[test]
fn at15_invalidate_marks_block_uncommitted() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x5000, &[0x90u8]).unwrap();
    buf.commit();
    assert_eq!(buf.n_committed_blocks(), 1);
    buf.invalidate_guest_pc(0x5000);
    assert_eq!(buf.n_committed_blocks(), 0);
}

#[test]
fn at15_invalidate_increments_generation() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x6000, &[0x90u8]).unwrap();
    buf.commit();
    let gen_before = buf.all_blocks()[0].generation;
    buf.invalidate_guest_pc(0x6000);
    let gen_after = buf.all_blocks()[0].generation;
    assert!(gen_after > gen_before, "generation must increment on invalidation");
}

#[test]
fn at15_invalidate_nonexistent_pc_is_noop() {
    let mut buf = CodeBuf::new(4096);
    let n = buf.invalidate_guest_pc(0xDEAD_BEEF);
    assert_eq!(n, 0);
}

#[test]
fn at15_reinject_after_invalidate_succeeds() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x7000, &[0x90u8]).unwrap();
    buf.commit();
    buf.invalidate_guest_pc(0x7000);
    // Re-emit same PC
    buf.alloc_block(0x7000, &[0xC3u8]).unwrap();
    buf.commit();
    assert!(buf.lookup_guest_pc(0x7000).next().is_some());
}

// ── Reset ─────────────────────────────────────────────────────────────────────

#[test]
fn at15_reset_clears_all_state() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x8000, &[0x90u8; 16]).unwrap();
    buf.commit();
    buf.reset();
    assert_eq!(buf.written_len(), 0);
    assert_eq!(buf.n_committed_blocks(), 0);
    assert!(buf.all_blocks().is_empty());
    assert_eq!(buf.protection(), Protection::ReadWrite);
}

#[test]
fn at15_reset_allows_fresh_emit() {
    let mut buf = CodeBuf::new(4096);
    buf.alloc_block(0x1000, &[0x90u8; 4]).unwrap();
    buf.commit();
    buf.reset();
    buf.alloc_block(0x2000, &[0xC3u8]).unwrap();
    buf.commit();
    assert_eq!(buf.written_len(), 1);
    assert_eq!(buf.n_committed_blocks(), 1);
}

// ── needs_serialize / dirty invariant ────────────────────────────────────────

#[test]
fn at15_dirty_after_emit() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    assert!(buf.is_dirty());
}

#[test]
fn at15_not_dirty_after_commit() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    buf.commit();
    assert!(!buf.is_dirty());
}

#[test]
fn at15_executable_after_commit() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    buf.commit();
    assert!(buf.is_executable());
}

#[test]
fn at15_not_executable_when_dirty() {
    let mut buf = CodeBuf::new(4096);
    buf.emit(&[0x90u8]).unwrap();
    assert!(!buf.is_executable());
}

// ── Self-modifying code surrogate (AT-15 gate) ────────────────────────────────

/// One SMC cycle via the `smcode_test_iteration` harness.
#[test]
fn at15_smc_single_cycle_succeeds() {
    let mut buf = CodeBuf::new(65536);
    smcode_test_iteration(
        &mut buf,
        0xA000,
        &[0x90u8], // NOP v1
        &[0xC3u8], // RET v2
    )
    .expect("single SMC cycle must succeed");
}

/// Verify generation increments after SMC cycle.
#[test]
fn at15_smc_generation_advances_after_cycle() {
    let mut buf = CodeBuf::new(65536);
    smcode_test_iteration(&mut buf, 0xB000, &[0x90u8], &[0xC3u8])
        .expect("SMC cycle");
    // After cycle buf has been reset + rebuilt; all_blocks has generation=1 for v2 block.
    let max_gen = buf.all_blocks().iter().map(|b| b.generation).max().unwrap_or(0);
    assert!(max_gen >= 1, "generation must be ≥ 1 after one SMC cycle");
}

/// 1 000-iteration fast surrogate (runs in normal CI).
#[test]
fn at15_smc_1k_iterations_structural_fast() {
    const ITERS: u32 = 1_000;
    let mut buf = CodeBuf::new(4096);
    for _ in 0..ITERS {
        smcode_test_iteration(&mut buf, 0xC000, &[0x90u8], &[0xC3u8])
            .expect("SMC iteration must succeed");
    }
    // After ITERS cycles the v2 block has generation ≥ ITERS (each cycle resets
    // and the harness pushes a block with generation=1; the total is per-reset).
    // The key gate is that all ITERS iterations succeeded without error.
}

/// 1 000 000-iteration structural surrogate — marked #[ignore] for normal CI.
/// Run with `cargo test -- --include-ignored at15_smc_1m` for the full gate.
#[test]
#[ignore]
fn at15_smc_1m_iterations_structural() {
    const ITERS: u32 = 1_000_000;
    let mut buf = CodeBuf::new(4096);
    for i in 0..ITERS {
        smcode_test_iteration(&mut buf, 0xD000, &[0x90u8], &[0xC3u8])
            .unwrap_or_else(|e| panic!("SMC iteration {i} failed: {e}"));
    }
}

// ── Byte-exact stored content ─────────────────────────────────────────────────

/// Bytes written must survive through commit unchanged.
#[test]
fn at15_xor_rax_rax_ret_survives_commit() {
    let code = [0x48u8, 0x31, 0xC0, 0xC3]; // XOR RAX,RAX; RET
    let mut buf = CodeBuf::new(4096);
    let off = buf.alloc_block(0xE000, &code).unwrap();
    buf.commit();
    assert_eq!(buf.read_bytes(off, 4), &code);
}

#[test]
fn at15_mfence_encoding_survives_commit() {
    let mfence = [0x0Fu8, 0xAE, 0xF0];
    let mut buf = CodeBuf::new(4096);
    let off = buf.alloc_block(0xF000, &mfence).unwrap();
    buf.commit();
    assert_eq!(buf.read_bytes(off, 3), &mfence);
}
