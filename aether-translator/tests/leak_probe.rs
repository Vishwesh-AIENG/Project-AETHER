//! Per-cold-block heap-leak probe for the DBT translate path.
//!
//! The hypervisor's global heap is a NEVER-FREEING bump allocator: every
//! allocation is permanent (dealloc is a no-op). `DbtRuntime::translate_block`
//! is supposed to be allocation-free once warm (it reuses scratch_func /
//! scratch_enc / scratch_regalloc / scratch_branch_patches). Any residual
//! per-call allocation is, under that bump heap, a permanent leak that
//! accumulates across the millions of unique blocks a full Android boot
//! translates → eventual OOM ("memory allocation of 4848 bytes failed").
//!
//! This test wraps the system allocator with a counter that NEVER decrements on
//! free (simulating the bump heap), warms the translate path, then measures the
//! allocation delta across N=4000 COLD translates (distinct PCs, distinct
//! bytes). A nonzero per-translate leak fails the assert.
//!
//! Run:
//!   cargo test -p aether-translator --test leak_probe -- --nocapture
#![cfg(all(test, target_arch = "x86_64"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// ── Counting allocator (models the never-freeing bump heap) ──────────────────
//
// Counters are PER-THREAD: libtest runs tests on parallel threads, and a
// process-global counter picked up other tests' (and the harness's)
// allocations inside a measurement window — the asserts below allow < 4
// allocations per 4000 iterations, so that noise made the suite flaky. Each
// test now measures only its own thread. `const` thread-locals with no
// destructor never allocate, so touching them from the allocator is safe.

thread_local! {
    static ALLOC_BYTES: Cell<u64> = const { Cell::new(0) };
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
}

fn count(bytes: usize) {
    // try_with: the TLS slot may already be gone during thread teardown.
    let _ = ALLOC_BYTES.try_with(|b| b.set(b.get() + bytes as u64));
    let _ = ALLOC_COUNT.try_with(|c| c.set(c.get() + 1));
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // NOTE: deliberately does NOT decrement — models the bump heap where a
        // free is a no-op, so every alloc is a permanent leak.
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A growing realloc allocates fresh; count the new size as a new leak.
        count(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn snap() -> (u64, u64) {
    (
        ALLOC_BYTES.with(Cell::get),
        ALLOC_COUNT.with(Cell::get),
    )
}

// ── A realistic, fully-decodable ARM64 block ─────────────────────────────────
//
// Each block: MOVZ X0,#imm ; ADD X0,X0,#1 ; ADD X1,X0,X0 ; SUB X2,X1,#4 ;
//             ORR X3,X2,X1 ; RET
// All are simple ALU ops the decoder+lift+regalloc+encode pipeline fully
// supports. We vary the MOVZ immediate per block so the lifted IR differs.

fn build_block(imm16: u16) -> Vec<u8> {
    // MOVZ X0, #imm16        : sf=1 opc=10 hw=00 imm16 Rd=0 -> 0xD2800000 | imm<<5
    let movz = 0xD280_0000u32 | ((imm16 as u32) << 5);
    // ADD X0, X0, #1         : 0x91000400
    let add_imm = 0x9100_0400u32;
    // ADD X1, X0, X0 (shifted reg) : 0x8B000001 (X1 = X0 + X0)
    let add_reg = 0x8B00_0001u32;
    // SUB X2, X1, #4         : 0xD1001022
    let sub_imm = 0xD100_1022u32;
    // ORR X3, X2, X1         : 0xAA010043
    let orr_reg = 0xAA01_0043u32;
    // RET                    : 0xD65F03C0
    let ret = 0xD65F_03C0u32;

    let words = [movz, add_imm, add_reg, sub_imm, orr_reg, ret];
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

// ── Sanity: confirm the synthesized words actually decode ─────────────────────

#[test]
fn words_decode_ok() {
    use aether_translator::decoder::decode_instruction;
    let bytes = build_block(0x1234);
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        decode_instruction(w)
            .unwrap_or_else(|e| panic!("word {i} {w:#010x} failed to decode: {e:?}"));
    }
}

// ── Full-pipeline leak measurement ───────────────────────────────────────────

#[test]
fn translate_block_leak_per_cold() {
    use aether_translator::dbt::{AetherDbtResult, DbtRuntime};

    let mut rt = DbtRuntime::new(); // host_pa_base = 0 → W^X commit no-ops
    let block = build_block(0xABCD);

    // WARM UP: drive a handful of cold translates so the reused scratch buffers
    // (and CodeBuf/BlockCache internals) reach steady-state capacity.
    for i in 0..64u64 {
        let pc = 0x10_0000 + i * 0x40; // distinct PCs → each is a cold translate
        let r = rt.translate_block(pc, &block);
        assert_eq!(r, AetherDbtResult::Ok, "warmup translate failed at pc {pc:#x}");
    }

    // MEASURE: N distinct cold translates.
    const N: u64 = 4000;
    let (b0, c0) = snap();
    for i in 0..N {
        // Distinct PC every call (misses the block cache → real cold translate).
        let pc = 0x40_0000 + i * 0x40;
        let r = rt.translate_block(pc, &block);
        assert_eq!(r, AetherDbtResult::Ok, "measure translate failed at pc {pc:#x}");
    }
    let (b1, c1) = snap();

    let bytes_per = (b1 - b0) as f64 / N as f64;
    let allocs_per = (c1 - c0) as f64 / N as f64;
    println!("[full pipeline] N={N}");
    println!("  bytes leaked / cold translate  = {bytes_per:.3}");
    println!("  allocs leaked / cold translate = {allocs_per:.4}");
    println!("  total Δbytes = {}  Δcount = {}", b1 - b0, c1 - c0);

    // FIXED: the only heap-growing component of a warm cold translate used to
    // be `CodeBuf::alloc_block` pushing one 32-byte `CodeBlock` into the
    // unbounded `CodeBuf.blocks` Vec (never cleared except on capacity-pressure
    // `reset()`), which scaled linearly with the millions of unique blocks an
    // Android boot translates → the ~1.5 GiB OOM before SurfaceFlinger.
    //
    // That registry is now `cfg(test)`-gated, so it does NOT exist in the
    // library when compiled as a dependency of this integration test (where
    // `cfg(test)` is unset) — exactly the configuration the production
    // hypervisor links (`default-features = false`). `alloc_block` now only
    // advances the watermark; PC→offset lookup is owned by `BlockCache`, and
    // production SMC handling flushes the whole cache via `flush_all`.
    //
    // REGRESSION GUARD: a warm cold translate must allocate essentially nothing.
    assert!(
        allocs_per < 0.001,
        "per-cold-block translate must be allocation-free now (allocs_per={allocs_per})"
    );
}

// ── Bisect: which pipeline stage allocates per cold iteration? ────────────────
//
// Each test replicates the translate_block pipeline up to a given stage, reusing
// the same scratch buffers translate_block does, and measures allocs/iter over N
// COLD iterations. The stage whose allocs/iter jumps from ~0 to nonzero is the
// leak.

const BISECT_N: u64 = 4000;

#[test]
fn bisect_decode_only() {
    use aether_translator::decoder::decode_instruction;
    let block = build_block(0x55AA);
    // warm
    for chunk in block.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let _ = decode_instruction(w);
    }
    let (_, c0) = snap();
    for _ in 0..BISECT_N {
        for chunk in block.chunks_exact(4) {
            let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let _ = decode_instruction(w).unwrap();
        }
    }
    let (_, c1) = snap();
    println!("[decode only] allocs/iter = {:.4}", (c1 - c0) as f64 / BISECT_N as f64);
}

#[test]
fn bisect_decode_lift_reused() {
    use aether_translator::decoder::decode_instruction;
    use aether_translator::ir::IrFunction;
    use aether_translator::lift::lift_at;

    let block = build_block(0x55AA);
    let mut func = IrFunction::new(0);

    // replicate translate_block's reuse: reset_single_block + lift each word
    let run_once = |func: &mut IrFunction| {
        let blk = func.reset_single_block(0x1000);
        let mut cur = 0x1000u64;
        for chunk in block.chunks_exact(4) {
            let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let insn = decode_instruction(w).unwrap();
            let _ = lift_at(&insn, blk, cur);
            cur += 4;
        }
    };

    for _ in 0..16 { run_once(&mut func); } // warm
    let (_, c0) = snap();
    for _ in 0..BISECT_N { run_once(&mut func); }
    let (_, c1) = snap();
    println!("[decode+lift reused] allocs/iter = {:.4}", (c1 - c0) as f64 / BISECT_N as f64);
}

#[test]
fn bisect_through_regalloc() {
    use aether_translator::decoder::decode_instruction;
    use aether_translator::ir::IrFunction;
    use aether_translator::lift::lift_at;
    use aether_translator::regalloc::{self, RegallocScratch};

    let block = build_block(0x55AA);
    let mut func = IrFunction::new(0);
    let mut scratch = RegallocScratch::default();

    let run_once = |func: &mut IrFunction, scratch: &mut RegallocScratch| {
        let blk = func.reset_single_block(0x1000);
        let mut cur = 0x1000u64;
        for chunk in block.chunks_exact(4) {
            let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let insn = decode_instruction(w).unwrap();
            let _ = lift_at(&insn, blk, cur);
            cur += 4;
        }
        regalloc::allocate_into(func, scratch);
    };

    for _ in 0..16 { run_once(&mut func, &mut scratch); } // warm
    let (_, c0) = snap();
    for _ in 0..BISECT_N { run_once(&mut func, &mut scratch); }
    let (_, c1) = snap();
    println!("[+regalloc reused] allocs/iter = {:.4}", (c1 - c0) as f64 / BISECT_N as f64);
}

#[test]
fn bisect_through_encode() {
    use aether_translator::backend::{IntLower, X86Encoder};
    use aether_translator::decoder::decode_instruction;
    use aether_translator::ir::{BlockId, IrFunction};
    use aether_translator::lift::lift_at;
    use aether_translator::regalloc::{self, RegallocScratch};

    let block = build_block(0x55AA);
    let mut func = IrFunction::new(0);
    let mut scratch = RegallocScratch::default();
    let mut enc = X86Encoder::new();
    let mut patches: Vec<(usize, BlockId)> = Vec::new();

    let run_once = |func: &mut IrFunction,
                        scratch: &mut RegallocScratch,
                        enc: &mut X86Encoder,
                        patches: &mut Vec<(usize, BlockId)>| {
        let blk = func.reset_single_block(0x1000);
        let mut cur = 0x1000u64;
        for chunk in block.chunks_exact(4) {
            let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let insn = decode_instruction(w).unwrap();
            let _ = lift_at(&insn, blk, cur);
            cur += 4;
        }
        regalloc::allocate_into(func, scratch);
        enc.reset();
        patches.clear();
        for b in &func.blocks {
            IntLower::lower_block_with_pc(b, 0x1000, &scratch.result, enc, patches);
        }
        enc.emit_ret();
    };

    for _ in 0..16 { run_once(&mut func, &mut scratch, &mut enc, &mut patches); } // warm
    let (_, c0) = snap();
    for _ in 0..BISECT_N { run_once(&mut func, &mut scratch, &mut enc, &mut patches); }
    let (_, c1) = snap();
    println!("[+encode reused] allocs/iter = {:.4}", (c1 - c0) as f64 / BISECT_N as f64);
}

#[test]
fn bisect_codebuf_alloc_block() {
    // Isolate the CodeBuf.alloc_block + BlockCache.insert stage: feed a fixed
    // pre-encoded block at DISTINCT PCs, exactly as translate_block does on the
    // cold path. This used to be the leak site (per-call push into the unbounded
    // CodeBuf.blocks Vec); with the registry now cfg(test)-gated out of this
    // integration build, alloc_block only advances the watermark and this stage
    // must be allocation-free.
    use aether_translator::backend::code_buf::CodeBuf;
    use aether_translator::runtime::block_cache::BlockCache;

    // a few valid-looking x86 bytes ending in RET
    let code: Vec<u8> = vec![0x48, 0x31, 0xC0, 0xC3]; // xor rax,rax; ret
    let mut cb = CodeBuf::new(16 * 1024 * 1024);
    let mut bc = BlockCache::new(262144);

    let run_once = |cb: &mut CodeBuf, bc: &mut BlockCache, pc: u64| {
        let off = cb.alloc_block(pc, &code).unwrap();
        cb.commit();
        bc.insert(pc, off, code.len(), true);
    };

    for i in 0..16u64 { run_once(&mut cb, &mut bc, 0x10_0000 + i * 0x40); } // warm
    let (_, c0) = snap();
    for i in 0..BISECT_N { run_once(&mut cb, &mut bc, 0x40_0000 + i * 0x40); }
    let (_, c1) = snap();
    let allocs_per = (c1 - c0) as f64 / BISECT_N as f64;
    println!("[codebuf.alloc_block + cache.insert] allocs/iter = {allocs_per:.4}");
    assert!(
        allocs_per < 0.001,
        "alloc_block must no longer push per-call into an unbounded Vec \
         (allocs_per={allocs_per})"
    );
}

#[test]
fn codebuf_alloc_block_is_bounded() {
    // The former `codebuf_blocks_unbounded_growth` test: it previously read
    // `cb.all_blocks().len()` to show the registry grew by one entry per
    // translate (the leak). The registry is now cfg(test)-gated and absent in
    // this build, so the production behaviour is directly observable: M cold
    // alloc_blocks into a buffer large enough to never hit reset() must leak ~0
    // heap bytes (the arena `Vec<u8>` is pre-sized in `CodeBuf::new`).
    use aether_translator::backend::code_buf::CodeBuf;
    let code: Vec<u8> = vec![0x48, 0x31, 0xC0, 0xC3];
    let mut cb = CodeBuf::new(64 * 1024 * 1024);
    for i in 0..256u64 { cb.alloc_block(0x1000 + i*0x40, &code).unwrap(); } // warm
    let (b0, _) = snap();
    const M: u64 = 100_000;
    for i in 0..M { cb.alloc_block(0x100_0000 + i*0x40, &code).unwrap(); }
    let (b1, _) = snap();
    let bytes_per = (b1 - b0) as f64 / M as f64;
    println!("[codebuf.alloc_block bounded] M={M} Δbytes={} bytes/call={bytes_per:.4}",
        b1 - b0);
    assert!(
        bytes_per < 0.001,
        "alloc_block must not grow the heap per call now (bytes/call={bytes_per})"
    );
}
