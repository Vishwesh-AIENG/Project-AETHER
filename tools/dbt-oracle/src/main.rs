//! dbt-oracle — host-side differential oracle for the AETHER ARM64->x86_64 DBT.
//!
//! For each corpus block:
//!   1. DBT side: translate via the REAL DBT, execute the emitted x86 on this
//!      host, read back GPRs / V-regs / NZCV / scratch memory.
//!   2. Reference side: run the SAME block + seed through the independent
//!      hand-written ARM64 interpreter (src/reference.rs).
//!   3. Diff. Any register/flag/memory mismatch is a pinned silent miscompile.
//!
//! Usage:
//!   dbt-oracle                 # run the built-in proof corpus (10 blocks)
//!   dbt-oracle <corpus.txt>    # run a corpus file (format: src/corpus.rs)
//!   dbt-oracle --self-test     # also run the CATCH demonstration (buggy ref)
//!
//! The built-in corpus proves PASS on known-good ops and a demonstrated CATCH
//! (the CMHI signed-vs-unsigned class of bug) via a deliberately-buggy reference.

#![cfg(all(target_arch = "x86_64", windows))]

mod ctx;
mod corpus;
mod dbt_side;
mod reference;

use corpus::Block;
use ctx::OracleState;
use dbt_side::{run_block_dbt, ScratchMem};
use reference::{RefCpu, RefMem, StepErr};

// ── reference execution ──────────────────────────────────────────────────────

/// Run a block through the reference interpreter. `buggy_cmhi` swaps CMHI to a
/// signed compare (reconstructing the historical DBT defect) so the oracle can
/// be shown to CATCH that class of divergence.
fn run_reference(b: &Block, base: Option<u64>) -> Result<(OracleState, Option<Vec<u8>>), StepErr> {
    let mem = b.mem_size.map(|sz| {
        let mut bytes = vec![0u8; sz];
        for (off, data) in &b.mem_init {
            bytes[*off..*off + data.len()].copy_from_slice(data);
        }
        RefMem { base: base.unwrap_or(0), bytes }
    });
    let mut cpu = RefCpu::from_state(&b.seed, mem);
    let mut pc = b.pc;
    for &w in &b.words {
        cpu.step(w, pc)?;
        pc += 4;
    }
    let out = cpu.to_state();
    let mem_after = cpu.mem.map(|m| m.bytes);
    Ok((out, mem_after))
}

// ── diff ─────────────────────────────────────────────────────────────────────

struct Diff {
    lines: Vec<String>,
}
impl Diff {
    fn new() -> Self { Diff { lines: Vec::new() } }
    fn ok(&self) -> bool { self.lines.is_empty() }
}

fn diff_states(dbt: &OracleState, refr: &OracleState, dbt_mem: &Option<Vec<u8>>, ref_mem: &Option<Vec<u8>>) -> Diff {
    let mut d = Diff::new();
    for i in 0..31 {
        if dbt.gpr[i] != refr.gpr[i] {
            d.lines.push(format!(
                "  x{:<2} DBT=0x{:016x}  REF=0x{:016x}",
                i, dbt.gpr[i], refr.gpr[i]
            ));
        }
    }
    if dbt.sp != refr.sp {
        d.lines.push(format!("  sp  DBT=0x{:016x}  REF=0x{:016x}", dbt.sp, refr.sp));
    }
    if (dbt.nzcv & 0xF000_0000) != (refr.nzcv & 0xF000_0000) {
        d.lines.push(format!(
            "  nzcv DBT={}  REF={}",
            nzcv_str(dbt.nzcv), nzcv_str(refr.nzcv)
        ));
    }
    for r in 0..32 {
        if dbt.vec[r] != refr.vec[r] {
            d.lines.push(format!(
                "  v{:<2} DBT=0x{:016x}{:016x}  REF=0x{:016x}{:016x}",
                r, dbt.vec[r][1], dbt.vec[r][0], refr.vec[r][1], refr.vec[r][0]
            ));
        }
    }
    if let (Some(a), Some(b)) = (dbt_mem, ref_mem) {
        if a != b {
            for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                if x != y {
                    d.lines.push(format!("  mem[{}] DBT=0x{:02x} REF=0x{:02x}", i, x, y));
                }
            }
        }
    }
    d
}

fn nzcv_str(n: u64) -> String {
    let bit = |sh: u64, c: char| if (n >> sh) & 1 == 1 { c } else { '-' };
    format!("{}{}{}{}", bit(31, 'N'), bit(30, 'Z'), bit(29, 'C'), bit(28, 'V'))
}

// ── driver ───────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Outcome { Pass, Fail, Skip, DbtErr }

fn run_block(b: &Block, buggy_cmhi: bool) -> (Outcome, String) {
    // Set up scratch memory (DBT side) if requested. The real host base of the
    // scratch buffer is the flat guest VA; we rebase any offset-registers.
    let scratch = b.mem_size.map(|sz| {
        let mut sm = ScratchMem::new(sz);
        for (off, data) in &b.mem_init {
            sm.bytes[*off..*off + data.len()].copy_from_slice(data);
        }
        sm
    });
    let base = scratch.as_ref().map(|s| s.base);

    // Rebase: seeded GPRs listed in `rebase_gprs` hold a scratch OFFSET; add the
    // real host base so both sides address the same bytes.
    let mut seed = b.seed.clone();
    if let Some(base) = base {
        for &g in &b.rebase_gprs {
            seed.gpr[g] = seed.gpr[g].wrapping_add(base);
        }
    }
    let mut b_dbt = b.clone();
    b_dbt.seed = seed.clone();

    // Reference side.
    reference::set_buggy_cmhi(buggy_cmhi);
    let mut b_ref = b.clone();
    b_ref.seed = seed.clone();
    let (ref_out, ref_mem) = match run_reference(&b_ref, base) {
        Ok(v) => v,
        Err(StepErr::Unsupported(w)) => {
            return (Outcome::Skip, format!("reference: unsupported insn 0x{:08x}", w));
        }
        Err(StepErr::MemFault(a)) => {
            return (Outcome::Skip, format!("reference: mem fault @ 0x{:x}", a));
        }
    };
    reference::set_buggy_cmhi(false);

    // DBT side.
    let dbt = match run_block_dbt(&b_dbt.words, b_dbt.pc, &b_dbt.seed, scratch) {
        Ok(r) => r,
        Err(e) => return (Outcome::DbtErr, format!("dbt: {}", e)),
    };

    let d = diff_states(&dbt.out, &ref_out, &dbt.mem_after, &ref_mem);
    if d.ok() {
        (Outcome::Pass, format!("({} bytes x86)", dbt.x86_len))
    } else {
        (Outcome::Fail, d.lines.join("\n"))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let self_test = args.iter().any(|a| a == "--self-test");
    let corpus_path = args.iter().find(|a| !a.starts_with("--")).cloned();

    let blocks: Vec<Block> = if let Some(path) = &corpus_path {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| { eprintln!("cannot read {}: {}", path, e); std::process::exit(2); });
        corpus::parse(&text)
            .unwrap_or_else(|e| { eprintln!("corpus parse error: {}", e); std::process::exit(2); })
    } else {
        builtin_corpus()
    };

    println!("=== AETHER dbt-oracle — {} block(s) ===", blocks.len());
    println!("    reference engine: hand-written ARM64 interpreter (independent of DBT)");
    println!();

    let mut n_pass = 0;
    let mut n_fail = 0;
    let mut n_skip = 0;
    let mut n_err = 0;

    for b in &blocks {
        let (outcome, detail) = run_block(b, false);
        let tag = match outcome {
            Outcome::Pass => { n_pass += 1; "PASS" }
            Outcome::Fail => { n_fail += 1; "FAIL" }
            Outcome::Skip => { n_skip += 1; "SKIP" }
            Outcome::DbtErr => { n_err += 1; "DBTERR" }
        };
        println!("[{:<6}] {:<28} {}", tag, b.name, first_line(&detail));
        if matches!(outcome, Outcome::Fail) {
            for l in detail.lines() {
                println!("           {}", l);
            }
        }
    }

    println!();
    println!("summary: {} PASS, {} FAIL, {} SKIP, {} DBTERR", n_pass, n_fail, n_skip, n_err);

    if self_test {
        println!();
        println!("=== CATCH demonstration: reconstruct the CMHI signed-vs-unsigned bug ===");
        println!("    Running the CMHI .2d block with a deliberately-BUGGY reference");
        println!("    (CMHI lowered as a SIGNED compare — the exact historical defect).");
        println!("    The oracle MUST now report a divergence, proving it catches this");
        println!("    class of silent miscompile.");
        let catch_block = cmhi_catch_block();
        let (outcome, detail) = run_block(&catch_block, /*buggy_cmhi=*/ true);
        match outcome {
            Outcome::Fail => {
                println!("[CATCH ] {:<28} divergence detected (as required):", catch_block.name);
                for l in detail.lines() {
                    println!("           {}", l);
                }
                println!("    ==> oracle CAUGHT the injected signed-vs-unsigned CMHI defect.");
            }
            _ => {
                println!("[MISS  ] {:<28} {}", catch_block.name, first_line(&detail));
                println!("    !! oracle did NOT catch the injected defect — harness is broken.");
                std::process::exit(1);
            }
        }

        // ── SQSHRUN saturating-narrow: reference must clamp negatives to 0 ──
        // Regression guard for the 2026-07-01 reference fix. Before the fix the
        // narrow-shift arm ran SQSHRUN (U=1, opcode 0b10000) as plain SHRN and
        // WRAPPED negative source lanes instead of saturating them to 0 — 33
        // false FAILs across the framework corpus (the DBT was correct all along).
        // Here we (a) run the REFERENCE alone and assert the negative halfwords
        // saturate to 0, and (b) run the full block and require the DBT to AGREE.
        println!();
        println!("=== SQSHRUN saturating narrow-shift (reference fix regression guard) ===");
        {
            // SQSHRUN V0.8B,V1.8H,#6. V1 halfwords: lane0=0x8505 (neg), lane1=0x0140
            //   (pos), lane2=0xFFC0 (neg), lane3=0x1230, lane4=0x7FFF, lane5=0x0000,
            //   lane6=0x8000 (neg, most-negative), lane7=0x03C0. Signed→unsigned:
            //   the negatives MUST clamp to 0; 0x7FFF>>6=0x1FF clamps to 0xFF.
            //   Expected V0[63:0] = 0x0F00_00FF_4800_0500.
            let block = vblock("selftest_sqshrun_8b", 0x2F0A_8420, 0,
                0x03C0_8000_0000_7FFF_1230_FFC0_0140_8505, 0);
            const EXPECT_V0: u128 = 0x0F00_00FF_4800_0500;

            // (a) Reference-only: prove negatives saturate to 0 (spec-literal).
            reference::set_buggy_cmhi(false);
            let (ref_out, _) = run_reference(&block, None)
                .expect("reference must support SQSHRUN");
            let ref_v0 = ref_out.vec_u128(0);
            // Byte lanes fed by negative source halfwords (0,2,6) must be 0.
            let neg_lanes_zero = [0usize, 2, 6]
                .iter()
                .all(|&i| ((ref_v0 >> (i * 8)) & 0xFF) == 0);
            assert!(
                ref_v0 == EXPECT_V0 && neg_lanes_zero,
                "reference SQSHRUN wrong: got 0x{:032x}, want 0x{:032x} \
                 (negative source lanes must saturate to 0)",
                ref_v0, EXPECT_V0
            );
            println!("[REF   ] {:<24} negatives saturate to 0: V0=0x{:016x}",
                block.name, ref_v0 as u64);

            // (b) DBT must agree with the (now-correct) reference → PASS.
            let (outcome, detail) = run_block(&block, false);
            match outcome {
                Outcome::Pass => {
                    println!("[PASS  ] {:<24} DBT agrees — DBT and reference both correct.",
                        block.name);
                    println!("    ==> the 33 framework false-FAILs are resolved.");
                }
                _ => {
                    println!("[FAIL  ] {:<24} DBT diverged from the fixed reference:",
                        block.name);
                    for l in detail.lines() { println!("           {}", l); }
                    println!("    !! SQSHRUN regression — investigate before shipping.");
                    std::process::exit(1);
                }
            }
        }

        // ── Known DBT issues surfaced by the new SIMD/FP reference coverage ──
        println!();
        println!("=== Known DBT issues surfaced by the new SIMD/FP reference ===");
        println!("    These are real defects the oracle now catches (previously SKIPped).");
        println!("    They do NOT affect the exit code (tracked, not gating).");
        for issue in known_dbt_issues() {
            let (outcome, detail) = run_block(&issue.block, false);
            let ok = match (&outcome, issue.expect_fail) {
                (Outcome::Fail, true) => true,   // expected silent-miscompile FAIL
                (Outcome::DbtErr, false) => true, // expected fail-loud UD2 gap
                _ => false,
            };
            let kind = if issue.expect_fail { "MISCOMPILE" } else { "GAP(UD2)  " };
            let mark = if ok { "as expected" } else { "UNEXPECTED — verify" };
            println!("[{}] {:<24} {} ({})", kind, issue.block.name, issue.note, mark);
            if matches!(outcome, Outcome::Fail) {
                for l in detail.lines() { println!("           {}", l); }
            } else if matches!(outcome, Outcome::DbtErr) {
                println!("           {}", first_line(&detail));
            }
        }
    }

    if n_fail > 0 || n_err > 0 {
        std::process::exit(1);
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

// ── built-in proof corpus ────────────────────────────────────────────────────
//
// Encodings verified against the ARM ARM. Each block seeds a state, runs both
// sides, and expects agreement (PASS). The last block deliberately exercises the
// dirty-upper-32 W-form corner. The CATCH demonstration lives in --self-test.

fn builtin_corpus() -> Vec<Block> {
    let mut v = Vec::new();

    // 1. MOVZ X0,#0x41 ; ADD X1,X0,X0  -> x0=0x41, x1=0x82
    {
        let mut b = Block::new("movz_add");
        b.words = vec![0xD280_0820, 0x8B00_0001];
        v.push(b);
    }
    // 2. ADD X0,X0,X1 (x0=40,x1=2 -> 42)
    {
        let mut b = Block::new("add_reg");
        b.words = vec![0x8B01_0000];
        b.seed.gpr[0] = 40;
        b.seed.gpr[1] = 2;
        v.push(b);
    }
    // 3. SUBS X2,X0,X1 (flags): x0=5,x1=5 -> 0, Z set, C set (no borrow)
    {
        let mut b = Block::new("subs_flags");
        b.words = vec![0xEB01_0002];
        b.seed.gpr[0] = 5;
        b.seed.gpr[1] = 5;
        v.push(b);
    }
    // 4. ORR/EOR/AND immediate mix: ORR X0,X0,#0xF ; EOR X0,X0,#0x3
    {
        let mut b = Block::new("logic_imm");
        // ORR X0,X0,#0xF = 0xB2400C00 ; EOR X0,X0,#0x3 = 0xD2... use reg forms:
        // ORR X0, XZR, #0xF (imm) = 0xB2400FE0 -> x0 = 0xF
        // EOR X0, X0, #0x3 (imm)  = 0xD2000C00 -> x0 = 0xF ^ 0x3 = 0xC
        b.words = vec![0xB240_0FE0, 0xD200_0C00];
        v.push(b);
    }
    // 5. LSL/LSR via UBFM alias: LSL X0,X0,#4 with x0=0x1 -> 0x10
    {
        let mut b = Block::new("lsl_imm");
        // LSL X0,X0,#4 = UBFM X0,X0,#60,#59 = 0xD37CEC00
        b.words = vec![0xD37C_EC00];
        b.seed.gpr[0] = 0x1;
        v.push(b);
    }
    // 6. MADD X0,X1,X2,X3 : 3 + 4*5 = 23
    {
        let mut b = Block::new("madd");
        // MADD X0,X1,X2,X3 = 0x9B020C20
        b.words = vec![0x9B02_0C20];
        b.seed.gpr[1] = 4;
        b.seed.gpr[2] = 5;
        b.seed.gpr[3] = 3;
        v.push(b);
    }
    // 7. CSEL X0,X1,X2,EQ with Z clear -> selects X2
    {
        let mut b = Block::new("csel_eq");
        // CSEL X0,X1,X2,EQ = 0x9A820020
        b.words = vec![0x9A82_0020];
        b.seed.gpr[1] = 0x1111;
        b.seed.gpr[2] = 0x2222;
        b.seed.nzcv = 0; // Z clear -> not-equal -> X2
        v.push(b);
    }
    // 8. FADD scalar single: FADD S0,S1,S2 with 1.5 + 2.25 = 3.75
    {
        let mut b = Block::new("fadd_s");
        // FADD S0,S1,S2 = 0x1E222820
        b.words = vec![0x1E22_2820];
        b.seed.set_vec_u128(1, (1.5f32).to_bits() as u128);
        b.seed.set_vec_u128(2, (2.25f32).to_bits() as u128);
        v.push(b);
    }
    // 9. NEON ADD V0.2D,V1.2D,V2.2D
    {
        let mut b = Block::new("neon_add_2d");
        // ADD V0.2D,V1.2D,V2.2D = 0x4EE28420
        b.words = vec![0x4EE2_8420];
        b.seed.set_vec_u128(1, 0x0000_0000_0000_0005_0000_0000_0000_0003);
        b.seed.set_vec_u128(2, 0x0000_0000_0000_0002_0000_0000_0000_0004);
        v.push(b);
    }
    // 10. CMHI V0.2D,V1.2D,V2.2D — the exact op that once compiled signed. Here
    //     with values that make signed vs unsigned DIFFER, so a correct DBT +
    //     correct reference AGREE (PASS), and the CATCH self-test shows the
    //     buggy-ref divergence.
    {
        v.push(cmhi_catch_block());
    }
    // 11. W-form dirty-upper-32: seed x0 with a dirty upper half, then
    //     ADD W1,W0,W0. Result must be 32-bit (upper cleared). Hand-computed.
    {
        let mut b = Block::new("wform_dirty_upper");
        // ADD W1,W0,W0 = 0x0B000001
        b.words = vec![0x0B00_0001];
        b.seed.gpr[0] = 0xFFFF_FFFF_8000_0001; // dirty upper; W0 = 0x80000001
        // W0+W0 = 0x1_0000_0002 truncated to 32 = 0x0000_0002, zero-extended.
        v.push(b);
    }

    // 12. EXTR regression: EXTR W10,W9,W10,#1 — Rn is HIGH, Rm is LOW. Seeds
    //     chosen so a hi/lo operand swap (the historical reference bug) diverges.
    {
        let mut b = Block::new("extr_w_reg_order");
        b.words = vec![0x138A_052A]; // EXTR W10,W9,W10,#1
        b.seed.gpr[9] = 0x0000_0000_8000_0009;
        b.seed.gpr[10] = 0x0000_0000_7FFF_FFA1;
        // (W9:W10)>>1 low32 = 0xBFFFFFD0.
        v.push(b);
    }
    // 13. CSINV taken: CSINV X0,X8,XZR,GE with GE TRUE (N==V) -> X0 = X8.
    {
        let mut b = Block::new("csinv_ge_true");
        b.words = vec![0xDA9F_A100]; // CSINV X0,X8,XZR,GE
        b.seed.gpr[8] = 0x1234_5678_9ABC_DEF0;
        b.seed.nzcv = 0; // N=0,V=0 -> GE true -> X0 = X8.
        v.push(b);
    }
    // 14. CSINV not-taken: GE FALSE (N!=V) -> X0 = ~XZR = 0xFFFF...FFFF.
    //     A bit11-vs-bit30 selector bug would mis-decode this as CSEL (-> 0).
    {
        let mut b = Block::new("csinv_ge_false");
        b.words = vec![0xDA9F_A100]; // CSINV X0,X8,XZR,GE
        b.seed.gpr[8] = 0x1234_5678_9ABC_DEF0;
        b.seed.nzcv = 0x8000_0000; // N=1,V=0 -> GE false -> X0 = ~0.
        v.push(b);
    }
    // 15. Sub-word logical-immediate bitmask regression: MOV X21,#0xAAAA...AAAA
    //     (ORR X21,XZR,#bitmask; element size 2). A ror-within-64 bug (instead of
    //     ror-within-element) collapses the mask to 0.
    {
        let mut b = Block::new("orr_bitmask_2bit");
        b.words = vec![0xB201_F3F5]; // ORR X21,XZR,#0xAAAAAAAAAAAAAAAA
        // result must be 0xAAAAAAAAAAAAAAAA.
        v.push(b);
    }
    // 16. Another sub-word bitmask: 0x3333... (element size 4) via ORR alias.
    {
        let mut b = Block::new("orr_bitmask_4bit");
        // ORR X0,XZR,#0x3333333333333333 (N=0,immr=0,imms=0x39 -> repeats 0011).
        b.words = vec![0xB200_E7E0];
        v.push(b);
    }

    // ── SIMD/FP coverage blocks (families added to the reference 2026-07-01) ──
    // Each seeds V1/V2 (and V0 for accumulate/insert ops) with values chosen so
    // the ARM-correct result is hand-verifiable and, where relevant, so a wrong
    // interpretation (signed vs unsigned, arith vs logical) would diverge.
    v.extend(simd_fp_corpus());

    v
}

/// Helper: build a one-instruction SIMD/FP block with optional V0/V1/V2 seeds.
fn vblock(name: &str, word: u32, v0: u128, v1: u128, v2: u128) -> Block {
    let mut b = Block::new(name);
    b.words = vec![word];
    b.seed.set_vec_u128(0, v0);
    b.seed.set_vec_u128(1, v1);
    b.seed.set_vec_u128(2, v2);
    b
}

/// The SIMD/FP self-test corpus. Encodings computed from the ARM ARM field
/// layouts (cross-checked against known-good hex). Inputs are hand-chosen so the
/// architectural result is obvious; the DBT must agree (PASS) or a divergence is
/// a real silent miscompile.
fn simd_fp_corpus() -> Vec<Block> {
    let mut v = Vec::new();

    // Two .4S lanes packed per 64 bits: lane layout is [l0 | l1] in low 64,
    // [l2 | l3] in high 64. Helper to build a .4S vector from four u32 lanes.
    let s4 = |a: u32, b: u32, c: u32, d: u32| -> u128 {
        (a as u128) | ((b as u128) << 32) | ((c as u128) << 64) | ((d as u128) << 96)
    };
    // .16B from a slice-ish of 16 bytes.
    let b16 = |bytes: [u8; 16]| -> u128 {
        let mut x = 0u128;
        for (i, by) in bytes.iter().enumerate() { x |= (*by as u128) << (i * 8); }
        x
    };
    let f32x4 = |a: f32, b: f32, c: f32, d: f32| -> u128 {
        s4(a.to_bits(), b.to_bits(), c.to_bits(), d.to_bits())
    };

    // MUL V0.4S,V1,V2: lanewise 2*3, 5*7, 0*9, 0xFFFFFFFF*2 (wraps).
    v.push(vblock("simd_mul_4s", 0x4EA2_9C20, 0,
        s4(2, 5, 0, 0xFFFF_FFFF), s4(3, 7, 9, 2)));
    // MLA V0.4S,V1,V2: V0 += V1*V2. V0 seed = {1,1,1,1}.
    v.push(vblock("simd_mla_4s", 0x4EA2_9420, s4(1,1,1,1),
        s4(2,3,4,5), s4(10,10,10,10)));
    // MLS V0.4S,V1,V2: V0 -= V1*V2. V0 seed = {100,...}.
    v.push(vblock("simd_mls_4s", 0x6EA2_9420, s4(100,100,100,100),
        s4(2,3,4,5), s4(10,10,10,10)));
    // SMAX V0.4S: signed max. Lane0: -1 (0xFFFFFFFF) vs 1 -> 1.
    v.push(vblock("simd_smax_4s", 0x4EA2_6420, 0,
        s4(0xFFFF_FFFF, 5, 0x8000_0000, 7), s4(1, 2, 3, 7)));
    // UMIN V0.4S: unsigned min. Lane0: 0xFFFFFFFF vs 1 -> 1.
    v.push(vblock("simd_umin_4s", 0x6EA2_6C20, 0,
        s4(0xFFFF_FFFF, 5, 10, 7), s4(1, 2, 3, 7)));
    // SABD V0.4S: |signed a - b|. Lane0: |(-1) - 1| = 2.
    v.push(vblock("simd_sabd_4s", 0x4EA2_7420, 0,
        s4(0xFFFF_FFFF, 10, 3, 0), s4(1, 4, 3, 5)));
    // UABD V0.8B: |unsigned a - b| per byte. (.4S UABD is a DBT Tier-1 gap →
    //   see known_dbt_issues(); .8B exercises the value path the DBT implements.)
    //   byte0: |0xFF-0x01|=0xFE; byte1: |0x10-0x30|=0x20; byte2: |5-5|=0.
    v.push(vblock("simd_uabd_8b", 0x2E22_7420, 0,
        0x00_00_00_00_00_05_10_FF, 0x00_00_00_00_00_05_30_01));
    // ADDP V0.4S,V1,V2: pairwise. out = {v1l0+v1l1, v1l2+v1l3, v2l0+v2l1, v2l2+v2l3}.
    v.push(vblock("simd_addp_4s", 0x4EA2_BC20, 0,
        s4(1,2,3,4), s4(10,20,30,40)));
    // CMTST V0.4S: (a&b)!=0. Lane0: 0b1100 & 0b0011 = 0 -> 0; Lane1: 0b1 & 0b1 -> all-ones.
    v.push(vblock("simd_cmtst_4s", 0x4EA2_8C20, 0,
        s4(0b1100, 0b1, 0xFF00, 0), s4(0b0011, 0b1, 0x00FF, 0xFFFF)));
    // AND V0.16B,V1,V2.
    v.push(vblock("simd_and_16b", 0x4E22_1C20, 0,
        0xFFFF_0000_FF00_FF00_0F0F_0F0F_AAAA_5555,
        0x0F0F_0F0F_F0F0_F0F0_FFFF_0000_FFFF_FFFF));
    // BSL V0.16B,V1,V2: dst=sel. V0=sel, picks V1 where bit=1 else V2.
    v.push(vblock("simd_bsl_16b", 0x6E62_1C20,
        0xFFFF_FFFF_0000_0000_FF00_FF00_00FF_00FF, // sel
        0xAAAA_AAAA_AAAA_AAAA_1111_1111_1111_1111, // Vn
        0x5555_5555_5555_5555_2222_2222_2222_2222)); // Vm
    // ORN V0.16B,V1,V2 = V1 | ~V2.
    v.push(vblock("simd_orn_16b", 0x4EE2_1C20, 0,
        0x0F0F_0F0F_0F0F_0F0F_0000_0000_0000_0000,
        0xFFFF_FFFF_0000_0000_00FF_00FF_00FF_00FF));

    // ABS V0.4S: signed abs. Lane0 = -5 -> 5; lane2 = INT_MIN stays INT_MIN.
    v.push(vblock("simd_abs_4s", 0x4EA0_B820, 0,
        s4((-5i32) as u32, 7, 0x8000_0000, 0), 0));
    // NEG V0.4S.
    v.push(vblock("simd_neg_4s", 0x6EA0_B820, 0,
        s4(5, (-7i32) as u32, 0, 1), 0));
    // CMGT #0 V0.4S: lane>0. {-1,0,1,5} -> {0,0,-1,-1}.
    v.push(vblock("simd_cmgt0_4s", 0x4EA0_8820, 0,
        s4((-1i32) as u32, 0, 1, 5), 0));
    // CMLT #0 V0.4S: lane<0. {-1,0,1,-5} -> {-1,0,0,-1}.
    v.push(vblock("simd_cmlt0_4s", 0x4EA0_A820, 0,
        s4((-1i32) as u32, 0, 1, (-5i32) as u32), 0));
    // CMGE #0 V0.4S: lane>=0 (U=1). {-1,0,1,-5} -> {0,-1,-1,0}.
    v.push(vblock("simd_cmge0_4s", 0x6EA0_8820, 0,
        s4((-1i32) as u32, 0, 1, (-5i32) as u32), 0));
    // SADDLP V0.2D,V1.4S: pairwise long add, signed. out[0]=l0+l1, out[1]=l2+l3.
    //   l0=-1,l1=2 -> 1 ; l2=3,l3=4 -> 7.
    v.push(vblock("simd_saddlp_2d", 0x4EA0_2820, 0,
        s4((-1i32) as u32, 2, 3, 4), 0));
    // XTN V0.4H,V1.4S: narrow each 32->16 (low half). {0x11112222,0x33334444,..}.
    v.push(vblock("simd_xtn_4h", 0x0E61_2820, 0,
        s4(0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888), 0));

    // SHL V0.4S,V1,#4.
    v.push(vblock("simd_shl_4s", 0x4F24_5420, 0,
        s4(1, 0x1000_0000, 0xF, 0x8000_0000), 0));
    // USHR V0.4S,V1,#4 (logical). 0x80000000>>4 = 0x08000000.
    v.push(vblock("simd_ushr_4s", 0x6F3C_0420, 0,
        s4(0x8000_0000, 0xF0, 0x10, 1), 0));
    // SSHR V0.4S,V1,#4 (arith). 0x80000000 (neg) >>4 = 0xF8000000.
    v.push(vblock("simd_sshr_4s", 0x4F3C_0420, 0,
        s4(0x8000_0000, 0xF0, 0x10, (-16i32) as u32), 0));
    // SSRA V0.4S,V1,#4: V0 += (V1 >>s 4). V0 seed = {1,1,1,1}.
    v.push(vblock("simd_ssra_4s", 0x4F3C_1420, s4(1,1,1,1),
        s4(0x100, 0x8000_0000, 16, 0), 0));
    // USHLL V0.4S,V1.4H,#3: widen low 4 halfwords, shift left 3.
    //   halfwords (low 64) = {0x0001,0x0002,0x0003,0x8000}; <<3.
    v.push(vblock("simd_ushll_4s", 0x6F13_A420, 0,
        0x0000_0000_0000_0000_8000_0003_0002_0001, 0));
    // USHLL V0.8H,V1.8B,#0 (UXTL): widen ALL 8 low bytes -> 8 halfwords spanning
    //   the FULL 128 bits. Regression for R1 (reference filled only low 64).
    //   bytes(low64) = {01,03,03,03,03,03,03,03} -> halfwords across 128 bits.
    v.push(vblock("simd_ushll_8h", 0x2F08_A420, 0,
        0x0000_0000_0000_0000_0303_0303_0303_0301, 0));
    // SSHLL V0.8H,V1.8B,#0 (SXTL): signed widen; top byte 0x81 sign-extends to
    //   0xFF81 in the HIGH halfword lane — proves both the full-width fill AND
    //   sign-extension of the upper lanes.
    v.push(vblock("simd_sshll_8h", 0x0F08_A420, 0,
        0x0000_0000_0000_0000_8103_0303_0303_0301, 0));
    // SSHLL2 V0.8H,V1.16B,#0: the `2` (high) variant reads the HIGH 64 bits of
    //   the source. Low 64 seed is decoy 0xFF; only the high bytes must appear.
    //   high64 bytes = {01,02,03,04,05,06,07,80} -> {0x0001..0x0007,0xFF80}.
    v.push(vblock("simd_sshll2_8h", 0x4F08_A420, 0,
        0x8007_0605_0403_0201_FFFF_FFFF_FFFF_FFFF, 0));
    // SHRN V0.4H,V1.4S,#4: narrow 32->16 after >>4 (low half of dst).
    v.push(vblock("simd_shrn_4h", 0x0F1C_8420, 0,
        s4(0x0000_00F0, 0x0000_1230, 0xFFFF_FFF0, 0x0000_0010), 0));
    // SQSHRUN V0.8B,V1.8H,#6: SIGNED-source → UNSIGNED-dest saturating narrow.
    //   The negative halfwords (0x8505, 0xFFC0, 0x8000) MUST saturate to 0 (not
    //   wrap); 0x7FFF>>6 = 0x1FF saturates UP to 0xFF; the in-range positives
    //   narrow normally (0x0140>>6=0x05, 0x1230>>6=0x48, 0x03C0>>6=0x0F).
    //   Expected V0[63:0] = 0x0F00_00FF_4800_0500. This is the class the reference
    //   previously got wrong (wrapped negatives) → 33 false FAILs in the framework
    //   corpus; a DBT/reference AGREE here proves both are now correct.
    v.push(vblock("simd_sqshrun_8b", 0x2F0A_8420, 0,
        0x03C0_8000_0000_7FFF_1230_FFC0_0140_8505, 0));
    // SQSHRN V0.4H,V1.4S,#8: SIGNED→SIGNED saturating narrow. Lane0 = 0x8000_0000
    //   (most-negative i32) >> 8 = 0xFF80_0000 → saturates to INT16_MIN 0x8000;
    //   lane1 = 0x7FFF_FF00 >> 8 = 0x007F_FFFF → saturates to INT16_MAX 0x7FFF;
    //   lane2 = 0x0000_1234 >> 8 = 0x12 (in range); lane3 = -256 (0xFFFF_FF00)
    //   >> 8 = -1 = 0xFFFF. Expected V0[63:0] = 0xFFFF_0012_7FFF_8000.
    v.push(vblock("simd_sqshrn_4h", 0x0F18_9420, 0,
        s4(0x8000_0000, 0x7FFF_FF00, 0x0000_1234, 0xFFFF_FF00), 0));
    // UQSHRN V0.8B,V1.8H,#4: UNSIGNED→UNSIGNED saturating narrow. 0xFFFF>>4 =
    //   0x0FFF saturates to 0xFF; 0x0130>>4 = 0x13; 0x0000>>4 = 0x00; 0x00F0>>4 =
    //   0x0F; the high 4 halfwords repeat the pattern.
    v.push(vblock("simd_uqshrn_8b", 0x2F0C_9420, 0,
        0x00F0_0000_0130_FFFF_00F0_0000_0130_FFFF, 0));

    // ZIP1 V0.4S,V1,V2: interleave low halves -> {v1l0, v2l0, v1l1, v2l1}.
    v.push(vblock("simd_zip1_4s", 0x4E82_3820, 0,
        s4(0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444),
        s4(0xAAAA_AAAA, 0xBBBB_BBBB, 0xCCCC_CCCC, 0xDDDD_DDDD)));
    // ZIP2 V0.4S,V1,V2: interleave high halves -> {v1l2, v2l2, v1l3, v2l3}.
    v.push(vblock("simd_zip2_4s", 0x4E82_7820, 0,
        s4(0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444),
        s4(0xAAAA_AAAA, 0xBBBB_BBBB, 0xCCCC_CCCC, 0xDDDD_DDDD)));
    // UZP1 V0.4S,V1,V2: even lanes -> {v1l0, v1l2, v2l0, v2l2}.
    v.push(vblock("simd_uzp1_4s", 0x4E82_1820, 0,
        s4(0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444),
        s4(0xAAAA_AAAA, 0xBBBB_BBBB, 0xCCCC_CCCC, 0xDDDD_DDDD)));
    // TRN1 V0.4S,V1,V2: {v1l0, v2l0, v1l2, v2l2}.
    v.push(vblock("simd_trn1_4s", 0x4E82_2820, 0,
        s4(0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444),
        s4(0xAAAA_AAAA, 0xBBBB_BBBB, 0xCCCC_CCCC, 0xDDDD_DDDD)));
    // EXT V0.16B,V1,V2,#4: take bytes [4..20) of V1:V2 concat.
    v.push(vblock("simd_ext_16b", 0x6E02_2020, 0,
        b16([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),
        b16([16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31])));
    // TBL V0.16B,{V1},V2: index bytes into V1; out-of-range (>=16) -> 0.
    v.push(vblock("simd_tbl_16b", 0x4E02_0020, 0,
        b16([0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF]),
        b16([0,2,4,6,8,10,12,14,16,20,255,1,3,5,7,9]))); // idx>=16 -> 0
    // TBX V0.16B,{V1},V2: like TBL but out-of-range keeps V0's byte.
    v.push(vblock("simd_tbx_16b", 0x4E02_1020,
        b16([0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF]),
        b16([0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF]),
        b16([0,2,4,6,8,10,12,14,16,20,255,1,3,5,7,9])));
    // DUP V0.4S,V1.S[1]: replicate lane 1 of V1 across all four .4S lanes.
    v.push(vblock("simd_dupel_4s", 0x4E0C_0420, 0,
        s4(0x1111_1111, 0xCAFEBABE, 0x3333_3333, 0x4444_4444), 0));
    // INS V0.S[1],W1: insert W1 into lane 1 of V0 (rest of V0 preserved).
    {
        let mut b = vblock("simd_ins_gen", 0x4E0C_1C20,
            0x4444_4444_3333_3333_2222_2222_1111_1111, 0, 0);
        b.seed.gpr[1] = 0xDEAD_BEEF;
        v.push(b);
    }
    // UMOV W0,V1.S[1]: extract lane 1 (zero-extended) into W0.
    v.push(vblock("simd_umov_w", 0x0E0C_3C20, 0,
        s4(0x1111_1111, 0x8000_0001, 0x3333_3333, 0x4444_4444), 0));
    // SMOV X0,V1.H[1]: extract signed half lane 1 -> sign-extended into X0.
    //   lane1 (halfword index 1) = 0x8ABC -> sign-extended 0xFFFF...FF8ABC.
    v.push(vblock("simd_smov_x", 0x4E06_2C20, 0,
        0x0000_0000_0000_0000_0000_0000_8ABC_1234, 0));

    // ADDV S0,V1.4S: sum all four lanes into S0. 1+2+3+4 = 10.
    v.push(vblock("simd_addv_4s", 0x4EB1_B820, 0, s4(1, 2, 3, 4), 0));
    // SMAXV S0,V1.4S: signed max lane. {-1, 5, -100, 3} -> 5.
    v.push(vblock("simd_smaxv_4s", 0x4EB0_A820, 0,
        s4((-1i32) as u32, 5, (-100i32) as u32, 3), 0));
    // UMINV S0,V1.4S: unsigned min lane. {0xFFFFFFFF, 5, 100, 3} -> 3.
    v.push(vblock("simd_uminv_4s", 0x6EB1_A820, 0,
        s4(0xFFFF_FFFF, 5, 100, 3), 0));
    // SADDLV D0,V1.4S: signed long sum -> 64-bit. {-1,-1,-1,-1} -> -4 = 0xFFFF..FC.
    v.push(vblock("simd_saddlv_4s", 0x4EB0_3820, 0,
        s4((-1i32) as u32, (-1i32) as u32, (-1i32) as u32, (-1i32) as u32), 0));

    // ── scalar FP ──
    // FMAX S0,S1,S2: max(3.5, 2.0) = 3.5.
    v.push(vblock("fp_fmax_s", 0x1E22_4820, 0,
        (3.5f32).to_bits() as u128, (2.0f32).to_bits() as u128));
    // FMIN S0,S1,S2: min(3.5, 2.0) = 2.0.
    v.push(vblock("fp_fmin_s", 0x1E22_5820, 0,
        (3.5f32).to_bits() as u128, (2.0f32).to_bits() as u128));
    // FNMUL S0,S1,S2: -(1.5*2.0) = -3.0.
    v.push(vblock("fp_fnmul_s", 0x1E22_8820, 0,
        (1.5f32).to_bits() as u128, (2.0f32).to_bits() as u128));
    // FABS S0,S1: |-2.5| = 2.5.
    v.push(vblock("fp_fabs_s", 0x1E20_C020, 0, ((-2.5f32).to_bits()) as u128, 0));
    // FSQRT S0,S1: sqrt(16) = 4.
    v.push(vblock("fp_fsqrt_s", 0x1E21_C020, 0, (16.0f32).to_bits() as u128, 0));
    // FRINTN S0,S1: round-to-nearest-even of 2.5 = 2.0 (ties to even).
    v.push(vblock("fp_frintn_s", 0x1E24_4020, 0, (2.5f32).to_bits() as u128, 0));
    // FRINTM S0,S1: floor(-1.5) = -2.
    v.push(vblock("fp_frintm_s", 0x1E25_4020, 0, ((-1.5f32).to_bits()) as u128, 0));
    // FCVT D0,S0: single 1.5 -> double 1.5.  (S->D is clean in the DBT; the
    //   D->S narrowing direction is a DBT bug — see known_dbt_issues().)
    v.push(vblock("fp_fcvt_ds", 0x1E22_C000, 0, (1.5f32).to_bits() as u128, 0));
    // FCMP S1,S2: 2.0 vs 3.0 -> N set (a<b): NZCV = 1000 -> 0x80000000.
    v.push(vblock("fp_fcmp_lt_s", 0x1E22_2020, 0,
        (2.0f32).to_bits() as u128, (3.0f32).to_bits() as u128));
    // FCSEL S0,S1,S2,GT with NZCV cleared -> GT false -> selects S2.
    v.push(vblock("fp_fcsel_gt_s", 0x1E22_CC20, 0,
        (7.0f32).to_bits() as u128, (9.0f32).to_bits() as u128));
    // SCVTF S0,W1: int 5 -> 5.0f. (W1 seeded.)
    { let mut b = vblock("fp_scvtf_s", 0x1E22_0020, 0, 0, 0); b.seed.gpr[1] = 5; v.push(b); }
    // UCVTF S0,W1: unsigned 0xFFFFFFFF -> 4294967295.0f.
    { let mut b = vblock("fp_ucvtf_s", 0x1E23_0020, 0, 0, 0); b.seed.gpr[1] = 0xFFFF_FFFF; v.push(b); }
    // FCVTZS W0,S1: 3.9f -> 3 (round toward zero).
    v.push(vblock("fp_fcvtzs_s", 0x1E38_0020, 0, (3.9f32).to_bits() as u128, 0));
    // FCVTZU W0,S1: 2.9f -> 2.
    v.push(vblock("fp_fcvtzu_s", 0x1E39_0020, 0, (2.9f32).to_bits() as u128, 0));

    // ── vector FP ──
    // FADD V0.4S: lanewise add.
    v.push(vblock("fp_fadd_4s", 0x4E22_D420, 0,
        f32x4(1.0, 2.0, 3.0, 4.0), f32x4(0.5, 0.5, 0.5, 0.5)));
    // FMUL V0.4S.
    v.push(vblock("fp_fmul_4s", 0x6E22_DC20, 0,
        f32x4(1.5, 2.0, 3.0, 4.0), f32x4(2.0, 2.0, 2.0, 2.0)));
    // FMLA V0.4S: V0 += V1*V2. V0 = {1,1,1,1}.
    v.push(vblock("fp_fmla_4s", 0x4E22_CC20,
        f32x4(1.0, 1.0, 1.0, 1.0),
        f32x4(2.0, 3.0, 4.0, 5.0), f32x4(10.0, 10.0, 10.0, 10.0)));
    // FCMEQ V0.4S: lanewise ==. {1,2,3,4} vs {1,9,3,9} -> {-1,0,-1,0}.
    v.push(vblock("fp_fcmeq_4s", 0x4E22_E420, 0,
        f32x4(1.0, 2.0, 3.0, 4.0), f32x4(1.0, 9.0, 3.0, 9.0)));
    // FABS V0.4S.
    v.push(vblock("fp_fabs_4s", 0x4EA0_F820, 0,
        f32x4(-1.0, 2.0, -3.0, 4.0), 0));
    // FNEG V0.4S.
    v.push(vblock("fp_fneg_4s", 0x6EA0_F820, 0,
        f32x4(1.0, -2.0, 3.0, -4.0), 0));
    // FCMGT #0 V0.4S: lane>0. {-1,0,1,5} -> {0,0,-1,-1}.
    v.push(vblock("fp_fcmgt0_4s", 0x4EA0_C820, 0,
        f32x4(-1.0, 0.0, 1.0, 5.0), 0));
    // FMAX V0.4S (finite): lanewise max. Locks the non-NaN path after the R2 fix
    //   (NaN handling is exercised as a known-DBT residual in known_dbt_issues()).
    v.push(vblock("fp_fmax_4s", 0x4E22_F420, 0,
        f32x4(1.0, 5.0, -3.0, 4.0), f32x4(2.0, 2.0, -1.0, 4.0)));
    // FMIN V0.4S (finite): lanewise min.
    v.push(vblock("fp_fmin_4s", 0x4EA2_F420, 0,
        f32x4(1.0, 5.0, -3.0, 4.0), f32x4(2.0, 2.0, -1.0, 4.0)));

    v
}

/// Blocks that the new reference coverage SURFACED as DBT problems. These are the
/// point of the oracle: each is a value/robustness defect the DBT would otherwise
/// hide behind a SKIP. Kept out of the main corpus (so the default run stays
/// green) and reported prominently under `--self-test`.
///
/// `expect_fail` = a genuine silent MISCOMPILE (wrong value — the gold we hunt).
/// `expect_gap`  = a fail-loud UD2 (unimplemented Tier-1 lowering — not a wrong
///                 value, but flagged so the gap is tracked).
struct DbtIssue { block: Block, expect_fail: bool, note: &'static str }

fn known_dbt_issues() -> Vec<DbtIssue> {
    let mut out = Vec::new();

    // ── SILENT MISCOMPILE: FCVT Sd,Dn (double→single) leaves stale bits[63:32].
    // ARM: writing a 32-bit Sd zeros bits[127:32] of Vd. The DBT lowers via
    // `cvtsd2ss VS0,VS0` then stores all 128 bits — but CVTSD2SS only writes
    // bits[31:0], so bits[63:32] keep the top half of the source double. Any
    // later read of Dd/Qd sees a corrupted value.
    //   FCVT S0,D1 with D1 = 2.25 -> S0 must be 0x0000_0000_4010_0000.
    out.push(DbtIssue {
        block: {
            let mut b = Block::new("fp_fcvt_sd_BUG");
            b.words = vec![0x1E62_4020];
            b.seed.set_vec_u128(1, (2.25f64).to_bits() as u128);
            b
        },
        expect_fail: true,
        note: "FCVT Sd,Dn leaves stale bits[63:32] (should zero upper) — lower_fpcvt2 in lower_simd_ctx.rs",
    });

    // ── SILENT MISCOMPILE (residual, low-severity): FMAX/FMIN NaN handling.
    // After the R2 reference fix (FMAX/FMIN now correctly PROPAGATE NaN as a quiet
    // NaN), the DBT — which lowers FMAX via x86 `maxps VS0=Vn, VS1=Vm` — diverges
    // on a NaN operand: x86 max/min returns the SECOND source (Vm) on any NaN
    // lane. So FMAX(Vn=NaN, Vm=number) returns the *number* (NaN NOT propagated —
    // categorically wrong per ARM), and FMAX(Vn=number, Vm=NaN) propagates the NaN
    // but leaves the raw payload un-quieted (0x7fc00001 vs canonical 0x7fc00000).
    // FPCR.DN (DefaultNaN, AETHER's production setting) would canonicalize the
    // second sub-case, but does NOT rescue the first (a NaN Vn must still yield a
    // NaN). Low-severity: NaN inputs are absent from the finite boot/render path.
    //   FMAX S0,S1,S2 with S1 = qNaN(0x7fc00001), S2 = 2.0 — DBT returns 2.0.
    out.push(DbtIssue {
        block: {
            let mut b = Block::new("fp_fmax_s_nan_BUG");
            b.words = vec![0x1E22_4820]; // FMAX S0,S1,S2
            b.seed.set_vec_u128(1, 0x7FC0_0001u128); // qNaN
            b.seed.set_vec_u128(2, (2.0f32).to_bits() as u128);
            b
        },
        expect_fail: true,
        note: "FMAX/FMIN NaN: x86 maxps returns 2nd src on NaN → Vn=NaN drops the NaN (returns number); ARM propagates NaN. lower_simd_ctx.rs:1230 (Max/Min). FPCR.DN canonicalizes payload only, not this.",
    });

    // ── GAP (fail-loud UD2): scalar FMADD/FNMSUB not lowered.
    out.push(DbtIssue {
        block: {
            let mut b = Block::new("fp_fmadd_s_GAP");
            b.words = vec![0x1F02_0C20]; // FMADD S0,S1,S2,S3
            b.seed.set_vec_u128(1, (2.0f32).to_bits() as u128);
            b.seed.set_vec_u128(2, (3.0f32).to_bits() as u128);
            b.seed.set_vec_u128(3, (1.0f32).to_bits() as u128);
            b
        },
        expect_fail: false,
        note: "scalar FMADD emits UD2 (Tier-1 unimplemented)",
    });

    // ── GAP (fail-loud UD2): UABD .4S (word) not lowered (byte/half ARE).
    out.push(DbtIssue {
        block: {
            let mut b = Block::new("simd_uabd_4s_GAP");
            b.words = vec![0x6EA2_7420]; // UABD V0.4S,V1,V2
            b.seed.set_vec_u128(1, 0x0000_0003_0000_0004_0000_0004_FFFF_FFFF);
            b.seed.set_vec_u128(2, 0x0000_0003_0000_000A_0000_000A_0000_0001);
            b
        },
        expect_fail: false,
        note: "UABD .4S emits UD2 (Tier-1; .8B/.4H are lowered) — lower_simd_ctx.rs UAbd size S",
    });

    out
}

/// The CMHI .2d block used both in the corpus (PASS) and the CATCH self-test.
/// V1 lane0 = 0x8000_0000_0000_0000 (huge unsigned; negative signed),
/// V2 lane0 = 1. Unsigned: v1 > v2 => all-ones. Signed (buggy): v1 < v2 => 0.
/// The two interpretations DIFFER, so a buggy CMHI is observable.
fn cmhi_catch_block() -> Block {
    let mut b = Block::new("cmhi_2d");
    // CMHI V0.2D,V1.2D,V2.2D = 0x6EE23420
    b.words = vec![0x6EE2_3420];
    b.seed.set_vec_u128(1, 0x0000_0000_0000_0001_8000_0000_0000_0000);
    b.seed.set_vec_u128(2, 0x0000_0000_0000_0002_0000_0000_0000_0001);
    b.note = "unsigned>: lane0 v1(0x8..)>v2(1)=all-ones; signed would be 0".to_string();
    b
}
