//! aether-dbt-bench — research-audit measurement harness for the AETHER DBT.
//!
//! Drives the LIVE translate path used by the x86 boot (`dbt::DbtRuntime::
//! translate_block`: decode -> lift -> linear-scan regalloc -> lower -> CodeBuf ->
//! BlockCache), the same function `boot_x86.rs::run_android_dispatch_loop`
//! reaches through `aether_dbt_translate_block`. Nothing in the translator is
//! modified.
//!
//! Modes:
//!   translate <corpus.txt>...  cold translate (cache miss) + warm re-dispatch
//!                              (cache hit) over every DISTINCT block, N runs
//!   exec                       per-instruction-family execution microbenchmarks
//!                              (translate once, then call the emitted x86 K times)
//!
//! Exec mode issues Win64-ABI helper calls for memory ops (that is how the
//! translator lowers them), so run the exec mode as a Windows binary (native or
//! Wine). Translate mode is ABI-neutral.
//!
//! Output is plain `key=value` lines so it can be diffed / parsed.

use std::collections::HashSet;
use std::time::Instant;

use aether_translator::dbt::{AetherDbtResult, DbtRuntime};
use aether_translator::runtime::context::vec_disp;

const RUNS: usize = 5;

fn stats(name: &str, unit: &str, xs: &[f64]) {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let sd = (v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0)).sqrt();
    let med = if v.len() % 2 == 1 { v[v.len() / 2] } else { (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0 };
    println!(
        "{name}: N={} mean={mean:.1} median={med:.1} min={:.1} max={:.1} sd={sd:.1} [{unit}]",
        v.len(), v[0], v[v.len() - 1]
    );
}

/// Minimal reader for the dbt-oracle corpus grammar: only `block`/`insn`/`end`.
fn read_blocks(path: &str) -> Vec<(String, Vec<u32>)> {
    let text = std::fs::read_to_string(path).expect("read corpus");
    let mut out = Vec::new();
    let mut cur: Option<(String, Vec<u32>)> = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut it = line.split_whitespace();
        match it.next() {
            Some("block") => cur = Some((it.next().unwrap_or("").to_string(), Vec::new())),
            Some("insn") => {
                if let Some((_, w)) = cur.as_mut() {
                    for t in it {
                        let t = t.trim_start_matches("0x");
                        w.push(u32::from_str_radix(t, 16).expect("hex insn"));
                    }
                }
            }
            Some("end") => {
                if let Some(b) = cur.take() {
                    out.push(b);
                }
            }
            _ => {}
        }
    }
    out
}

fn bytes_of(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn translate_mode(paths: &[String]) {
    // Distinct word-tuples only (corpora repeat each block under 3 seeds).
    let mut seen = HashSet::new();
    let mut blocks: Vec<Vec<u32>> = Vec::new();
    for p in paths {
        for (_, w) in read_blocks(p) {
            if seen.insert(w.clone()) {
                blocks.push(w);
            }
        }
    }
    let insns: usize = blocks.iter().map(|b| b.len()).sum();
    println!("corpus_files={} distinct_blocks={} arm_insns={} mean_insns_per_block={:.2}",
             paths.len(), blocks.len(), insns, insns as f64 / blocks.len() as f64);
    let mems: Vec<Vec<u8>> = blocks.iter().map(|b| bytes_of(b)).collect();

    let (mut cold_bps, mut cold_ips, mut cold_ns, mut warm_ns, mut warm_lps) =
        (vec![], vec![], vec![], vec![], vec![]);
    for run in 0..RUNS {
        let mut rt = DbtRuntime::new();
        // Distinct, 4-aligned, non-overlapping guest PCs (one 256-byte slot per block).
        let pc_of = |i: usize| 0x4000_0000u64 + (i as u64) * 0x100;
        let t0 = Instant::now();
        let mut ok = 0usize;
        let mut ok_insns = 0usize;
        for (i, m) in mems.iter().enumerate() {
            if rt.translate_block(pc_of(i), m) == AetherDbtResult::Ok {
                ok += 1;
                ok_insns += blocks[i].len();
            }
        }
        let cold = t0.elapsed().as_secs_f64();
        let translated = rt.stat_blocks_translated;
        let x86_bytes = rt.code_buf.written_len();
        let hits0 = rt.stat_blocks_dispatched_hit;
        let t1 = Instant::now();
        for (i, m) in mems.iter().enumerate() {
            let _ = rt.translate_block(pc_of(i), m);
        }
        let warm = t1.elapsed().as_secs_f64();
        let hits = rt.stat_blocks_dispatched_hit - hits0;
        if run == 0 {
            println!("translate_ok={ok} translate_failed={} stat_blocks_translated={translated} \
                      decode_fail={} lift_fail={} lower_fail={} x86_bytes_live={x86_bytes} \
                      warm_hits={hits} warm_hit_rate={:.4}",
                     mems.len() - ok, rt.stat_decode_failures, rt.stat_lift_failures,
                     rt.stat_lower_failures, hits as f64 / mems.len() as f64);
            println!("expansion_x86_bytes_per_arm_insn={:.2} (approx: code_buf may reset when full)",
                     x86_bytes as f64 / ok_insns.max(1) as f64);
        }
        cold_bps.push(mems.len() as f64 / cold);
        cold_ips.push(insns as f64 / cold);
        cold_ns.push(cold * 1e9 / mems.len() as f64);
        warm_ns.push(warm * 1e9 / mems.len() as f64);
        warm_lps.push(mems.len() as f64 / warm);
    }
    stats("cold_translate_blocks_per_s", "blocks/s", &cold_bps);
    stats("cold_translate_arm_insns_per_s", "insns/s", &cold_ips);
    stats("cold_translate_ns_per_block", "ns", &cold_ns);
    stats("warm_cache_hit_ns_per_lookup", "ns", &warm_ns);
    stats("warm_cache_hit_lookups_per_s", "lookups/s", &warm_lps);
}

// ------------------------------------------------------------------ exec mode
const CTX_U64S: usize = 0x728 / 8;

#[cfg(windows)]
fn make_exec(bytes: &[u8]) -> *const u8 {
    use std::ffi::c_void;
    extern "system" {
        fn VirtualAlloc(a: *mut c_void, s: usize, t: u32, p: u32) -> *mut c_void;
    }
    unsafe {
        let p = VirtualAlloc(core::ptr::null_mut(), bytes.len().max(1), 0x3000, 0x40);
        assert!(!p.is_null());
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
        p as *const u8
    }
}

#[cfg(not(windows))]
fn make_exec(_bytes: &[u8]) -> *const u8 {
    panic!("exec mode must run as a Windows binary (translator emits Win64 helper calls)");
}

/// Same entry stub as tools/dbt-oracle/src/dbt_side.rs::enter_block.
unsafe fn enter_block(code: *const u8, ctx: *mut u64) {
    core::arch::asm!(
        "push rbx", "push rbp", "push rsi", "push rdi",
        "push r12", "push r13", "push r14", "push r15",
        "mov r15, {ctx}",
        "call {code}",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rdi", "pop rsi", "pop rbp", "pop rbx",
        ctx = in(reg) ctx,
        code = in(reg) code,
        lateout("r15") _,
        clobber_abi("C"),
    );
}

fn exec_mode() {
    // Representative instruction families (incl. the ones behind past bugs).
    // Each block is straight-line and ends WITHOUT a terminator, so the live
    // translator appends a synthetic WritePc fallthrough + RET.
    let fams: &[(&str, &[u32])] = &[
        ("int_arith (add/sub/madd/eor x8)", &[0x8b010000, 0xcb020021, 0x9b030c42, 0xca040063,
                                              0x8b010000, 0xcb020021, 0x9b030c42, 0xca040063]),
        ("shift_bitfield (lsl/lsr/asr/ubfx/bfi)", &[0xd37ff800, 0xd341fc21, 0x9343fc42, 0xd34c7c63,
                                                    0xb3481c84, 0xd37ff800, 0xd341fc21, 0x9343fc42]),
        ("flags_csel (cmp/csel/csinc/ccmp)", &[0xeb01001f, 0x9a820020, 0x9a8304a1, 0xfa410804,
                                              0xeb01001f, 0x9a820020, 0x9a8304a1, 0xfa410804]),
        ("scalar_fp (fadd/fmul/fdiv/fmadd d)", &[0x1e612800, 0x1e630841, 0x1e651882, 0x1f4310c3,
                                                0x1e612800, 0x1e630841, 0x1e651882, 0x1f4310c3]),
        ("fp_convert (scvtf/fcvtzs/fcvt s<-d)", &[0x9e620000, 0x9e780021, 0x1e624042, 0x1e220063,
                                                  0x9e620000, 0x9e780021, 0x1e624042, 0x1e220063]),
        ("simd_int (add.4s/cmhi.2d/zip1/tbl)", &[0x4ea18400, 0x6ee33442, 0x4e053883, 0x4e0300a4,
                                                  0x4ea18400, 0x6ee33442, 0x4e053883, 0x4e0300a4]),
        ("simd_fp (fmla.4s/fadd.4s/fmul.4s)", &[0x4e22cc20, 0x4e25d483, 0x6e27dcc5, 0x4e22cc20,
                                                0x4e25d483, 0x6e27dcc5, 0x4e22cc20, 0x4e25d483]),
        ("load_store (ldr/str x, flat MMU)", &[0xf9400040, 0xf9000441, 0xf9400845, 0xf9000c43,
                                               0xf9400040, 0xf9000441, 0xf9400845, 0xf9000c43]),
        ("atomics (ldadd/swp/cas x)", &[0xf8200041, 0xf8208043, 0xc8a07c44, 0xf8200041,
                                        0xf8208043, 0xc8a07c44, 0xf8200041, 0xf8208043]),
        ("system (mrs nzcv/msr nzcv/mrs tpidr_el0)", &[0xd53b4200, 0xd51b4200, 0xd53bd041, 0xd53b4200,
                                                       0xd51b4200, 0xd53bd041, 0xd53b4200, 0xd51b4200]),
    ];
    let k: usize = std::env::var("BENCH_K").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    println!("exec_iters_per_run={k} runs={RUNS}");
    // Scratch RAM for the flat (SCTLR=0) load/store path; x2 points into it.
    let scratch = vec![0u8; 4096];
    let base = scratch.as_ptr() as u64;
    aether_translator::runtime::mmu::aether_mmu_set_window(base, scratch.len() as u64);
    let bare = make_exec(&[0xC3u8]);
    let overhead = time_block(bare, base, k);
    stats(&format!("harness_bare_ret_ns_per_{CALLS}calls"), "ns", &overhead);
    for (name, words) in fams {
        let mut rt = DbtRuntime::new();
        let pc = 0x4000_0000u64;
        let r = rt.translate_block(pc, &bytes_of(words));
        let info = rt.block_cache.lookup(pc).map(|b| (b.host_offset, b.len, b.safe));
        let Some((off, len, safe)) = info else {
            println!("family={name} translate={r:?} -> NOT RUNNABLE (translation failed)");
            continue;
        };
        if !safe {
            println!("family={name} x86_bytes={len} -> NOT RUNNABLE (block contains UD2 fail-loud)");
            continue;
        }
        let code = rt.code_buf.read_bytes(off, len).to_vec();
        let exec = make_exec(&code);
        let per = time_block(exec, base, k);
        let net: Vec<f64> = per.iter().zip(overhead.iter()).map(|(a, b)| (a - b) / CALLS as f64).collect();
        println!("family={name} arm_insns={} x86_bytes={len} expansion={:.1}B/insn",
                 words.len(), len as f64 / words.len() as f64);
        stats(&format!("  gross_ns_per_{CALLS}calls[{name}]"), "ns", &per);
        stats(&format!("  net_ns_per_block[{name}]"), "ns (minus bare-RET loop, /CALLS)", &net);
        let npi: Vec<f64> = net.iter().map(|x| x / words.len() as f64).collect();
        stats(&format!("  net_ns_per_arm_insn[{name}]"), "ns", &npi);
    }
}

const CALLS: usize = 16;

/// One timing sample per run: reseed ctx (identical for every block), then call
/// the block CALLS times. Returns ns per (reseed + CALLS calls).
fn time_block(exec: *const u8, base: u64, k: usize) -> Vec<f64> {
    let mut ctx = vec![0u64; CTX_U64S];
    let mut out = vec![];
    for _ in 0..RUNS {
        let t = Instant::now();
        for _ in 0..k {
            for i in 0..31 { ctx[i] = 3 + i as u64; }
            ctx[2] = base + 64;
            ctx[4] = base + 256;
            for r in 0..32 {
                let s = vec_disp(r) as usize / 8;
                ctx[s] = 0x3f80_0000_4000_0000; ctx[s + 1] = 0x4040_0000_3f00_0000;
            }
            for _ in 0..CALLS { unsafe { enter_block(exec, ctx.as_mut_ptr()); } }
        }
        out.push(t.elapsed().as_secs_f64() * 1e9 / k as f64);
    }
    out
}

/// DBT-only coverage: for every distinct block, does the LIVE translate path
/// accept it, and does the emitted code contain a fail-loud UD2? Independent of
/// the oracle's reference interpreter (which SKIPs before ever calling the DBT).
/// Prints one line per non-OK block: `status <first-bad-word|-> <words...>`.
fn coverage_mode(paths: &[String]) {
    let mut seen = HashSet::new();
    let (mut ok, mut partial, mut fail, mut ud2) = (0usize, 0usize, 0usize, 0usize);
    let mut rt = DbtRuntime::new();
    let mut i = 0u64;
    for p in paths {
        for (_, w) in read_blocks(p) {
            if !seen.insert(w.clone()) {
                continue;
            }
            let pc = 0x4000_0000u64 + i * 0x100;
            i += 1;
            let before = rt.stat_decode_failures;
            let r = rt.translate_block(pc, &bytes_of(&w));
            let words = w.iter().map(|x| format!("{x:08x}")).collect::<Vec<_>>().join(" ");
            if r != AetherDbtResult::Ok {
                fail += 1;
                println!("FAIL {:08x} {words}", rt.last_failure_word());
                continue;
            }
            if rt.stat_decode_failures > before {
                partial += 1;
                println!("PARTIAL {:08x} {words}", rt.last_failure_word());
                continue;
            }
            match rt.block_cache.lookup(pc).map(|b| b.safe) {
                Some(false) => { ud2 += 1; println!("UD2 - {words}"); }
                _ => ok += 1,
            }
        }
    }
    println!("summary distinct_blocks={} ok={ok} ud2={ud2} partial_decode={partial} translate_fail={fail}",
             seen.len());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("translate") => translate_mode(&a[2..]),
        Some("coverage") => coverage_mode(&a[2..]),
        Some("exec") => exec_mode(),
        _ => eprintln!("usage: aether-dbt-bench translate <corpus.txt>... | exec"),
    }
}
