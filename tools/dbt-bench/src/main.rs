//! aether-dbt-bench — measurement harness for the AETHER DBT (ch66 gate).
//!
//! `kernels` mode is the headline metric: slowdown of translated ARM64 vs the
//! same C (tools/dbt-bench/kernels) compiled natively, flat + MMU-on variants.
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
        Some("kernels") => kernels_mode(a.get(2).map(|s| s.as_str()).unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/kernels"))),
        _ => eprintln!("usage: aether-dbt-bench translate <corpus.txt>... | coverage <corpus.txt>... | exec | kernels [dir]"),
    }
}

// --------------------------------------------------------------- kernels mode
// Phase-0 headline metric: slowdown of translated ARM64 vs the SAME C source
// compiled natively for x86_64 (research_audit/bench/kernels, build.sh). The
// x86 build exists only as the timing baseline; it is not part of AETHER.
// The ARM blob runs through the live DbtRuntime with a minimal dispatch loop
// (one cache lookup per block, translate on miss) in flat (SCTLR=0) MMU mode.
// The boot's dispatch loop does strictly more work per block than this one, so
// these numbers are a lower bound on the boot's translated slowdown.

const PC_SLOT: usize = 32;
const SP_SLOT: usize = 31;
const PEND_SLOT: usize = aether_translator::runtime::context::SYSREG_SLOT0
    + aether_translator::runtime::mmu::SLOT_PEND_PENDING;
const RET_MAGIC: u64 = 0x0000_dead_0000;
const EXIT_SLOT: usize = aether_translator::runtime::context::SYSREG_SLOT0
    + aether_translator::runtime::context::CHAIN_EXIT_IDX;
const BUDGET_SLOT: usize = aether_translator::runtime::context::SYSREG_SLOT0
    + aether_translator::runtime::context::CHAIN_BUDGET_IDX;
/// Chained transfers allowed per dispatcher entry (env CHAIN_BUDGET, default
/// 64; 0 disables chaining).
fn chain_budget() -> u64 {
    std::env::var("CHAIN_BUDGET").ok().and_then(|s| s.parse().ok()).unwrap_or(64)
}
const ARENA: usize = 64 << 20;

fn load_syms(path: &str) -> Vec<(String, usize)> {
    std::fs::read_to_string(path).expect("read syms").lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        Some((it.next()?.to_string(), usize::from_str_radix(it.next()?, 16).ok()?))
    }).collect()
}

#[cfg(windows)]
fn make_rwx(p: *const u8, len: usize) {
    use std::ffi::c_void;
    extern "system" { fn VirtualProtect(a: *const c_void, s: usize, n: u32, o: *mut u32) -> i32; }
    let mut old = 0u32;
    assert!(unsafe { VirtualProtect(p as *const c_void, len, 0x40, &mut old) } != 0, "VirtualProtect");
}
#[cfg(not(windows))]
fn make_rwx(_p: *const u8, _len: usize) { panic!("kernels mode must run as a Windows binary"); }

/// Data regions inside an arena (identical layout for native and translated runs).
struct Regions { r0: u64, r1: u64, r2: u64, stack_top: u64 }
fn regions(base: u64) -> Regions {
    Regions { r0: base + (16 << 20), r1: base + (24 << 20), r2: base + (32 << 20),
              stack_top: base + ARENA as u64 - 4096 }
}

/// Deterministic per-kernel input setup; returns the 4 arguments.
fn setup(name: &str, rg: &Regions, hi: u64) -> [u64; 4] {
    let fill = |at: u64, n: usize, f: &dyn Fn(usize) -> u8| unsafe {
        let p = at as *mut u8; for i in 0..n { *p.add(i) = f(i); }
    };
    let rnd = |i: usize| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8;
    match name {
        "k_intloop" => [2_000_000, 12345, 0, 0],
        "k_memcpy" => { fill(rg.r1, 65536, &|i| i as u8); [rg.r0 | hi, rg.r1 | hi, 65536, 40] }
        "k_strlen" => { fill(rg.r0, 65536, &|i| { let b = rnd(i); if b % 23 == 0 || i == 65535 { 0 } else { b | 1 } });
                        [rg.r0 | hi, 65536, 20, 0] }
        "k_sort" => [rg.r0 | hi, 2000, 7, 0],
        "k_crc32" => { fill(rg.r0, 16384, &rnd); [rg.r0 | hi, 16384, 4, 0] }
        "k_fib" => [24, 0, 0, 0],
        "k_matmul" => [rg.r0 | hi, rg.r1 | hi, rg.r2 | hi, 64],
        "k_interp" => { fill(rg.r0, 4096, &rnd); [rg.r0 | hi, 4096, 100, 0] }
        "k_sieve" => [rg.r0 | hi, 200_000, 5, 0],
        _ => panic!("unknown kernel {name}"),
    }
}

fn kernels_mode(dir: &str) {
    let arm_bin = std::fs::read(format!("{dir}/k_arm64.bin")).expect("k_arm64.bin (run kernels/build.sh)");
    let x86_bin = std::fs::read(format!("{dir}/k_x86_64.bin")).expect("k_x86_64.bin");
    let arm_syms = load_syms(&format!("{dir}/k_arm64.syms"));
    let x86_syms = load_syms(&format!("{dir}/k_x86_64.syms"));
    let only: Option<String> = std::env::var("KERNEL").ok();

    // Native arena (x86 blob at +0) and guest arena (ARM blob at +0), same layout.
    let native = vec![0u8; ARENA + 4096];
    let nbase = (native.as_ptr() as u64 + 4095) & !4095;
    unsafe { core::ptr::copy_nonoverlapping(x86_bin.as_ptr(), nbase as *mut u8, x86_bin.len()); }
    make_rwx(nbase as *const u8, x86_bin.len());
    let guest = vec![0u8; ARENA + 4096];
    let gbase = (guest.as_ptr() as u64 + 4095) & !4095;
    unsafe { core::ptr::copy_nonoverlapping(arm_bin.as_ptr(), gbase as *mut u8, arm_bin.len()); }
    aether_translator::runtime::mmu::aether_mmu_set_window(gbase, ARENA as u64);

    println!("kernels arm_blob={}B x86_blob={}B runs={RUNS}", arm_bin.len(), x86_bin.len());
    // Variants: flat = MMU off; ttbr0 = MMU on, user (low) VAs, 4 KiB pages;
    // ttbr1 = MMU on, kernel (high) VAs, same tables. VA[47:0] == host address.
    let variants: [(&str, bool, u64); 3] =
        [("flat", false, 0), ("ttbr0", true, 0), ("ttbr1", true, 0xFFFF_0000_0000_0000)];
    let only_var: Option<String> = std::env::var("VARIANT").ok();
    let ttbr = build_identity_tables(gbase);
    print!("{:<10} {:>10}", "kernel", "native_us");
    for (v, _, _) in &variants {
        if only_var.as_deref().map_or(false, |o| o != *v) { continue; }
        print!(" | {:>27}", format!("{v}: slow cold dispatch"));
    }
    println!();
    let mut geo: std::collections::HashMap<&str, f64> = Default::default();
    let mut cnt = 0;
    for (name, aoff) in &arm_syms {
        if only.as_deref().map_or(false, |k| k != name) { continue; }
        let xoff = x86_syms.iter().find(|(n, _)| n == name).expect("x86 sym").1;
        // ---- native baseline
        let nrg = regions(nbase);
        let f: extern "win64" fn(u64, u64, u64, u64) -> u64 = unsafe { core::mem::transmute(nbase + xoff as u64) };
        let mut nat = vec![]; let mut want = 0;
        for _ in 0..RUNS {
            let a = setup(name, &nrg, 0);
            let t = Instant::now(); want = f(a[0], a[1], a[2], a[3]); nat.push(t.elapsed().as_secs_f64());
        }
        let n_best = nat.iter().cloned().fold(f64::MAX, f64::min);
        print!("{:<10} {:>10.1}", name, n_best * 1e6);
        for &(vname, mmu, hi) in &variants {
            if only_var.as_deref().map_or(false, |v| v != vname) { continue; }
            let (cold, w_best, blocks) = run_translated(name, gbase, *aoff, mmu, hi, ttbr, want);
            let slow = w_best / n_best;
            *geo.entry(vname).or_insert(0.0) += slow.ln();
            print!(" | {:>8.1}x {:>7.1}x {:>8}", slow, cold / n_best, blocks);
        }
        println!();
        cnt += 1;
    }
    for &(vname, _, _) in &variants {
        if let Some(g) = geo.get(vname) {
            println!("geomean_slowdown_warm[{vname}]={:.1}x over {cnt} kernels", (g / cnt as f64).exp());
        }
    }
}

/// 4-level, 4 KiB-granule identity tables for the guest arena (VA[47:0] == PA),
/// placed inside the arena at +40 MiB. Shared by TTBR0 and TTBR1. Returns L0 PA.
fn build_identity_tables(gbase: u64) -> u64 {
    let pool = gbase + (40 << 20);
    let mut next = pool;
    let mut alloc = || { let t = next; next += 4096; unsafe { core::ptr::write_bytes(t as *mut u8, 0, 4096); } t };
    let l0 = alloc();
    let ent = |t: u64, i: u64| (t + i * 8) as *mut u64;
    let sub = |t: u64, i: u64, alloc: &mut dyn FnMut() -> u64| -> u64 {
        unsafe {
            let d = *ent(t, i);
            if d & 1 != 0 { return d & 0x0000_FFFF_FFFF_F000; }
            let n = alloc(); *ent(t, i) = n | 0b11; n
        }
    };
    for page in (0..ARENA as u64).step_by(4096) {
        let pa = gbase + page;
        let l1 = sub(l0, (pa >> 39) & 0x1FF, &mut alloc);
        let l2 = sub(l1, (pa >> 30) & 0x1FF, &mut alloc);
        let l3 = sub(l2, (pa >> 21) & 0x1FF, &mut alloc);
        unsafe { *ent(l3, (pa >> 12) & 0x1FF) = pa | 0b11 | (1 << 10); } // page + AF, RW
    }
    l0
}

/// One kernel through the live translator; returns (cold_s, best_warm_s, blocks).
fn run_translated(name: &str, gbase: u64, aoff: usize, mmu: bool, hi: u64, ttbr: u64, want: u64)
    -> (f64, f64, u64)
{
    use aether_translator::runtime::context::SYSREG_SLOT0;
    use aether_translator::runtime::mmu::{SLOT_SCTLR, SLOT_TCR, SLOT_TTBR0, SLOT_TTBR1, aether_mmu_flush_all};
    let mut rt = DbtRuntime::new();
    let cb = rt.code_buf.base_ptr();
    make_rwx(cb, rt.code_buf.capacity());
    let grg = regions(gbase);
    let (mut cold, mut warm, mut blocks) = (0.0, vec![], 0u64);
    for run in 0..RUNS {
        let a = setup(name, &grg, hi);
        let mut ctx = vec![0u64; aether_translator::runtime::context::CTX_U64S];
        ctx[..4].copy_from_slice(&a);
        ctx[30] = RET_MAGIC; ctx[SP_SLOT] = grg.stack_top | hi; ctx[PC_SLOT] = (gbase + aoff as u64) | hi;
        if mmu {
            ctx[SYSREG_SLOT0 + SLOT_SCTLR] = 1;
            ctx[SYSREG_SLOT0 + SLOT_TTBR0] = ttbr;
            ctx[SYSREG_SLOT0 + SLOT_TTBR1] = ttbr;
            ctx[SYSREG_SLOT0 + SLOT_TCR] = 16 | (16 << 16) | (0b10 << 30); // T0SZ=T1SZ=16, TG0=4K, TG1=4K
        }
        aether_mmu_flush_all();
        let t = Instant::now();
        let mut nb = 0u64;
        // ch66 chaining protocol: seed the budget + clear the exit word before
        // each entry; after the block, link the exit it reported (if any) to
        // the block the guest PC now names.
        let budget = chain_budget();
        let mut pending: Option<(u64, u64)> = None;
        loop {
            let pc = ctx[PC_SLOT];
            if pc == RET_MAGIC { break; }
            let (off, _len, safe) = match rt.host_offset_for_pc_safe(pc) {
                Some(x) => x,
                None => {
                    let host = pc & 0x0000_FFFF_FFFF_FFFF;
                    let end = ((host | 4095) + 1).min(host + 256);
                    let bytes = unsafe { std::slice::from_raw_parts(host as *const u8, (end - host) as usize) };
                    let r = rt.translate_block(pc, bytes);
                    assert!(r == AetherDbtResult::Ok, "{name}: translate {r:?} at +{:#x} word {:08x}",
                            host - gbase, rt.last_failure_word());
                    rt.host_offset_for_pc_safe(pc).expect("cached after translate")
                }
            };
            assert!(safe, "{name}: UD2 block at {pc:#x}");
            if let Some((exit, ep)) = pending.take() {
                rt.chain_link(exit, ep, pc, off);
            }
            ctx[EXIT_SLOT] = 0;
            ctx[BUDGET_SLOT] = budget;
            let ep = rt.arena_epoch;
            unsafe { enter_block(cb.add(off), ctx.as_mut_ptr()); }
            assert!(ctx[PEND_SLOT] == 0, "{name}: guest fault at {pc:#x} far={:#x} esr={:#x}",
                    ctx[PEND_SLOT + 1], ctx[PEND_SLOT + 2]);
            pending = Some((ctx[EXIT_SLOT], ep));
            nb += 1;
        }
        let dt = t.elapsed().as_secs_f64();
        if run == 0 { cold = dt; } else { warm.push(dt); }
        blocks = nb;
        assert!(ctx[0] == want, "{name}: CHECKSUM MISMATCH dbt={:#x} native={want:#x} (miscompile)", ctx[0]);
    }
    (cold, warm.iter().cloned().fold(f64::MAX, f64::min), blocks)
}
