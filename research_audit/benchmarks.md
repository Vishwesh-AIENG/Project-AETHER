# Benchmarks

Everything here is **new measurement on the audited commit** (`9f34e2f`). The one exception, the historical 346K dispatches/s figure, is discussed in §5.

**Host:** Intel Xeon @ 2.10 GHz (4 vCPU, AVX-512/FMA/BMI2), 15.7 GiB RAM, Ubuntu 24.04, no KVM. **Toolchain:** rustc 1.101.0-nightly (2026-10-07). AETHER's own release profile is used: `opt-level="s"`, `lto=true`, `panic="abort"`. **Statistic:** N=5 runs per configuration; I report median, plus mean/min/max/sd where they matter. Raw output is in `raw/2026-10-08_9f34e2f_bench-*.log`.

**Harness:** `bench/aether-dbt-bench/` (new, about 330 lines, outside the AETHER build). It drives the **live** translate path: `dbt::DbtRuntime::translate_block`, which does decode → lift → linear-scan regalloc → lower → `CodeBuf` → `BlockCache`. This is the same function `boot_x86.rs::run_android_dispatch_loop` reaches via `aether_dbt_translate_block`. Translator source is untouched.

## 1. Translation throughput (cold, cache miss)

Workload: every **distinct** block of the real-Android oracle corpus. Each block gets a unique guest PC and a fresh `DbtRuntime` per run.

| Workload | Distinct blocks | ARM insns | Translated OK | Median blocks/s | Median ARM insns/s | Median ns/block (min–max) |
|---|---:|---:|---:|---:|---:|---|
| Multi-instruction blocks (bb_*, 13 libs, mean 5.31 insns/block) | 4,958 | 26,332 | 4,879 (98.4%) | **580,400** | **3.08 M** | 1,723 (1,630–1,942) |
| Single SIMD/FP + trace instructions | 30,375 | 30,375 | 29,646 (97.6%) | 1,805,181 | 1.81 M | 554 (449–681) |

Code expansion: about **69 bytes of x86 per ARM instruction** for multi-instruction blocks, and about 100 B for single instructions. This is what you'd expect from the live design: every guest register goes through the in-memory context on every instruction (`ReadGpr`/`WriteGpr` per instruction), with no cross-instruction register allocation. The optimiser (`opt/*`) and SSA (`ssa/*`) modules exist but are **not on the live path**; they are absent from the x86 image (see `claims.md` D).

## 2. Translation cache: hit vs miss

Same workload, second pass over the same PCs; `translate_block` returns on `block_cache.lookup` hit.

| | Median ns per dispatch | Ratio |
|---|---:|---:|
| Warm, cache hit (bb_*) | **33.2** (31.9–50.9) | 1× |
| Cold, cache miss: translate (bb_*) | 1,723 | **≈52×** |
| Warm hit (single-instruction corpus) | 43.6 | — |
| Warm hit rate on 2nd pass | 98.4% (= blocks that translate at all) | — |

The "cache disabled" configuration means every dispatch pays the cold cost, so caching cuts per-dispatch translation overhead by about 50× on real blocks. I could **not measure** a hit rate during an actual boot: the boot log prints a dispatch counter but no hit/miss split (`DbtRuntime::stat_blocks_dispatched_hit` exists but is not printed). Treat this as a gap.

## 3. Execution microbenchmarks by instruction family

Method: translate an 8-instruction straight-line block once through the live path, then reseed the context and call the emitted x86 16 times, K=100,000 iterations, N=5. **Net** cost = (block loop − identical loop calling a bare `RET`) / 16, which removes call/ret and reseed overhead. The binary is the Windows build under Wine, because memory and system instructions lower to Win64 helper calls. Loads and stores use the flat (SCTLR.M=0) soft-MMU path, so the **page-table walk cost of a real boot is not included**. All encodings were checked with `aarch64-linux-gnu-objdump`.

| Family (8 insns) | x86 bytes (B/insn) | AETHER net ns/block (median) | ns/insn | QEMU TCG user-mode, same block: ns/block (median) | ns/insn |
|---|---:|---:|---:|---:|---:|
| int arith (add/sub/madd/eor) | 378 (47) | 4.3 | 0.54 | 0.81 | 0.10 |
| shift/bitfield (lsl/lsr/asr/ubfx/bfi) | 580 (73) | 4.8 | 0.60 | 0.45 | 0.06 |
| flags/csel (cmp/csel/csinc/ccmp) | 840 (105) | 9.4 | 1.18 | 2.69 | 0.34 |
| scalar FP (fadd/fmul/fdiv/fmadd d) | 490 (61) | 4.3 | 0.54 | 36.2 | 4.52 |
| FP convert (scvtf/fcvtzs/fcvt) | 504 (63) | 4.4 | 0.55 | 45.2 | 5.65 |
| SIMD int (add.4s/cmhi.2d/zip1/tbl) | 574 (72) | 6.2 | 0.78 | 42.9 | 5.37 |
| SIMD FP (fmla/fadd/fmul .4s) | 495 (62) | 5.8 | 0.73 | 105.4 | 13.18 |
| load/store (ldr/str x) | 1,338 (167) | 55.3 | 6.91 | 2.48 * | 0.31 * |
| atomics (ldadd/swp/cas) | 1,379 (172) | 48.0 | 6.00 | 6.15 * | 0.77 * |
| system (mrs/msr nzcv, mrs tpidr_el0) | 304 (38) | 3.2 | 0.40 | 7.17 | 0.90 |

`*` **Not comparable.** qemu-user maps guest memory directly (no softmmu), while AETHER emulates a system-level MMU and calls `aether_mmu_xlate`/`aether_mmu_store` on every access.

How to read this (honestly):
- **Integer/flags:** QEMU TCG is about 3.5–10× cheaper per instruction. TCG keeps guest registers in host registers within a translation block and optimises the IR; AETHER's live path writes each guest register back to memory after every instruction.
- **FP/SIMD:** AETHER is about 7–18× cheaper. It maps ARM FP/SIMD directly onto SSE/AVX/FMA instructions, while QEMU emulates them in softfloat helpers. This speed has a correctness price. ARM and x86 differ on NaN propagation, signed zero, saturation and rounding, and every difference needs a fix-up sequence. **That is exactly where the large majority of AETHER's confirmed miscompiles live** (`bug_taxonomy.md`).
- **Memory:** a soft-MMU helper call per access makes memory instructions about 10× more expensive than ALU instructions in AETHER. In a real boot, the MMU is on and the TLB walk adds to this. Memory access is very likely the dominant cost of whole-system execution, but I have not profiled a real boot.
- These are **isolated, warm, per-block** costs. They are **not** a whole-system speed comparison, and they must not be presented as "AETHER is faster/slower than QEMU". The fair whole-system baseline (QEMU system-mode TCG booting the same Android image) was not run (§6).

QEMU baseline sources: `bench/qemu-tcg-baseline/tcgbench.c` (same encodings, generated from the harness). Built with `aarch64-linux-gnu-gcc -O2 -static`, run with `qemu-aarch64` 8.2.2. Per outer iteration it initialises registers once and runs 16 non-unrolled inner iterations, so each block ends at a TB boundary with live registers. An earlier variant that re-initialised inside an unrolled loop let TCG dead-code-eliminate the integer blocks (≈0 ns), so I discarded it; it is documented in the log header.

## 4. Whole-system timing: ARM tier (QEMU TCG, nested EL2 emulated)

See `boot_milestones.md`. Summary: firmware takes about 5.8 s, AETHER's EL2 bring-up is under 0.05 s, and kernel entry → `PROOF done` takes 7.1 s at smp4 and 5.2 s at smp1.

## 5. Dispatch rate and the "346K dispatches/s under WHPX" claim

| Source | Value | Status |
|---|---|---|
| `_claude-memory/phase-g-tbl-multireg-t12187.md` (2026-06-26): "Measured ~55 guest-t/wall-min, ~346K dispatch/s WHPX"; repeated in `docs/GAP-ROADMAP.md` | ~346,000 /s | **Not reproducible here.** WHPX needs a Windows host with Windows Hypervisor Platform. No script or log records how it was computed. The preserved WHPX log (`raw/old-evidence/x86-serial-com1.log.gz`) has no host timestamps, so the rate cannot be re-derived from it. **Anecdotal.** |
| **This audit:** x86-tier AETHER under QEMU **TCG** (`-accel tcg,tb-size=512 -cpu max`), full system (OVMF → AETHER host-mode DBT → GKI 6.1). Rate = Δ`[dbt] #counter` / Δwall from a 15 s heartbeat (`raw/x86-tcg-2026-10-08_9f34e2f/heartbeat.tsv`) | see `boot_milestones.md` §2 (≈20–22 K dispatches/s, early kernel boot) | **Reproduced (TCG only)** |

"Dispatch" is one iteration of `run_android_dispatch_loop`: fetch PC, translate-or-lookup, and call one translated block. It is not one instruction. The TCG figure is roughly 15–17× below the claimed WHPX figure. That ratio fits the project's own note that "WHPX ≈ 30–70× TCG" in ballpark, but does not confirm it. **Do not use 346K in a paper unless it is re-measured with a logged, scripted method** (runbook in `reproducibility.md`).

## 6. Baselines: what exists and what is missing

| Baseline | Status | Why |
|---|---|---|
| QEMU TCG user-mode, per-family microbenchmark | **Done (partial)**, §3 | Same host, same instruction sequences. Not whole-system. |
| QEMU direct kernel boot vs AETHER EL2 (ARM tier, both under TCG) | **Done**, `boot_milestones.md` | It shows the *emulated* EL2 layer is not a large cost. It says nothing about hardware. |
| QEMU **system-mode** TCG booting the same AOSP images (x86 host, ARM guest) vs AETHER x86 tier | **Missing** | The natural fair baseline for the x86 tier. It needs a bootable ARM64 AOSP configuration for `qemu-system-aarch64 -M virt` with the same system/vendor images. Not attempted for lack of time; feasible. |
| FEX-Emu | **Missing** | FEX is a user-mode ARM64→x86 translator; it cannot boot a kernel. A fair comparison would be on user-space workloads (for example the corpus blocks or a static benchmark binary), which AETHER's harness can do but FEX was not installed. The README's "FEX-Emu DBT inside the hypervisor" is historical: `hypervisor/third_party/fex` is a stub and the in-tree translator replaced it. |
| Box64 | **Not applicable** | Box64 translates x86-64 → ARM64, the opposite direction. |
| Native ARM hardware | **Missing** | No ARM64 host. Never measured by the project either ("never on Snapdragon"). |
