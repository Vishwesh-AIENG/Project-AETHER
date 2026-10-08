# Differential-oracle results

**What was measured:** the AETHER ARM64→x86-64 DBT, checked against an independent ARM64 reference interpreter on a corpus of basic blocks taken from real Android binaries. Everything here was **re-run on the audited commit** (`sandbox/aether-translator` @ `9f34e2f`).

> **Host / tooling for every number here:** Intel Xeon @ 2.10 GHz (4 vCPU), Ubuntu 24.04. `dbt-oracle` was built for `x86_64-pc-windows-gnu` (rustc nightly 1.101.0) and run under Wine 9.0. The translator emits Win64-ABI calls to its runtime helpers, so this keeps the same ABI as the authors' Windows machine. No AETHER source was changed. Raw logs: `raw/oracle-sweep-2026-10-08_9f34e2f/`.

## 1. The oracle is real

| Property | Evidence | Verdict |
|---|---|---|
| Independent reference interpreter | `tools/dbt-oracle/src/reference.rs`: 2,191 lines of hand-written Rust. It does not depend on the DBT's decoder or lifter; it only uses the context-layout helper `vec_disp`. | **Yes** |
| Differential execution against translated x86 | `dbt_side.rs` runs each block through the real `decode→lift→regalloc→lower` pipeline, executes the emitted x86 in RWX memory, and diffs GPRs, V-registers, NZCV and scratch memory. | **Yes** |
| Catches a known bug class | `--self-test` re-injects the historical CMHI signed/unsigned defect, and the oracle reports a divergence. Reproduced: `raw/2026-10-08_9f34e2f_oracle-selftest.log`. Result: 85 PASS / 0 FAIL / 0 SKIP / 0 DBTERR, CATCH detected. | **Yes** |
| Real Android corpus | `tools/corpus-extract/extract.py` disassembled `system.raw` and the ART APEX payload with a cross objdump. Libraries: libhwui (with Skia statically linked), surfaceflinger (with RenderEngine), libart, libgui, libui, libbinder, libandroid_runtime, app_process64, plus smaller ones. | **Yes** |
| "~105k blocks" | Exact count: **105,573 blocks**, in 14 corpus files. Of these, 15,993 are multi-instruction blocks and 89,520 are single instructions (29,840 distinct SIMD/FP words × 3 seed contexts). Distinct ARM64 instruction words across the corpus: 30,375. Distinct multi-instruction blocks: 4,958. | **Verified** |

### Limits of the oracle
- **Single basic block, register-only.** Branches and PC-relative instructions are SKIPped by design. Memory is limited to a flat scratch window.
- **Reference-first evaluation.** `main.rs::run_block` runs the reference first. If the reference does not model an instruction, the block is SKIPped **without ever calling the DBT**. This means DBTERR undercounts DBT coverage gaps; §4 measures them directly.
- **The reference is itself buggy.** Sweeps #1 and #2 and this audit all found reference defects (§3). A FAIL is therefore a *candidate* until a third party adjudicates it.
- **Three fixed seed contexts per block.** This is not random or exhaustive testing.

## 2. Sweep results: historical vs today

| Run | Blocks | PASS | FAIL | SKIP | DBTERR | Source |
|---|---:|---:|---:|---:|---:|---|
| Sweep #2 (2026-07-01, pre-fix) | 105,573 | 74,564 | 1,903 | 26,754 | 2,352 | `docs/phase-g/oracle-sweep-2.md` (old evidence, not re-run at that commit) |
| **This audit, 9f34e2f** | **105,573** | **78,301** | **422** | **26,709** | **141** | `raw/oracle-sweep-2026-10-08_9f34e2f/*.log` (new) |

Per-file results for this audit:

| File | PASS | FAIL | SKIP | DBTERR |
|---|---:|---:|---:|---:|
| bb_libhwui | 2,560 | 2 | 3,423 | 15 |
| bb_libsurfaceflinger | 2,101 | 38 | 3,855 | 6 |
| bb_libart | 345 | 0 | 1,005 | 0 |
| bb_libandroid_runtime | 798 | 0 | 102 | 0 |
| bb_libbinder | 885 | 0 | 15 | 0 |
| bb_libgui | 114 | 0 | 363 | 0 |
| bb_libui | 127 | 5 | 108 | 0 |
| bb_libEGL / libvulkan / libartbase / libdexfile / libopenjdkjvm | 18 | 0 | 99 | 0 |
| bb_app_process64 | 63 | 0 | 6 | 0 |
| simd_from_framework | 71,290 | 377 | 17,733 | 120 |
| (extra) trace_insns (boot-trace, sweep #1 corpus) | 1,149 | 6 | 462 | 0 |
| (extra) memory (hand-written) | 4 | 0 | 0 | 0 |

The whole corpus runs in about 8 s of wall time under Wine.

## 3. Adjudication of every remaining FAIL (new work)

A FAIL means the DBT and the reference disagree; it doesn't say which one is wrong. I adjudicated every remaining FAIL **independently of both** in two ways:

1. **Single-instruction FAILs (383 blocks):** `scripts/adjudicate_oracle.py` recomputes the architecturally correct result from the corpus seed. It uses exact rational arithmetic (`fractions.Fraction`) written from the ARM ARM pseudocode, with FPCR=0 (round to nearest even, no flush-to-zero, no default-NaN), and covers FRINT{N,M,P,Z,A}, FMLA/FMLS and REV. Output: `raw/oracle-sweep-2026-10-08_9f34e2f/ADJUDICATION.md`.
2. **Multi-instruction FAILs (45 blocks):** I fixed the reference's FRINT decode in a **scratch copy** of the oracle (diff: `raw/.../reference-frint-fix.audit.diff`; the repository is untouched) and re-ran. All 45 multi-instruction FAILs disappeared: `raw/.../refpatched/`.

| Family | Verdict | FAIL blocks | Distinct words |
|---|---|---:|---:|
| Vector FRINTM | DBT correct; **reference bug** (FRINTM/FRINTP keyed on bit 29 (U) instead of bit 23, so it computes ceil for M and floor for P) | 264 | 97 |
| Vector FRINTP | DBT correct; reference bug (same root cause) | 45 | 21 |
| Vector FMLA | DBT correct (fused); **reference bug** (reference is now unfused, 1 ULP off) | 39 | 38 |
| Vector FMLS | DBT correct; reference bug (rounding) | 11 | 10 |
| REV (32/64) | DBT correct; reference bug (no byte-reverse, already noted in sweep #1) | 6 | 2 |
| Multi-instruction bb_* blocks | All downstream of the reference FRINT bug (they vanish with the scratch fix) | 45 | — |
| **Vector FMLS with NaN operand** | **DBT wrong.** ARM negates op1 before NaN propagation (FPNeg flips the NaN's sign); the DBT returns the NaN with its original sign | 11 | 11 |
| **Scalar + vector FRINTA, input in (−0.5, 0)** | **DBT wrong.** Returns +0.0; ARM returns −0.0 | 5 | 5 |
| Vector FRINTA (2 blocks) | **DBT wrong** (+0.0 instead of −0.0); the reference is also wrong (−1.0) | 2 | 2 |

**Silent DBT divergences left at 9f34e2f on this corpus: 18 blocks / 18 distinct words, in 2 families.** Both are signed-zero / NaN-sign corner cases:

- **New finding: FRINTA returns +0.0 instead of −0.0 for inputs in (−0.5, 0).** Neither sweep #2 nor the Fable-5 review recorded it. It is probably a side effect of the 2026-07-03 branchless ties-away fix (F4/F6, `lower_simd_ctx.rs` `lower_fpround` / `lower_vecfpround`). That is an inference; I have not root-caused it.
- **FMLS NaN-sign.** Low severity, but it is a real architectural divergence. It is the same class as the "x86 maxps NaN" caveat in sweep #2 §6.

## 4. DBT-only coverage, independent of the reference (new measurement)

Because of the reference-first evaluation order, I measured coverage directly: every distinct word or block goes through the live `DbtRuntime::translate_block`, and I check whether the emitted code contains the fail-loud UD2 sentinel (`dbt::block_bytes_are_safe`). Tool: `bench/aether-dbt-bench coverage`. Logs: `raw/2026-10-08_9f34e2f_dbt-coverage-*.log`; classification: `raw/2026-10-08_9f34e2f_dbt-coverage-single.CLASSIFIED.md`.

| Corpus | Distinct | Translates, no UD2 | Emits UD2 (fail-loud) | Decoder rejects (`Reserved`) | Partial (decode stops mid-block) |
|---|---:|---:|---:|---:|---:|
| Distinct SIMD/FP + trace words | 30,375 | **28,453 (93.7%)** | 1,193 (3.9%) | 729 (2.4%) | — |
| Distinct multi-instruction blocks | 4,958 | **4,503 (90.8%)** | 240 (4.8%) | 79 (1.6%) | 136 (2.7%) |

Largest remaining gap families, by distinct words:
- **UD2:** FCCMP (295; Fable-5 already ranked it the #1 gap), scalar FMUL by element (167), vector FMOV immediate (136), fixed-point UCVTF/SCVTF (163), URSHR/URSRA (72), the widening/narrowing families UADDW/SADDL/SSUBL/RADDHN/ADDHN (~200), SQDMULH/SQRDMULH (52).
- **Decoder `Reserved`:** FABD (231), FCVTL/FCVTN/FCVTL2/FCVTN2 (221), scalar SCVTF/UCVTF/FCVTZS (102), BIF/ORN `.8b` (40, the only gap family visible to the oracle as DBTERR), FRECPS/FRECPE/FRSQRTS/FRSQRTE (42), SQXTUN/UQXTN (39).

Twelve of sweep #2's thirteen fail-loud gap families (G1–G4, G6–G13) are closed. **G5 (ORN/BSL/BIT/BIF) is still open** for the 64-bit (`.8b`) arrangement. Meanwhile the reference-independent measurement shows a larger untested surface (FABD, FCVTL/N, FCCMP, ...) than sweep #2 reported, because those words were SKIPped by the reference.

## 5. What can be claimed

- **Demonstrated (re-run):** the differential oracle runs on a 105,573-block real-Android corpus. On the current commit it shows 78,301 PASS, 422 FAIL and 141 DBTERR. Independent adjudication shows **404/422 FAILs are reference-interpreter bugs and 18 are genuine DBT divergences in 2 families.**
- **Demonstrated (re-run):** the four sweep-#2 silent miscompiles (C1 FCVT narrowing, C2 SCVTF/UCVTF sign, C3 FCVTZ* saturation, C4 FMLA fusion) **no longer reproduce.** The oracle's own known-issue probes report "UNEXPECTED" (that is, fixed), and the corresponding FAIL families are gone from the sweep.
- **Methodology caveat to state in a paper:** with reference-first evaluation, the oracle measures correctness only on the subset the reference models (about 75% of blocks). The DBT's own fail-loud coverage is 93.7% of distinct framework SIMD/FP words and must be measured separately.
