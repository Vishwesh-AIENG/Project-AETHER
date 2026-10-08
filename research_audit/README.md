# AETHER research audit (2026-10-08)

A fresh, evidence-driven audit of what AETHER actually demonstrates, written to decide what an 8–12 page systems paper can honestly claim. **Evidence beats documentation:** every number below was re-run in this audit unless it is marked otherwise.

**Audited code:** `Project-AETHER` branch `sandbox/aether-translator` @ `9f34e2f`. This is identical to the private `AETHER-FILES` dump for all tracked files; the dump also carries the logs, corpora, images and notes. **No AETHER source was modified.**

## Files

| File | Contents |
|---|---|
| [`claims.md`](claims.md) | Claim-by-claim table (evidence, reproducibility, status, confidence); passing-tests-vs-working-system numbers; bare-metal/Type-1 audit; image/ELF pipeline; LOC; the **"What we can actually claim"** classification |
| [`oracle_results.md`](oracle_results.md) | Differential oracle on 105,573 real-Android blocks, re-run; independent adjudication of every FAIL; reference-independent DBT coverage |
| [`bug_taxonomy.md`](bug_taxonomy.md) | DBT miscompiles (oracle / adversarial review / boot-found) and EL2 hypervisor bugs, with **fault-injection confirmation** |
| [`benchmarks.md`](benchmarks.md) | Translation throughput, cache hit/miss, per-family execution microbenchmarks vs a QEMU TCG baseline, dispatch rate |
| [`boot_milestones.md`](boot_milestones.md) | Exact last reproducible milestone per tier, with timestamps |
| [`reproducibility.md`](reproducibility.md) | Environment, every command, infrastructure issues, gaps, Windows/WHPX runbook |
| `raw/` | All logs and outputs, named `2026-10-08_9f34e2f_*` or in dated directories. `raw/old-evidence/` holds prior logs copied from the dump (not re-run). |
| `scripts/` | Analysis tools: oracle classification and adjudication, coverage, line-table reachability, LOC split, ARM milestone timer, EL2 fault injection |
| `bench/` | `aether-dbt-bench` (harness over the live translate path) and the QEMU TCG baseline program |

## One-paragraph verdict

AETHER's **strongest defensible result is the differential-testing work on its ARM64→x86-64 DBT.** An independent hand-written ARM64 reference interpreter is compared against the real translator on **105,573 basic blocks taken from real Android 64-bit libraries**. On today's code it yields 78,301 PASS / 422 FAIL / 141 DBTERR. Third-party exact-arithmetic adjudication attributes **404 FAILs to reference bugs and 18 to genuine DBT defects in 2 families**, one of them newly found here (FRINTA loses the sign of −0). Together with an AI adversarial review, this workflow found and fixed **18 documented silent miscompiles**, almost all in FP/SIMD semantics where x86 and ARM differ. The **ARM-tier EL2 hypervisor boots GKI 6.1 to EL0 userspace on 1 or 4 vCPUs, but only under QEMU's emulated EL2.** Seven of its boot-blocking bugs were **reproduced by fault injection**. **Android userspace was only ever reached on the x86 tier, which runs as a UEFI application in host mode (no VMX/SVM), not as a hypervisor.** The furthest preserved log reaches `init` → apexd-bootstrap → `keystore2` start under WHPX. apexd-33/bpfloader exist only in notes, and **zygote was never reached.** A second, equally important finding: **47 of 88 hypervisor source files contribute no code to either boot image, and 71% of the hypervisor's unit tests exercise that code.** "Chapter complete" and "runs at boot" diverged for most of the project.

## Headline numbers (re-run, commit 9f34e2f)

| Quantity | Value |
|---|---|
| Oracle corpus | 105,573 blocks (15,993 multi-instruction + 89,520 single), 30,375 distinct instruction words, 13 Android libraries/binaries |
| Oracle result | 78,301 PASS / 422 FAIL / 26,709 SKIP / 141 DBTERR (sweep #2 at the July commit: 74,564 / 1,903 / 26,754 / 2,352) |
| Genuine DBT divergences today | 18 blocks, 2 families (FRINTA ±0, FMLS NaN sign); both open |
| DBT coverage, reference-independent | 93.7% of distinct framework SIMD/FP words; 90.8% of distinct real blocks |
| Documented silent miscompiles, fixed + regression-tested | 5 oracle-found + 13 adversarial-review-found (+ ~15 boot-found, narrative) |
| Tests | 2,177 pass / 1 fail (hard-coded `D:\` path) / 10 ignored |
| EL2 bugs confirmed by fault injection | 7 / 7 |
| ARM boot (QEMU TCG, N=10) | 100% reach `PROOF done`; firmware 5.8 s; EL2 bring-up < 0.05 s; kernel → userspace done 7.1 s (smp4) |
| x86 tier under TCG | translated GKI boots; median 21.8K dispatches/s; `init` not reached in 400 s |
| Translation | 580K real blocks/s (3.1M ARM insns/s), 1.7 µs/block; cache hit 33 ns (≈52× cheaper); ~69 B x86 per ARM insn |
| Reachability | 47/88 hypervisor and 35/64 translator files absent from the shipped images |
| Code size | 63.6k lines of production Rust (+30.8k tests); ~100k code lines overall, not 250k |

The paper-oriented summary (contributions, limitations, gaps, framing and confidence) is the final section of `claims.md`, and was also given in the session reply.
