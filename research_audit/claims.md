# Claim audit

**Audited code:** `Vishwesh-AIENG/Project-AETHER` branch `sandbox/aether-translator` @ **`9f34e2f`** (2026-10-08). The private dump `AETHER-FILES` @ `1adc516` is byte-identical to `9f34e2f` for all 400 tracked files, plus untracked local material (logs, corpora, images, notes, docs). `main` holds only README/skeleton commits.

**Evidence classes** used throughout:
- **R** = re-run in this audit
- **L** = preserved log or artifact read, not re-run
- **T** = unit/integration test
- **S** = static inspection of code
- **N** = prose only (memory notes, commit messages, README)
- **A** = author-reported to the auditor, with no artifact in the repository

**Author-reported hardware reproduction (2026-10-08, not independently verified).** The project author states that every milestone the ARM tier reached in QEMU was also reached on a real ARM laptop, and every milestone the x86 tier reached in QEMU was also reached on real x86 hardware, in runs done independently of this audit. No hardware logs, photos, machine models, firmware versions, EFI hashes or build configurations are in the repository or the AETHER-FILES dump, so these runs are classed **A (author-reported)**: stronger than nothing, weaker than a preserved log.

Caveats that a log would resolve:
- The audited ARM build (`9f34e2f`) hard-codes QEMU `virt` addresses (PL011 at `0x0900_0000`, GICD/GICR at `0x0800_0000`/`0x080A_0000`). It also expects QEMU's `-device loader` to have pre-placed the kernel at `0x4080_0000` and the initramfs at `0x4410_0000`. A laptop run therefore implies a different build or loading setup; the paper should state which commit and patches were used.
- CLAUDE.md (2026-10-05) and the `9f34e2f` commit message describe the ARM tier as never run on Snapdragon and as first booting at all on 2026-10-08.
- On x86, the hardware evidence in the dump is `_claude-memory/m4b5-first-hw-boot-log.md`: a real AMD machine reached ExitBootServices and live DBT dispatch on 2026-06-04, photographed, with no serial log. A hardware run of the current `whpx_hostmode` path would still be **host mode (no VMX/SVM)**. Hardware execution does not by itself make the x86 tier a Type-1 hypervisor.

To upgrade A → L, add for each tier: the full serial log (or photos if there is no serial port), machine model, CPU, firmware version, commit plus diff, EFI SHA-256, and kernel/initramfs/image hashes, under `raw/hardware-<date>/`.


## 1. Claims table

| # | Claim (where found) | Evidence location | Reproducible here? | Current status | Confidence | Notes |
|---|---|---|---|---|---|---|
| 1 | **~105k-block real-Android corpus** (`docs/phase-g/oracle-sweep-2.md`) | `tools/dbt-oracle/corpus/*.txt` (14 files) | **R** | **True: 105,573 blocks** (15,993 multi-instruction + 89,520 single-instruction; 30,375 distinct words) | High | Extractor is in `tools/corpus-extract/`. Regenerating the corpus needs the AOSP `system.raw` and an aarch64 objdump (both available in the dump). |
| 2 | **Independent ARM64 reference interpreter** | `tools/dbt-oracle/src/reference.rs` | **R/S** | True, but the reference has its own bugs: FRINTM/P swap, unfused FMLA, no REV (found in this audit) | High | Self-test catches an injected CMHI bug. |
| 3 | **Differential testing finds silent DBT miscompiles** | sweep #2 doc + this audit's sweep | **R** | True. Sweep #2 found 4 (C1–C4), now fixed. This audit found **2 open families** (FRINTA signed zero, FMLS NaN sign). | High (current) / Medium (historical) | The historical pre-fix state is not in git (squashed into `99023be`), so pre-fix FAILs cannot be re-run. |
| 4 | **"~24 confirmed DBT miscompiles"** (user brief) | **nowhere**: no document, note, commit or branch contains it | — | **Unverified; figure not found.** Recoverable documented count: **5 oracle-found** (C1–C4 + RSHRN) + **13 adversarial-review live defects** (Fable-5 S1, S2, F1–F7, L1–L4; the notes say "15", which includes the latent S3 and D1) + **2 new** (this audit) | — | Use the itemised list in `bug_taxonomy.md`, not "24". |
| 5 | FCVT narrowing / SCVTF sign / FCVTZ* saturation / FMLA fusion / RSHRN saturation bugs | sweep #2 §4, `at_exec_proof.rs` | **R** (fix side) | **Fixed.** The oracle's known-issue probes no longer reproduce, the families are absent from the current sweep, and regression tests pass (`fcvt_narrow_zeroes_upper_bits_execute`, `scvtf_ucvtf_wform_sign_execute`, `fp_vector_fcvtzs_saturation`, `fmla_4s_executes`, `rshrn_modular_narrow_no_saturation`) | High | |
| 6 | SP-as-XZR in atomics (Fable-5 L1) | `docs/phase-g/fable5-lift-review.md` | **T** | Fixed; lift tests `lift_ldar_sp_base_reads_sp_not_xzr`, `lift_swp_sp_base_reads_sp_not_xzr` pass | Medium-High | Pre-fix behaviour documented with exact encodings; not re-executable (pre-fix code not in git). |
| 7 | Adversarial "Fable-5" review found 15 live miscompiles | 4 `docs/phase-g/fable5-*.md` files | **T** | 13 distinct live defects + 1 defensive (S3) + 1 latent (D1, **not applied**: `SDiv/UDiv` still clobber RDX, unreachable on the live path) | Medium-High | Each has a repro encoding and expected/actual values; regression tests exist and pass. |
| 8 | **1,300+ passing tests** (README badge "1300 passing") | `cargo test` | **R** | **Stale (undercount).** Today: **2,177 pass / 1 fail / 10 ignored** = 1,330 hypervisor (host x86 unit tests, not ARM tests) + 794 translator (215 execution tests are Windows-only, run under Wine) + 64 tools | High | The 1 failure writes to `D:/AETHER/qemu/test.dtb` (environment). The commit message of `9f34e2f` says 2,178. |
| 9 | **"1,300+ passing ARM tests"** | — | **R** | **Misleading.** No test runs on ARM. All 1,330 hypervisor tests run on the x86 host; 71% of the hypervisor's inline tests exercise files absent from both boot images (claim 12). | High | |
| 10 | **64 completed chapters** (`sandbox/x86_64-port` CLAUDE.md "58 → 64"; README badge "58/70") | `CLAUDE.md` (dump, rewritten 2026-10-05) | **S** | **False under any runtime definition.** Current self-audit: 13 Live / 17 Partial / 19 Spec-only / 15 Design / 6 Not started. "Complete" used to mean "typed module + gate struct + unit tests". | High | |
| 11 | Chapters 34/35/36 "Validated" (commits `17d9cd5`, `e2d6cac`, `2098780`, 2026-05-15) | git history | **R/S** | **Were false when committed.** The first boot to userspace was 2026-10-08 (`9f34e2f`: "The ARM tier had never booted on this machine"). The ch35 commit's "PSCI **HVC**" conduit was itself one of the bugs fixed. | High | 146 days between "Validated" and the first runtime proof. |
| 12 | **~50/86 modules with no live caller** (`_claude-memory/baseline-2026-10-05.md`) | linker-level attribution: `raw/2026-10-08_9f34e2f_image-attribution-*.md` | **R** | **Confirmed and sharpened: 47 of 88 hypervisor source files contribute no code to either shipped EFI image** (aarch64, or x86 `whpx_hostmode`). Translator: 35/64 files absent from the x86 image, including all of `opt/`, `ssa/` and 11 spec `runtime/*` modules. | High | Method: PDB line tables of the LTO release build; every instruction symbolised with its full inline chain; a file is present if it appears in any frame. Presence ≠ execution; absence = unreachable from that image's entry point. |
| 13 | **GKI 6.1 boot** | ARM: `run-arm-auto.py`; x86: old log; hardware: author report | **R** (QEMU) / **A** (hardware) | ARM: GKI 6.1.79 boots under EL2 to EL0 (TCG). x86: translated GKI boots (TCG here, early init; WHPX old log to init and later). The author reports the same milestones on a real ARM laptop and on real x86 hardware. | High (QEMU) / Low-Medium (hardware, no log) | See the hardware note above. |
| 14 | **Android `init` runs** | `raw/old-evidence/x86-serial-com1.log.gz` (WHPX) | **L** | True in the old log: `Run /init` at guest t=191 s, init executing `init.rc`. Not re-run (needs WHPX; TCG too slow). | Medium-High | x86 host-mode DBT only. Never on the ARM tier. |
| 15 | **apexd runs** | same log | **L** | apexd-**bootstrap** ran and exited 0 (`Activated 3 package`) | Medium-High | |
| 16 | **33 APEXes activated** | memory note only | **N** | **Unverified.** No log in the dump. Relied on image-side edits (converted .capex, SELinux xattrs, `/metadata` + `/data`) that are not in the repository. | Low | |
| 17 | **bpfloader success** | memory note only | **N** | **Unverified.** Same as 16; also needs a kernel sysctl patch (`qemu/patches/0001-…`, in git). | Low | |
| 18 | **zygote** | — | — | **Never evidenced.** `init.zygote64_32.rc` is only *parsed*. The latest notes say "next: zygote". | High (that it was **not** reached) | Must not be claimed. |
| 19 | **346K dispatches/s under WHPX** | memory note + `docs/GAP-ROADMAP.md` | **No** (needs Windows/WHPX) | **Unverified / anecdotal.** No script, no timestamped log. This audit measured **21.8K/s median under TCG** (range 17.4K–641K/s; strongly phase-dependent). | Low | See `benchmarks.md` §5 and the runbook in `reproducibility.md`. |
| 20 | **EL2 hypervisor bugs** (9 "runtime rules", 12 fixes) | `9f34e2f` diff, `CLAUDE.md` | **R** (fault injection) | **Real: 7/7 revertible fixes confirmed by fault injection.** Reverting any one of EOImode=1, AMBA PL011 node, SMC conduit, ELR+=4 on emulated traps, ID-register sanitising, HCR.APK/API, or MADT topology breaks the ARM proof with the documented symptom (`bug_taxonomy.md` §B). | High | QEMU only. |
| 21 | Stage-2 tables / EL2 state outside guest RAM | `main.rs`, `boot.rs`, `el2_mmu.rs` | **R/S** | True on the ARM boot path: allocator `largest_conventional_outside`, a static EL2 stack, an AETHER-owned EL2 page table, and a launch guard. Exercised by every ARM proof run. | High | QEMU only. |
| 22 | GIC EOImode=1, PSCI via SMC, AMBA PL011 DT node (ttynull fix) | code + fault injection | **R** | True; each reproduced by fault injection (B1, B2, B3). | High | |
| 23 | **Bare-metal Type-1 hypervisor** (README, CLAUDE.md) | `main.rs`, `boot_x86.rs` | **R/S** | **ARM tier: an EL2 hypervisor reproduced under QEMU TCG** (emulated EL2); a run on a real ARM laptop is author-reported, with no log and an unidentified build (the audited binary is QEMU-virt-specific). **x86 tier: not a hypervisor in its working configuration.** The Android boot runs in UEFI host mode with no VMX/SVM. VMLAUNCH/VMRUN appear only on a "not armed" smoke path that runs a HLT stub. | High | See §3. |
| 24 | **FEX-Emu DBT inside the hypervisor** (README) | `hypervisor/third_party/fex/` | **S** | **Obsolete.** The FEX directory is a stub crate; the in-tree `aether-translator` replaced it. The `fex_linked` feature now aliases the in-tree DBT. | High | |
| 25 | **"250k LOC"** | — | **R** | **Not supported.** All tracked code in all languages is ~100k code lines (~155k raw including comments and blanks). Production Rust is 63.6k. | High | See §4. |
| 26 | "Production Android", "full app compatibility", "undetectable", Phone Bridge, synthetic IMEI/IMSI, Snapdragon, frame-time targets (README) | README, spec modules | **S** | **Unsupported.** No app ever ran; no UI; GPU/NVMe/USB/network/AVB/OTA/recovery/phone-bridge modules are spec-only (absent from both images); never run on Snapdragon or bare-metal x86. Identity/fingerprint modules are tables with no boot-path caller. | High | Remove from any paper. |
| 27 | Hardware validation (`HARDWARE_VALIDATION.md`, memory `m4b5-first-hw-boot-log.md`, author report 2026-10-08) | notes + author statement | **N / A** | Note: real AMD box reached live DBT dispatch on 2026-06-04 (photos). Author: all QEMU milestones reproduced on a real ARM laptop and real x86 hardware. No logs in the dump. | Low-Medium | Needs logs, machine details and build identity (see hardware note). The audited ARM binary is QEMU-virt-specific. |

## 2. "Passing tests vs working system" (quantified)

| Metric | Value | Source |
|---|---:|---|
| Hypervisor source files | 88 | tree |
| … contributing code to the ARM EFI | 23 (incl. `irq_forward.rs`, fully inlined) | line-table attribution |
| … contributing code to the x86 (whpx_hostmode) EFI | 22 | line-table attribution |
| … contributing to **either** image | **41** | |
| … contributing to **neither** image | **47 (53%)** | |
| Hypervisor production LOC in image-present files | 19,173 of 33,557 (57%) | `scripts/rust_loc_split.py` |
| Hypervisor inline `#[test]`s in image-absent files | **1,146 of 1,618 (71%)** | |
| Translator files absent from the x86 image | 35 of 64 | |
| Translator integration tests targeting absent modules (`at17`, `at18`, `at20`–`at23`, `at25`–`at30`, `at6`–`at8`, `at10`) | 239 | |
| Example: `runtime/perf_bench.rs` ("AT-30 Performance Benchmarks") | 25 passing tests; **no timing code at all** (UART-string parser + thresholds) | `at30_perf_bench.rs` |
| Example: `runtime/zygote_launch.rs` | 20 passing tests; zygote never started | `at28_zygote_launch.rs` |
| Example: ch46 "Adreno GPU — Rendering — Functional" (2026-05-17) | spec-only; no GPU path exists | git log, `adreno_render.rs` absent from images |
| Example: ch34–36 "Validated" (2026-05-15) | first runtime proof 2026-10-08, after 12 fixes | git log, `9f34e2f` |
| Modules exercised during an **Android** boot | Only the x86 image's 22 hypervisor files + 29 translator files can participate. On the ARM tier, Android never booted. | |

**Lesson worth stating in a paper:** for a systems artifact developed largely by AI coding agents, "chapter complete" (types + gate struct + unit tests) diverged from "runs at boot" for most modules. The divergence was invisible to the test suite and was only exposed by (a) runtime boot proofs and (b) linker-level reachability.

## 3. Bare-metal / Type-1 audit (code-traced)

| Component | Implemented | Unit-tested | Executed end-to-end | Where |
|---|---|---|---|---|
| UEFI entry, ExitBootServices retry loop | yes | yes | **yes** (ARM + x86, QEMU) | `boot.rs`, `main.rs`, `boot_x86.rs` |
| ARM EL2: vectors, HCR/VTCR/VTTBR, Stage-2 tables | yes | yes | **yes (QEMU TCG, emulated EL2)** | `arm64/*`, `memory.rs` |
| EL2-owned stage-1 identity map, static EL2 stack, isolation guard | yes | partly | **yes (QEMU)** | `el2_mmu.rs`, `boot.rs` |
| Trapped-sysreg emulation, ID sanitisation | yes | yes | **yes (QEMU)** | `sysreg_trap.rs`, `arm64/exception.rs` |
| GICv3 physical + vGIC (EOImode=1, HW-linked LRs, SGI forwarding) | yes | yes | **yes (QEMU)** | `gic.rs`, `irq_forward.rs` (inlined) |
| PSCI CPU_ON via SMC, MADT topology | yes | yes | **yes (QEMU, 1 and 4 CPUs)** | `smp.rs` |
| SMMU programming | types only | yes | **no** (`SMMU_STREAM_TABLE` declared, never programmed) | `main.rs` |
| x86 VMX: VMXON, VMCS, EPT | yes | yes | **smoke path only** (unarmed; guest = HLT). **Not used** for Android. | `vtx.rs`, `boot_x86.rs::boot_intel` |
| x86 SVM: VMCB, NPT, VMRUN loop | yes | yes | **smoke path only**; not used for Android | `svm.rs`, `boot_x86.rs::boot_amd` |
| x86 Android execution | — | — | **UEFI application, ring 0, host mode**: CALLs translated blocks; software MMU for guest memory; UEFI's identity-mapped CR3 plus a host IDT. **No hardware isolation between AETHER and the Android guest.** | `boot_x86.rs::run_android_dispatch_loop` |
| GDT/IDT | x86 host IDT installed (`host_idt.rs`); firmware GDT reused | — | yes | |
| Raw memory ownership | ARM: Stage-2 identity map of 2 GiB. x86: a fixed software-MMU window (`aether_mmu_set_window`) | | yes (QEMU) | |
| Real hardware | ARM laptop and x86: **author-reported** (no artifacts). AMD: one note of DBT dispatch on hardware (photos, 2026-06-04) | | **author-reported, not verified** | The audited ARM build hard-codes QEMU-virt addresses |

**Verdict** (the author additionally reports hardware runs of both; see the hardware note): what has been demonstrated **in this audit** is "**an ARM64 EL2 hypervisor that boots GKI to userspace under QEMU's emulated EL2**" and, separately, "**a UEFI-hosted ARM64→x86-64 system-level DBT that boots Android's kernel and early userspace under QEMU (WHPX/TCG)**". Calling either "bare-metal Type-1" for Android is not supported by runtime evidence.

## 4. Android image / ELF pipeline

| Stage | Implemented | Tested | Executed end-to-end | Notes |
|---|---|---|---|---|
| boot.img v3/v4 header parse | yes (`bootloader.rs`, `android_boot.rs`) | yes | **yes (x86)**: `[android] boot.img found … kernel_pa=…` | ARM tier ignores boot.img; QEMU's loader places the raw Image. |
| ESP file read (boot.img) | yes (`boot_x86_esp.rs`) | — | **yes (x86)** | |
| Kernel Image header validation | yes (`kernel.rs`) | yes | **yes (both)** | |
| gzip inflate | yes (`inflate.rs`) | yes | in image; this kernel is uncompressed (`kernel uncompressed`) | |
| DTB generation (FDT) | yes (`kernel.rs`, `android_handoff.rs`) | yes | **yes (both)**; `[fdt] checks: PASS` | |
| Ramdisk / initramfs | cpio newc length scan (`cpio.rs`) on ARM; placement on x86 | yes | **yes** | AETHER does not extract the ramdisk; the guest kernel does. |
| Partition / GPT parsing | installer tool only (`tools/aether-install/src/gpt.rs`) | yes | **not on any boot path** | |
| system/vendor image loading | **QEMU `-device loader`** stages raw ext4 images; AETHER exposes them as PMEM DT nodes and checks the ext4 magic | — | yes (x86) | AETHER does not parse ext4. |
| AVB verification | `avb_boot.rs`, `boot_x86_avb.rs` | yes | **no** (absent from images) | |
| **ELF parsing / segment mapping / stack setup / entry transfer for Android init** | **not in AETHER**. `aether_dbt_load_arm64_elf` is a stub returning `Ok`. | — | Done by the **guest Linux kernel** (`binfmt_elf`) running under the DBT | |
| Android init execution | — | — | x86 (old WHPX log): yes. ARM: no. | |

## 5. LOC (claim: 250k)

| Category | Lines | Notes |
|---|---:|---|
| **Rust production code** (non-blank, non-comment; excluding `#[cfg(test)]` and `tests/`) | **63,649** | hypervisor 33,557 · translator 22,875 · dbt-oracle 2,622 · installer 2,891 · setup GUI 871 · compat 751 · other 82 |
| Rust test code | 30,847 | 17,138 inline + 13,709 `tests/` |
| Rust comments | 40,513 | heavy doc comments (27% of all lines) |
| Rust blank | 11,977 | |
| Shell / Python / PowerShell / batch scripts (tracked) | ~2,800 code | build/boot/watch scripts; 31 more scratch scripts untracked |
| AOSP device configs (XML/make/C++/rc) | ~1,050 code | `aosp/device`, `tools/aosp-device-port` |
| **All tracked code, all languages** | **~99,970** (cloc) | ~155k raw lines with comments and blanks |
| Docs (CLAUDE.md, docs/, READMEs, build spec) | ~4,300 lines markdown + 162 KB RTF spec | untracked/local |
| AI-session memory notes | ~5,200 lines | `_claude-memory/` |
| Generated corpora (oracle) | 7.5 M lines | generated; must not be counted |
| Generated disassembly | 267 MB | generated |
| Vendored third-party | ~0 | `third_party/fex` is a 51-line stub; no vendored C/C++ |

**Project-authored code: ≈ 64k lines of production Rust (≈ 95k including tests).** "250k LOC" is reachable only by counting comments, docs, notes or generated data. Note also that the commit trailers show much of the code was produced with AI coding agents (`Co-Authored-By: Claude …`); a paper should disclose that.

## 6. What we can actually claim

### Demonstrated (reproduced in this audit)
1. A host-side **differential oracle** with an independent hand-written ARM64 reference runs over **105,573 basic blocks from real Android 64-bit libraries** (libhwui+Skia, SurfaceFlinger+RenderEngine, ART, binder, …). On the current commit: 78,301 PASS / 422 FAIL / 26,709 SKIP / 141 DBTERR. Third-party adjudication shows **18 FAILs are genuine DBT defects (2 families, 1 newly found) and 404 are reference-interpreter defects.**
2. The DBT translates **93.7%** of 30,375 distinct framework SIMD/FP instruction words and 90.8% of 4,958 distinct real basic blocks without a fail-loud gap; the remaining gaps are enumerated.
3. The previously reported silent-miscompile classes (FCVT narrowing, SCVTF/UCVTF sign, FCVTZ* saturation, FMLA fusion, RSHRN saturation, FRECPE mis-decode, FMAX/FMIN NaN/±0, ties-away rounding, `.8b` pairwise leak, byte shift by 8, SP-as-XZR in atomics, CMP SP, B/H FP load/store, AND SP,#imm) are **fixed and covered by passing regression tests**.
4. **ARM tier:** an EL2 hypervisor boots GKI 6.1.79 to EL0 userspace with 1 or 4 vCPUs, per-CPU timer interrupts and IPIs, under QEMU TCG with emulated EL2 (N=10 timed runs, 100% success). EL2 bring-up costs < 50 ms.
5. **x86 tier:** the UEFI-hosted DBT boots the ARM64 GKI kernel through early init under QEMU TCG (median 21.8K dispatches/s).
6. Translation cost of about 1.7 µs per real basic block (580K blocks/s, 3.1M ARM insns/s); cache hit ≈ 33 ns (≈ 52× cheaper than a miss); about 69 bytes of x86 per ARM instruction.
7. Test suite: 2,177/2,178 pass (1 environment failure).
8. **Linker-level fact:** 47/88 hypervisor files and 35/64 translator files are absent from the shipped images; 71% of hypervisor unit tests target that absent code.

### Strongly supported (substantial preserved evidence, not re-run)
9. Under WHPX, the x86 tier ran Android's kernel to **`init`** (guest t=191 s) and through `apexd-bootstrap`, post-fs/late-fs, up to `keystore2` start (preserved log).
10. The Fable-5 adversarial review found 13 live miscompiles with exact repro values; fixes and regression tests exist (pre-fix code not preserved in git).
11. A long series of boot-driven DBT bug fixes (ADR/ADRP PC, REV/BSWAP, RBIT, UMULH, LDPSW scale, LSE atomics, TBZ NZCV, WriteGpr truncation, TBL multi-register, CMHI .2d, chained-block PC slot) is documented in commits and notes and has regression tests.

### Partially demonstrated
12. "Android boot": kernel + init + early services, x86 host-mode DBT only, under QEMU WHPX; not on the hypervisor path; no zygote.
13. EL2 isolation properties: implemented and exercised in QEMU, with no adversarial guest testing and no SMMU.
14. Throughput: per-block microbenchmarks and TCG dispatch rate only; no whole-system baseline.

### Unverified
15. apexd **33 APEXes activated**; **bpfloader exit 0** (notes only; logs and image changes not in the repository).
16. **346K dispatches/s under WHPX** (no method, no log).
17. "~24 confirmed DBT miscompiles" (number not found anywhere).
18. Runs on real hardware. **Author-reported:** the ARM tier reached its QEMU milestones (GKI → EL0, 4 CPUs) on a real ARM laptop, and the x86 tier reached its QEMU milestones on real x86 hardware. One AMD note from 2026-06-04 (photos) is the only artifact. **Publishable once logs and setup details are added.**

### Unsupported / should be removed
19. "Bare-metal **Type-1** hypervisor delivering production Android". The x86 Android path is not virtualised; the ARM path has never booted Android (its hardware run is author-reported and reaches only GKI → EL0 test binary).
20. "Full app compatibility", "production Android", any UI/frame-time numbers (≤ 17 ms / ≤ 33 ms p99).
21. "Undetectable / no fingerprint", attestation evasion, synthetic device identifiers (IMEI/IMSI), Phone Bridge Mode: spec tables only.
22. "Snapdragon X Elite support" as a product claim (the author reports a laptop boot to the same milestones; even with logs, that supports "boots GKI to userspace on <model>", not support); GPU SR-IOV; NVMe/USB/network passthrough; AVB; OTA; recovery.
23. "FEX-Emu inside the hypervisor" (replaced by the in-tree DBT).
24. "1,300+ passing **ARM** tests", "64 completed chapters", "250k LOC".
25. **zygote / SurfaceFlinger reached.**

## 7. Paper-oriented summary

1. **Strongest contribution.** Differential validation of a system-level ARM64→x86-64 DBT against an independent reference, on 105,573 blocks drawn from real Android framework libraries, plus a quantified taxonomy of the silent miscompiles it exposes. They concentrate in FP/SIMD semantic gaps between ARM and x86: NaN propagation, signed zero, saturation, rounding, fusion. A second-order finding: the reference itself was wrong for about 96% of today's FAILs, so the method needs a third arbiter (here, exact-arithmetic adjudication).
2. **Secondary contributions.**
   - (a) An EL2 bug taxonomy with fault-injection confirmation: 7/7 runtime rules are necessary (protected-state ownership, preferred-return exit handling, ID sanitising, PAC traps, EOImode, PSCI conduit, DT console).
   - (b) A "passing tests ≠ working system" experience result for an AI-agent-built codebase: 47/88 modules absent from the images, 71% of unit tests on dead code, chapters "Validated" 146 days before the first boot.
   - (c) Evidence that a host-side oracle finds in minutes what took many multi-hour boots.
   - (d) Measurements of the live DBT design: per-instruction context round-trip at ~69 B/insn and soft-MMU-dominated memory cost.
3. **Exact reproducible numbers.** See `README.md`: corpus 105,573; 78,301/422/26,709/141; 18 genuine divergences; 93.7% coverage; 2,177/2,178 tests; 7/7 fault injections; ARM `PROOF done` 13.0 s median (smp4, N=5); 21.8K dispatches/s (TCG); 580K blocks/s; 33 ns cache hit; 63.6k production LOC.
4. **Furthest runtime milestone.** Reproduced: ARM GKI 6.1 → EL0 test binary with 4 CPUs under emulated EL2; x86 translated GKI early boot under TCG. Preserved log (WHPX): Android `init` → apexd-bootstrap → `keystore2` start at guest t=2177 s. Notes only: apexd-33, bpfloader. Never: zygote.
5. **Main limitations.** Hardware runs are author-reported only, with no logs or setup details in the repository. The x86 tier is not virtualised. The ARM tier never booted Android. No whole-system baseline. Images and logs for the deepest milestones are not reproducible from the repository. Pre-fix code states are squashed. The oracle is single-block, register-only and reference-first.
6. **Benchmark gaps.** WHPX dispatch rate and time-to-milestone with host timestamps (runbook); boot-time cache hit rate (counter exists, not printed); memory-heavy workloads with the MMU on; whole-system profile.
7. **Baseline gaps.** QEMU system-mode TCG booting the same AOSP images; FEX-Emu on user-space workloads (the corpus blocks or a static benchmark); native ARM hardware. Box64 does not apply (wrong direction).
8. **Reproducibility gaps.** Image manifests and hashes; the apexd/bpfloader logs; kernel and initramfs rebuild; a scripted 346K measurement; per-fix git history for July 2026.
9. **Recommended framing.** Today: a **workshop paper or experience report**, e.g. "Differential testing of a system-level ARM64→x86 DBT on real Android code: what silent miscompiles look like", with the agent-built-systems lesson as a second theme. Not a full systems paper: hardware results are not yet documented (author-reported only), no whole-system performance comparison, and no Android boot past early userspace on the hypervisor path. A technical report can carry the full taxonomy and artifacts.
10. **Confidence.**

| Claim | Confidence | Why |
|---|---|---|
| Oracle and corpus exist and work as described | High | Re-run, deterministic, self-test catch |
| 18 genuine divergences today; 404 reference bugs | High | Exact-arithmetic adjudication plus a scratch reference fix |
| 18 historical silent miscompiles found and fixed | Medium-High | Exact repros documented and regression tests pass; pre-fix states not in git |
| EL2 bugs real and necessary | High | Fault injection, QEMU only |
| ARM GKI → userspace under EL2 | High (QEMU) / Low-Medium (hardware) | Reproduced N=10 under TCG; laptop run author-reported, no log; audited build is QEMU-virt-specific |
| x86 milestones on real hardware | Low-Medium | Author-reported; one AMD photo note (2026-06-04) |
| Android init under the x86 DBT | Medium | One preserved WHPX log; not re-run |
| apexd 33 / bpfloader | Low | Notes only |
| zygote | High that it was *not* reached | No evidence anywhere |
| 346K dispatches/s | Low | No method or log; TCG measures 21.8K |
| Dead-code / test-divergence numbers | High | Linker line tables, reproducible script |
| Type-1 bare-metal Android | Unsupported | x86 path not virtualised (also on hardware: host mode); ARM tier never booted Android (hardware run author-reported, kernel → test binary only) |
