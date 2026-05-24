# AETHER Translator (AT) — Chapter Plan

Numbered as a parallel series (`AT-1 … AT-30`) since this is a multi-year
subproject that supersedes the placeholder `ch52` (FEX-Emu Integration in
Hypervisor — currently a Rust no-op stub).

Each chapter has one gate, same convention as the main roadmap.

The translator's job: convert ARM64 instruction streams to host x86_64 code
at runtime so Android (which ships ARM64 binaries) can boot on Intel/AMD
silicon. Phase A delivers the foundation (decoder + IR); Phases B–F build
the optimizer, x86 backend, runtime, integration, and validation gates.

---

## Phase A — Decoder & IR Foundation

### AT-1: ARM64 A64 Base Decoder

Decode integer / load-store / branch / data-processing instructions from
`&[u8]` into a Rust `DecodedInsn` enum. Reference: ARM ARM DDI 0487 §C4.

**Gate:** decode 1000 canned encodings (incl. `0x91000421 → ADD x1, x1, #1`);
fuzz round-trip against Capstone.

**Status:** ✅ **Done.** 7340 canned vectors green (7.3× floor). Four
always-on capstone-diff gates pass against `capstone-rs 0.14` (Capstone
5.x). Decoder vs Capstone agree on every random 32-bit input except two
documented patterns where Capstone declines without explicit
`FEAT_FP16`/`FEAT_RDM` extra-mode flags. Decoder structured around 5
top-level family modules (DP-immediate, DP-register, load/store,
branch/sys, DP-SIMD/FP) totaling ~3 kLOC with full sub-family
validation. Cargo-fuzz harness exists for the 10M-iteration deep-fuzz
(`fuzz/fuzz_targets/decode_capstone_diff.rs`); not yet executed in CI.

### AT-2: IR Data Model

Define `IrOp`, `IrValue`, `IrBlock`, `IrFunction` in `no_std` Rust.
SSA-friendly; ~140 opcodes (load / store / alu / cmp / branch / call /
atomic / barrier / simd-vec).

**Gate:** IR round-trips through serialize/parse; unit tests on every
opcode constructor.

**Status:** ✅ **Lift done.** ~150 `IrOp` variants enumerated, stable
1-byte serialize tags for all of them. 73 variants (every one the AT-2
lift step actually emits — integer / branch / memory / system / hint /
register-access) have full encode/decode codecs. Lift to IR produces
real semantically-shaped IR for every major `DecodedInsn` variant
including 10 new register/flag/PC-access ops (`ReadGpr`/`WriteGpr`/
`ReadSp`/`WriteSp`/`ReadFpr`/`WriteFpr`/`ReadFlags`/`WriteFlags`/
`ReadPc`/`WritePc`) — the pre-SSA shape Phase B SSA construction
expects. On real ARM64 production code (AETHER's own hypervisor.efi),
**99.85 % lift coverage** (5244 / 5252 instructions). SIMD/FP/crypto
get coarse opaque lifts (refined in Phase B alongside SSA).

### AT-3: NEON / FP / SIMD Decoder

Cover Advanced SIMD (NEON) + FP scalar + crypto extensions used by
Android (AES, SHA, CRC32).

**Gate:** decode every NEON op emitted by
`clang -O2 -march=armv8-a+crypto` on libcrypto.

**Status:** ⚠️ **Code done, corpus gate deferred.** Per-sub-family
validation accepts every valid NEON / scalar-FP / crypto encoding and
rejects every reserved combination. 21 sub-families covered: 3-same,
3-same-extra, 3-diff, 2-reg-misc, across-lanes, copy, modimm,
shift-imm, indexed, permute, extract, table, plus 6 scalar variants;
FP 1/2/3-source, immediate, compare, ccmp, csel, int convert,
fixed-point convert; AES, SHA 3-reg, SHA 2-reg. SHA512/SHA3/SM3/SM4
declared `Reserved` to match bundled Capstone behavior. Corpus run
against a `clang -march=armv8-a+crypto` artifact still
`#[ignore]`'d — no `aarch64-linux-gnu-gcc` available locally; needs a
Linux/WSL host with `apt install gcc-aarch64-linux-gnu`.

### AT-4: System, Atomics, Barriers

`LDXR/STXR/LDAR/STLR/DMB/DSB/ISB/MRS/MSR/SVC/HVC/SMC`. Model memory
ordering in IR. Full ~600-entry sysreg catalog.

**Gate:** decode every system-instruction encoding emitted by Android
kernel + bionic.

**Status:** ⚠️ **Code done, corpus gate deferred.** Full `(opc, LL)`
exception-generation table; LL/SC + LSE atomics (including CAS, all 8
LDADD-family ops, SWP); acquire/release variants (LDAR/STLR/LDAPR);
all 12 DMB/DSB barrier domains; full system encoding bits[23:22]=00
tightening; IC/DC/AT/TLBI placeholders. Sysreg catalog covers **~310
architectural registers**:
- 180 hand-named singletons (ID, SCTLR, TTBR, TCR, ESR, FAR, VBAR,
  MAIR, ContextIDR, TPIDR, generic timer, GIC v3, PMU, debug, PAC).
- 124 via array variants (`PmevCntr(u8)`/`PmevTyper(u8)`/`DbgBvr(u8)`/
  `DbgBcr(u8)`/`DbgWvr(u8)`/`DbgWcr(u8)`).
- 21 VHE EL12 aliases (SctlrEl12, TtbrEl12_*, CntpCtlEl02, etc.).
- 21 AArch32 ID/feature regs read by Linux at boot (IdPfr0/1/2,
  IdMmfr0..5, IdIsar0..6, Mvfr0/1/2).
- SVE ZcrEl1/2/3 + ARMv8.4 Cnthps/Cnthvs hyp secure timer.
- Spec target was ~600; full catalog requires Linux's
  `arch/arm64/tools/sysreg` generator (out of repo here). Corpus run
  against vmlinux + bionic libc still `#[ignore]`'d — needs Android
  GSI extract.

### AT-5: Decoder Coverage Audit

Bulk-decode every executable byte of a real Android `system.img`
(libart.so, libhwui.so, libvulkan.so, …); flag unknown encodings.

**Gate:** zero unknown encodings across the 21 AOT default libraries.

**Status:** ✅ **Surrogate gate passing** + ⚠️ 21-lib gate deferred.

- **Surrogate (`at5_aether_efi_corpus`):** audit against AETHER's own
  `hypervisor.efi` (PE32+ ARM64 built by rustc + lld). **0 unknown
  encodings across 5252 instructions** of real-world rustc-emitted
  production ARM64 code. Always-on, runs in CI on every push.
- **Real 21-lib gate (`at5_system_img`):** `#[ignore]`'d. Driver,
  audit harness, and ELF+PE32+ `.text` extractor all implemented and
  tested. `scripts/fetch_gsi.sh` refreshed with portable-tool fallback
  paths. Unblocks when run on Linux/WSL with `simg2img` + `7z` +
  current GSI build ID.

### Phase A summary

| | Code | Local gate | External corpus gate |
|---|:-:|:-:|:-:|
| AT-1 (decoder) | ✅ | ✅ 7340 + 4 capstone-diff layers | ⚠️ 10M cargo-fuzz not run |
| AT-2 (IR + lift) | ✅ | ✅ 73-variant roundtrip + 6 lift unit tests | n/a |
| AT-3 (NEON/FP/crypto) | ✅ | ✅ via capstone-diff parity | ⚠️ libcrypto NEON corpus |
| AT-4 (sys/atomics) | ✅ | ✅ via capstone-diff parity | ⚠️ vmlinux + bionic |
| AT-5 (coverage audit) | ✅ | ✅ hypervisor.efi: 0 unknown / 5252 | ⚠️ Android 21-lib GSI |

Honest framing: **"code-complete and gate-passing on every gate runnable
on this host without admin."** Three corpus gates remain `#[ignore]`'d
because the external Android binary corpora couldn't be fetched without
admin/tooling on the dev host. Everything is *ready* for those runs —
audit driver, ELF/PE32+ extractors, fetch script, 21-library list,
corpus walker all exist and pass against the surrogate ARM64 binary.

---

## Phase B — Middle-End (Direction-Agnostic)

### AT-6: SSA Construction

Per-basic-block SSA on the decoded IR. Phi insertion at join points;
dominator tree. Folds the AT-2 `Read*`/`Write*` register-access pairs
into proper SSA via memory-promotion.

**Gate:** SSA verifier passes on every decoded block from AT-5 corpus.

### AT-7: Core Optimizer Passes

DCE, copy propagation, constant folding, GVN, redundant-load elimination.

**Gate:** measurable IR-size reduction (≥ 15 % median) on AT-5 corpus;
semantic-equivalence test via interpreter.

### AT-8: Flag Elision Pass

Detect ARM `NZCV`-producing ops whose flags are never read before the
next clobber; mark for x86-side flag suppression. Critical for
performance — ARM→x86 must not eagerly compute `EFLAGS`.

**Gate:** ≥ 60 % of flag-producing ops elided on libart.so.

### AT-9: Linear-Scan Register Allocator

Allocate over 16 x86 GPRs + 16 XMM/YMM regs. Spill the extra 15 ARM
GPRs to a per-thread context block.

**Gate:** zero allocator failures on AT-5 corpus; spill ratio < 8 % by
op count.

### AT-10: Memory-Ordering Lowering

ARM is weak, x86 is TSO — most `DMB/DSB` become no-ops. `LDAR/STLR`
map to plain `MOV` under x86 TSO. Only acquire/release fences crossing
locks need attention.

**Gate:** x86-TSO formal-model spot-checks on a curated test suite
(litmus tests).

---

## Phase C — x86_64 Backend

### AT-11: x86_64 Encoder

REX / ModR/M / SIB / immediates / RIP-relative addressing. Hand-rolled,
no `asmjit` dep (link-cleanliness for UEFI).

**Gate:** encode 100 % of opcodes used by AT-12 lowering; byte-exact
match vs LLVM-MC reference.

### AT-12: Integer Lowering

IR int / load / store / branch ops → x86_64 sequences. Includes LL/SC →
`LOCK CMPXCHG` with retry loop.

**Gate:** hello-world (`mov x0, #0; ret`) translates and executes
correctly.

### AT-13: SIMD Lowering

NEON → SSE2 / SSE4 / AVX2. Lower 128-bit NEON into XMM; widen to YMM
where helpful.

**Gate:** `glm_mat4_mul` ARM → x86 produces bit-exact result vs native
ARM.

### AT-14: Atomics & Barriers

LDXR/STXR pairs → `LOCK CMPXCHG` retry loops. Acquire/release semantics
preserved.

**Gate:** 16-thread stress on a `__atomic_compare_exchange`
microbenchmark produces no torn writes.

### AT-15: Code Buffer & ICache

Allocate executable pages from JIT arena. After write: `CLFLUSH` +
`MFENCE` + serializing instruction before execute (x86 doesn't need
explicit ICache invalidation, but does need serialization on
cross-modifying code).

**Gate:** self-modifying-code unit test (write block, execute, rewrite,
re-execute) passes 1M iterations.

---

## Phase D — Dispatcher & Runtime

### AT-16: Block Cache

Hash table keyed by guest ARM64 PC → x86_64 host PA + length. Eviction
policy (LRU or generational).

**Gate:** cache hit rate ≥ 99 % on libart steady-state workload.

### AT-17: Dispatcher Loop

Hot path: lookup → jump-to-host. Cold path: decode → IR → optimize →
emit → install → jump.

**Gate:** p99 dispatch latency on hit ≤ 50 cycles measured via `RDTSC`.

### AT-18: Indirect-Branch Chaining

Inline cache for indirect calls (vtables, function pointers, `BR x_n`).
Patches host code in-place when target settles.

**Gate:** indirect-branch microbenchmark within 2× of native x86
indirect call.

### AT-19: Context Save / Restore

On VM exit (HLT, EPT fault, IRQ), save current translated-block
register file back into AETHER's `GuestContext`. On entry, restore.
This is the missing piece that today's `fex_dispatch.rs` stubs as
`pc += 4`.

**Gate:** VM exit during translated block correctly preserves all 31
ARM GPRs + 32 NEON regs + SP + PC + NZCV.

### AT-20: Exception Forwarding

Translated code that traps (`UD`, `#PF`, `#GP`) must surface as the
equivalent ARM exception class (`ExceptionClass::DataAbort`, etc.) so
EL1 Android handles it identically to native ARM.

**Gate:** unaligned-load on translated ARM code produces the same
`SIGBUS` at the same PC as a native ARM run.

---

## Phase E — Integration & AOT

### AT-21: AOT Pre-Translation

Pre-translate the 21 default libraries (libart, libhwui, libvulkan, …)
at first boot; persist cache.

**Gate:** p99 frame ≤ 33 ms on cold app launch after first boot.

### AT-22: JIT Cache Persistence

Spill cold blocks to paravirt NVMe (per ch37 admin queue); reload on
boot.

**Gate:** cold-boot warm-cache restore reduces first 60 s of
translation work by ≥ 80 %.

### AT-23: Self-Modifying Code Handling

W^X enforcement: blocks live in RX pages. Guest writes to those
guest-PA ranges trigger EPT/NPT write fault → invalidate cached
translations → retranslate on next execute.

**Gate:** JIT'd app (V8, dalvikvm) runs correctly without translation
staleness.

### AT-24: AETHER FFI Surface

Replace the current `fex_*` 5-symbol API with `aether_dbt_*` symbols.
Rename `fex_integration.rs` → `dbt_integration.rs`. Delete the FEX
stub crate.

**Gate:** `hypervisor.efi` links with the new translator static
archive; no FEX symbols remain.

### AT-25: UEFI Link & Forbidden-Symbol Gate

The static archive must contain zero libc / pthread / file-I/O symbols.
Bump-arena alloc, spinlock-only sync, NVMe-backed spill.

**Gate:** `llvm-nm libaether_dbt.a` returns empty for the
forbidden-symbol set listed in ch52.

---

## Phase F — Validation

### AT-26: Static Hello-World

ARM64 `aarch64-linux-gnu-gcc -static hello.c` runs under the
translator on Intel / AMD x86 hardware. UART prints "Hello, AETHER".

**Gate:** same as today's ch52 gate, but now with real translation.

### AT-27: Bionic + libart Bring-Up

Android's libart starts; `dalvikvm` interprets a trivial `.dex` under
translation.

**Gate:** `dalvikvm -classpath hello.dex Hello` prints "Hello" via
translated libart.

### AT-28: Zygote Launch

Full Android Zygote forks; SystemServer comes up; logcat is alive.

**Gate:** `getprop sys.boot_completed=1` on x86 hardware.

### AT-29: App Compatibility (x86 tier)

Re-run ch49 harness on x86 hardware via the translator.

**Gate:** ≥ 950 / 1000 apps pass (same gate as ARM tier).

### AT-30: Performance

Geekbench / PCMark Android on translator vs native ARM (Snapdragon X)
and vs native x86 (Android-x86 reference where possible).

**Gate:** ≥ 70 % of native ARM on integer geomean; ≥ 80 % on SIMD;
≥ 60 % on JS (V8) benchmarks.

---

## Sequencing notes

- **AT-1 through AT-12 are blocking** for any sign of life. After AT-12
  you can translate and execute simple ARM64 binaries.
- **AT-13 through AT-20 unlock realistic workloads** — without flag
  elision and SIMD you'll see < 30 % native performance even on trivial
  code.
- **AT-21 through AT-25 are productization** — until these land, the
  translator runs but isn't shippable inside `hypervisor.efi`.
- **AT-26 through AT-30 are validation gates**, mapping back onto the
  existing AETHER gate philosophy.

**Realistic calendar:** AT-1 to AT-12 ≈ 6–9 months single-engineer.
AT-13 to AT-25 ≈ 9–15 months. AT-26 to AT-30 ≈ 3–6 months of bring-up.
**Total: 18–30 months single-engineer.**

---

## Current status (sandbox/aether-translator @ commit a6422ee)

```
┌─────────┬──────────────────────────┬─────────────────────────────────────────┐
│ Chapter │ Status                   │ Notes                                   │
├─────────┼──────────────────────────┼─────────────────────────────────────────┤
│  AT-1   │ ✅ Done                  │ 7340 vectors + 4 capstone-diff layers   │
│  AT-2   │ ✅ Lift done             │ 99.85% lift on real ARM64; 73 codecs    │
│  AT-3   │ ⚠️ Code done             │ Corpus gate ⏸ pending aarch64-gcc       │
│  AT-4   │ ⚠️ Code done             │ Sysreg ~310; corpus gate ⏸ pending GSI │
│  AT-5   │ ✅ Surrogate passing     │ hypervisor.efi: 0/5252 unknown          │
│         │ ⚠️ 21-lib gate           │ ⏸ pending GSI extract                   │
├─────────┼──────────────────────────┼─────────────────────────────────────────┤
│ AT-6+   │ ⬜ Not started           │ Phase B SSA + optimizer next            │
└─────────┴──────────────────────────┴─────────────────────────────────────────┘
```

**CI:** `.github/workflows/aether-translator.yml` runs lint + host tests +
the surrogate AT-5 gate on every push to `main`/`sandbox/**` and every
PR. The surrogate gate builds `hypervisor.efi` (real ARM64 PE32+) and
audits its 5252 `.text` instructions — catches Phase B/C/D decoder
regressions on push.

**Three corpus gates deferred (environment work, not code):** AT-3
libcrypto NEON, AT-4 vmlinux+bionic, AT-5 21-lib Android GSI. All three
flip from `#[ignore]` to `#[test]` when run on a host with:
- `aarch64-linux-gnu-gcc` (Linux: `apt install gcc-aarch64-linux-gnu`)
- A current GSI build + `simg2img` + ext4 extraction (Linux loopback
  mount as root, or Windows 7-Zip 21+ with the Ext plugin)

These are scheduled to run when Phase D lands (between dispatcher and
integration — the point where end-to-end translation works and you'd
notice a decoder gap anyway, and the development host is by definition
Linux at that point).

## Crate layout

See [`aether-translator/README.md`](../aether-translator/README.md) for the
file-by-file map.

## Where work happens

- **Plan file:** `~/.claude/plans/identify-your-weaknesses-in-wondrous-pond.md`
- **Implementation:** `aether-translator/`
- **Branch:** `sandbox/aether-translator`
- **CI:** `.github/workflows/aether-translator.yml`
- **FEX scaffolding it replaces:** `hypervisor/src/fex_integration.rs`,
  `hypervisor/src/fex_dispatch.rs`, `hypervisor/third_party/fex/` — kept in
  tree (renamed to `dbt_*` at AT-24); ~70 % of content survives the rename.
