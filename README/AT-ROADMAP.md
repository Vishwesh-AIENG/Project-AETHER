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
`&[u8]` into a Rust IR enum. Reference: ARM ARM DDI 0487 §C4.

**Gate:** decode 1000 canned encodings (incl. `0x91000421 → ADD x1, x1, #1`);
fuzz round-trip against Capstone.

### AT-2: IR Data Model

Define `IrOp`, `IrValue`, `IrBlock`, `IrFunction` in `no_std` Rust.
SSA-friendly; ~140 opcodes (load / store / alu / cmp / branch / call /
atomic / barrier / simd-vec).

**Gate:** IR round-trips through serialize/parse; unit tests on every opcode
constructor.

### AT-3: NEON / FP / SIMD Decoder

Cover Advanced SIMD (NEON) + FP scalar + crypto extensions used by Android
(AES, SHA, CRC32).

**Gate:** decode every NEON op emitted by `clang -O2 -march=armv8-a+crypto`
on libcrypto.

### AT-4: System, Atomics, Barriers

`LDXR/STXR/LDAR/STLR/DMB/DSB/ISB/MRS/MSR/SVC/HVC/SMC`. Model memory ordering
in IR. Full ~600-entry sysreg catalog.

**Gate:** decode every system-instruction encoding emitted by Android kernel
+ bionic.

### AT-5: Decoder Coverage Audit

Bulk-decode every executable byte of a real Android `system.img` (libart.so,
libhwui.so, libvulkan.so, …); flag unknown encodings.

**Gate:** zero unknown encodings across the 21 AOT default libraries.

---

## Phase B — Middle-End (Direction-Agnostic)

### AT-6: SSA Construction

Per-basic-block SSA on the decoded IR. Phi insertion at join points;
dominator tree.

**Gate:** SSA verifier passes on every decoded block from AT-5 corpus.

### AT-7: Core Optimizer Passes

DCE, copy propagation, constant folding, GVN, redundant-load elimination.

**Gate:** measurable IR-size reduction (≥ 15 % median) on AT-5 corpus;
semantic-equivalence test via interpreter.

### AT-8: Flag Elision Pass

Detect ARM `NZCV`-producing ops whose flags are never read before the next
clobber; mark for x86-side flag suppression. Critical for performance —
ARM→x86 must not eagerly compute `EFLAGS`.

**Gate:** ≥ 60 % of flag-producing ops elided on libart.so.

### AT-9: Linear-Scan Register Allocator

Allocate over 16 x86 GPRs + 16 XMM/YMM regs. Spill the extra 15 ARM GPRs to
a per-thread context block.

**Gate:** zero allocator failures on AT-5 corpus; spill ratio < 8 % by op
count.

### AT-10: Memory-Ordering Lowering

ARM is weak, x86 is TSO — most `DMB/DSB` become no-ops. `LDAR/STLR` map to
plain `MOV` under x86 TSO. Only acquire/release fences crossing locks need
attention.

**Gate:** x86-TSO formal-model spot-checks on a curated test suite (litmus
tests).

---

## Phase C — x86_64 Backend

### AT-11: x86_64 Encoder

REX / ModR/M / SIB / immediates / RIP-relative addressing. Hand-rolled, no
`asmjit` dep (link-cleanliness for UEFI).

**Gate:** encode 100 % of opcodes used by AT-12 lowering; byte-exact match
vs LLVM-MC reference.

### AT-12: Integer Lowering

IR int / load / store / branch ops → x86_64 sequences. Includes LL/SC →
`LOCK CMPXCHG` with retry loop.

**Gate:** hello-world (`mov x0, #0; ret`) translates and executes correctly.

### AT-13: SIMD Lowering

NEON → SSE2 / SSE4 / AVX2. Lower 128-bit NEON into XMM; widen to YMM where
helpful.

**Gate:** `glm_mat4_mul` ARM → x86 produces bit-exact result vs native ARM.

### AT-14: Atomics & Barriers

LDXR/STXR pairs → `LOCK CMPXCHG` retry loops. Acquire/release semantics
preserved.

**Gate:** 16-thread stress on a `__atomic_compare_exchange` microbenchmark
produces no torn writes.

### AT-15: Code Buffer & ICache

Allocate executable pages from JIT arena. After write: `CLFLUSH` + `MFENCE`
+ serializing instruction before execute (x86 doesn't need explicit ICache
invalidation, but does need serialization on cross-modifying code).

**Gate:** self-modifying-code unit test (write block, execute, rewrite,
re-execute) passes 1M iterations.

---

## Phase D — Dispatcher & Runtime

### AT-16: Block Cache

Hash table keyed by guest ARM64 PC → x86_64 host PA + length. Eviction
policy (LRU or generational).

**Gate:** cache hit rate ≥ 99 % on libart steady-state workload.

### AT-17: Dispatcher Loop

Hot path: lookup → jump-to-host. Cold path: decode → IR → optimize → emit →
install → jump.

**Gate:** p99 dispatch latency on hit ≤ 50 cycles measured via `RDTSC`.

### AT-18: Indirect-Branch Chaining

Inline cache for indirect calls (vtables, function pointers, `BR x_n`).
Patches host code in-place when target settles.

**Gate:** indirect-branch microbenchmark within 2× of native x86 indirect
call.

### AT-19: Context Save / Restore

On VM exit (HLT, EPT fault, IRQ), save current translated-block register
file back into AETHER's `GuestContext`. On entry, restore. This is the
missing piece that today's `fex_dispatch.rs` stubs as `pc += 4`.

**Gate:** VM exit during translated block correctly preserves all 31 ARM
GPRs + 32 NEON regs + SP + PC + NZCV.

### AT-20: Exception Forwarding

Translated code that traps (`UD`, `#PF`, `#GP`) must surface as the
equivalent ARM exception class (`ExceptionClass::DataAbort`, etc.) so EL1
Android handles it identically to native ARM.

**Gate:** unaligned-load on translated ARM code produces the same `SIGBUS`
at the same PC as a native ARM run.

---

## Phase E — Integration & AOT

### AT-21: AOT Pre-Translation

Pre-translate the 21 default libraries (libart, libhwui, libvulkan, …) at
first boot; persist cache.

**Gate:** p99 frame ≤ 33 ms on cold app launch after first boot.

### AT-22: JIT Cache Persistence

Spill cold blocks to paravirt NVMe (per ch37 admin queue); reload on boot.

**Gate:** cold-boot warm-cache restore reduces first 60 s of translation
work by ≥ 80 %.

### AT-23: Self-Modifying Code Handling

W^X enforcement: blocks live in RX pages. Guest writes to those guest-PA
ranges trigger EPT/NPT write fault → invalidate cached translations →
retranslate on next execute.

**Gate:** JIT'd app (V8, dalvikvm) runs correctly without translation
staleness.

### AT-24: AETHER FFI Surface

Replace the current `fex_*` 5-symbol API with `aether_dbt_*` symbols.
Rename `fex_integration.rs` → `dbt_integration.rs`. Delete the FEX stub
crate.

**Gate:** `hypervisor.efi` links with the new translator static archive; no
FEX symbols remain.

### AT-25: UEFI Link & Forbidden-Symbol Gate

The static archive must contain zero libc / pthread / file-I/O symbols.
Bump-arena alloc, spinlock-only sync, NVMe-backed spill.

**Gate:** `llvm-nm libaether_dbt.a` returns empty for the forbidden-symbol
set listed in ch52.

---

## Phase F — Validation

### AT-26: Static Hello-World

ARM64 `aarch64-linux-gnu-gcc -static hello.c` runs under the translator on
Intel / AMD x86 hardware. UART prints "Hello, AETHER".

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

Geekbench / PCMark Android on translator vs native ARM (Snapdragon X) and
vs native x86 (Android-x86 reference where possible).

**Gate:** ≥ 70 % of native ARM on integer geomean; ≥ 80 % on SIMD; ≥ 60 %
on JS (V8) benchmarks.

---

## Notes on sequencing

- **AT-1 through AT-12 are blocking** for any sign of life. After AT-12 you
  can translate and execute simple ARM64 binaries.
- **AT-13 through AT-20 unlock realistic workloads** — without flag elision
  and SIMD you'll see < 30 % native performance even on trivial code.
- **AT-21 through AT-25 are productization** — until these land, the
  translator runs but isn't shippable inside `hypervisor.efi`.
- **AT-26 through AT-30 are validation gates**, mapping back onto the
  existing AETHER gate philosophy.

**Realistic calendar:** AT-1 to AT-12 = ~6–9 months for one engineer. AT-13
to AT-25 = another 9–15 months. AT-26 to AT-30 = 3–6 months of bring-up
debugging. **Total: 18–30 months single-engineer**, faster with more hands
but with classic Brooks-law diminishing returns past two people.

---

## Current status (as of branch `sandbox/aether-translator`)

| Chapter | Status | Notes |
|---|---|---|
| AT-1 | ✅ Done | 7340 canned vectors green; capstone-diff parity against `capstone-rs 0.14` with a 2-pattern Phase A residual gap for FEAT_FP16 / FEAT_RDM encodings the bundled Capstone declines without extra-mode flags |
| AT-2 | 🟡 Code done | 63 of ~140 IR variants have full encode/decode codecs (the ones AT-1 lift produces). Remaining: NEON/FP/crypto/sysreg-bearing variants. |
| AT-3 | ⚠️ Code done, corpus gate blocked | Per-sub-family validation: every valid NEON/FP/crypto encoding accepted, every reserved combination rejected. `at3_neon_corpus` gate `#[ignore]`'d pending `aarch64-linux-gnu-gcc` cross-toolchain install. |
| AT-4 | ⚠️ Code done, corpus gate blocked | Branch/exception decoders tightened (full `(opc, LL)` table); sysreg catalog **~310 architectural registers covered** (180 hand-named + 124 via PMU/Debug array variants + ~50 v8.1+ VHE/SVE/secure-timer adds). `at4_system_corpus` gate `#[ignore]`'d pending GSI. |
| AT-5 | ⚠️ Driver done, corpus gate blocked | ELF .text extractor + corpus walker scaffolded and tested. `at5_system_img` gate `#[ignore]`'d pending GSI download (ci.android.com URL stale + `simg2img`/`7z` missing on this Windows host). |
| AT-6 onwards | ⬜ Not started | |

**What's shippable today:** the decoder + IR + serialization framework
under `aether-translator/`. Built as a host-testable Rust workspace member;
folds into `hypervisor/src/translator/` at AT-24.

## Crate layout

See [`aether-translator/README.md`](../aether-translator/README.md) for the
file-by-file map.

## Where work happens

- **Plan file:** `~/.claude/plans/identify-your-weaknesses-in-wondrous-pond.md`
- **Implementation:** `aether-translator/`
- **Branch:** `sandbox/aether-translator` (this work)
- **FEX scaffolding it replaces:** `hypervisor/src/fex_integration.rs`,
  `hypervisor/src/fex_dispatch.rs`, `hypervisor/third_party/fex/` — kept in
  tree (renamed to `dbt_*` at AT-24); ~70 % of content survives the rename.
