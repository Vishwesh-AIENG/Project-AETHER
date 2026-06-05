I have complete ground truth. Now I'll write the authoritative build spec.

# AETHER M4b-6 Build Spec — ARM64 SIMD / FP / Crypto Coverage in the DBT

**Status:** authoritative. Implemented verbatim by the next workflow.
**Verified against tree** at `D:\AETHER\aether-translator\` on 2026-06-05. Every file/line cited below was Read or Grep'd directly; the input MAP/TABLE/VERDICT findings were re-verified and **corrected where they were wrong** (see callouts marked ⚠️ CORRECTION).

---

## 0. Ground-truth reconciliation (read this first — it overrides several inputs)

Three load-bearing facts were re-verified and change the plan the inputs assumed:

1. **The live lowerer is `IntLower::lower_block`, called at `dbt.rs:317`. `SimdLower::lower_block` is NEVER called in the dispatch path.** `lower_simd.rs` is an SSA/XMM-allocator pass full of `enc.emit_nop()`/placeholder stubs and is **dead code today**. The ctx-template SIMD lowering therefore goes into **`IntLower`** (a new sibling module `backend/lower_simd_ctx.rs` that `IntLower::lower_op` delegates to). **Do NOT build on `lower_simd.rs`.** It stays as-is (dead) or is deleted in a later cleanup; it is out of scope.
   - ⚠️ CORRECTION to the "Lower mapping (backend/lower_simd.rs)" section title in the task: the corrected x86 sequences live in **`backend/lower_simd_ctx.rs`**, invoked from `lower_int.rs`. The task's section 7 is renamed accordingly below.

2. **ReadFpr/WriteFpr already exist as IR ops and are already emitted by lift** (`lift/mod.rs:584,593,997,1003`) for FP load/store and the AES placeholder. They currently lower to `UD2` at `lower_int.rs:1762`. The vertical slice's first job is to make those two ops real ctx load/store-to-scratch — that alone unblocks LDR/STR Q and AES.

3. **The `IrValueId`-keyed `VAdd..VFMa` / `FAdd..FCmp` ops (ops.rs:365-583) presume the XMM allocator and collide with the ctx model.** They are reachable only through the dead `SimdLower`. **We add a NEW compact, V-register-numbered op family** (`reg: u8`, mirroring `ReadGpr`/`WriteGpr`) and route lift to it. The old IrValueId-keyed vector ops are left untouched (no regression — nothing produces them on the live path) and are deprecated.

4. **Scratch-XMM model:** the ctx templates use **fixed scratch XMMs reserved out of allocation**. Because the live path never runs the XMM allocator for these ops, reservation is trivial: we simply never hand these XMMs to `linear_scan`. Assignment below.

---

## 1. Architecture decision

### 1.1 The ctx-template vector lowering model

Every NEON/FP/crypto op is a **self-contained ctx template** keyed by ARM V-register *number* (0–31), not by SSA `IrValueId`. The guest q-register file in context memory (`[R15 + VEC_OFFSET=0x128 + n*16]`, confirmed `context.rs:56`) is **authoritative between blocks and between ops**. A lowering fn does:

```
movdqu  VS0, [R15 + 0x128 + n*16]      ; load Vn
movdqu  VS1, [R15 + 0x128 + m*16]      ; load Vm   (binary ops)
<one or more SSE ops on VS0/VS1/VS2/VS3>
; if D-form / scalar: zero the upper lanes of VS0 (see §1.4)
movdqu  [R15 + 0x128 + d*16], VS0      ; store Vd
```

No XMM register allocator. No cross-op XMM liveness. Each instruction family is an independent `fn lower_<family>(enc, …)`.

**Verified primitives present:** `emit_movdqu_load` (encode.rs:908), `emit_movdqu_store` (917), `emit_movdqa_rr` (881), all four `padd*`/`psub*` (934-941), `pmullw`/`pmulld` (942/1084), the full signed/unsigned `pmins*`/`pmaxs*` set (953-964), `pcmpeqd`/`pcmpgtd` (949/952), `pand`/`pandn`/`por`/`pxor` (943-946), all `psll*`/`psrl*`/`psra*`-imm (966-1029), `punpck*` (1104-1114), `pshufb`/`pshufd` (1089/1094), `movq_xmm_r64`/`movq_r64_xmm` (1117/1126), `pinsr*`/`pextr*` (1135-1186), `aesenc/dec/last/imc` (1198-1219), `pclmulqdq` (1223), `crc32*` (1232-1252), scalar `cvt*_r64`/`ucomiss`/`ucomisd`/`cvtss2sd`/`cvtsd2ss` (1256-1316), `andps`/`andnps`/`xorps`/`cmpps`/`cmppd` (1326-1349).

### 1.2 ⚠️ The prologue/epilogue XMM hazard — EXACT resolution

`context.rs:264-302` (`emit_save_prologue`/`emit_restore_epilogue`) blind-save/restore XMM0..15 ↔ ctx VEC region, AND the helper `emit_vmovdqu_mem_xmm`/`_xmm_mem` (338-371) emits a **2-byte VEX (0xC5)** which has no REX.B and **cannot encode base=R15** — the comment at 352-354 even admits this is wrong. Both bugs are confirmed and both are dangerous under the ctx-authoritative model (the blind save would clobber `q0..q15` with stale scratch; the mis-encoding corrupts whatever it touches).

**Resolution (do this FIRST, before any math fix — it is a precondition):** delete the XMM half of both functions. Templates always load-from/store-to ctx, so there is nothing to save/restore.

Exact edit to `context.rs`:

```rust
// emit_save_prologue — DELETE lines 274-279 (the `for i in 0..16` loop and its
// VMOVDQU emit). Change the return to:
    ContextCode { bytes, reg_count: count }   // was: count + 16

// emit_restore_epilogue — DELETE lines 289-293 (the XMM restore loop). The GPR
// restore loop and return:
    ContextCode { bytes, reg_count: count }   // was: count + 16
```

Then **delete** the now-unused `emit_vmovdqu_mem_xmm` (338-356) and `emit_vmovdqu_xmm_mem` (358-371) entirely (they have no other callers — Grep-verify before deleting; the only references are the two loops being removed plus the context round-trip test). If `at19_context.rs` asserts `reg_count == count + 16`, update that assertion to `count`. The round-trip `round_trip_test()` (377+) operates on `GuestRegisterFile` fields directly and is unaffected.

If a future block boundary genuinely needs XMM persistence (it does not, under this model), re-add it as a correct **SSE2 MOVDQU (`F3 0F 6F`/`7F`) with `rex_opt`** — i.e. reuse `emit_movdqu_load`/`emit_movdqu_store`, which already encode R15 correctly. Never re-introduce the 2-byte VEX form.

### 1.3 Fixed scratch-XMM assignment

Reserve **XMM0, XMM1, XMM2, XMM3** as the SIMD/FP scratch set, named:

| Name | Reg | Role |
|------|-----|------|
| `VS0` | XMM0 | primary operand / result accumulator (`movdqu VS0,[Vn]`) |
| `VS1` | XMM1 | second operand (`movdqu VS1,[Vm]`) |
| `VS2` | XMM2 | third operand / accumulator-read for MLA/SABA / mask build |
| `VS3` | XMM3 | scratch for min-max trees, sign masks, constant build |

Add to `regalloc/x86_regs.rs`:

```rust
/// SIMD/FP ctx-template scratch registers (never allocated to IR values).
pub const VS0: u8 = 0;
pub const VS1: u8 = 1;
pub const VS2: u8 = 2;
pub const VS3: u8 = 3;
/// First XMM index the linear-scan allocator may hand to an IR value.
/// 0..=3 reserved as SIMD scratch (mirrors GPR_ALLOC_FIRST_INDEX=2).
pub const XMM_ALLOC_FIRST_INDEX: usize = 4;
```

`ALLOCATABLE_XMMS` (54-59) stays a 16-entry table for index stability; the allocator must start handing out at `XMM_ALLOC_FIRST_INDEX`. Since `SimdLower` (the only XMM consumer) is dead, this is defensive: update `linear_scan.rs` to honor `XMM_ALLOC_FIRST_INDEX` only if/when it ever allocates an Xmm class. **No live test depends on XMM allocation today** — verify with `cargo test --lib` after the change.

**GPR scratch** for FP↔GPR moves and saturation fixups: reuse the existing reserved `SCRATCH0=RAX`, `SCRATCH1=RCX` (`GPR_ALLOC_FIRST_INDEX=2`, x86_regs.rs:50-52). The fixup helpers use RAX/RCX only.

### 1.4 D-vs-Q upper-zeroing rule (ARM 64-bit-write-zeroes-upper analog)

Every D-form (`Q=0`) or scalar write to `Vd` must zero `Vd[127:64]` (D), `[127:32]` (S), or `[127:16]` (H). The template guarantees it by building the result in a **PXOR-zeroed scratch** then `movdqu`-ing the full 128 bits, OR by the GPR-roundtrip idiom. ⚠️ CORRECTION to the table's recurring "`movq xmm,xmm` (F3 0F 7E)" suggestion: **no `emit_movq_xmm_xmm` exists** and adding one is fine, but the **uniform, already-available** idiom is the GPR roundtrip:

```
; zero-upper of a 64-bit (D-form) result currently in VS0:
movq  RAX, VS0          ; emit_movq_r64_xmm(RAX, VS0)
pxor  VS0, VS0          ; emit_pxor(VS0, VS0)
movq  VS0, RAX          ; emit_movq_xmm_r64(VS0, RAX)   -> low64 set, [127:64]=0
```

Add a single helper `emit_movq_xmm_xmm` (`F3 0F 7E /r`, §3) for the common D-form case so the idiom is one instruction; both are acceptable, use the helper. For S/H scalar results produced via `movss`/`movd`-from-memory or `movd xmm,r32`, the **to-xmm form inherently zeroes upper lanes** — no extra step needed.

---

## 2. New IR ops (ir/ops.rs) + serializer arms (ir/serialize.rs)

All new ops are **V-register-numbered** (`u8`), self-contained, with NO `IrValueId` operands (so they need **no** `visit_def_values`/`visit_use_values`/`remap_uses` arms — those iterate `IrValueId`s; a `reg:u8` op yields none). ⚠️ CORRECTION to the MAP finding that "remap_uses is exhaustive so a new variant forces a compile error": `remap_uses`, `visit_def_values`, `visit_use_values`, `visit_def_flags`, `visit_use_flags` all end with `Unimplemented`/catch-all or only match value-bearing ops — **verify each ends with `_ => {}` or an exhaustive list that you extend with a no-op arm.** For these reg-numbered ops add an explicit `_ => {}`-equivalent arm (no values to yield) in each of the five methods to be safe and to silence non-exhaustiveness. Confirm by compiling.

### 2.1 Enum variants to add (after `WritePc`, before `X86Mfence`)

```rust
// ───── M4b-6: V-register-numbered SIMD/FP ctx templates ─────
// All operate on ctx q-regs [R15+0x128+reg*16]; no IrValueId operands.

/// 3-same integer NEON binary. d=use+def for Mla/Mls/SAba/UAba.
VecBin   { op: VecBinOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
/// 2-reg-misc single-source (ABS/NEG).
VecUn    { op: VecUnOp, size: u8, q: bool, d: u8, n: u8 },
/// Vector shift by immediate (signed/logical, left/right).
VecShift { op: VecShiftOp, size: u8, q: bool, d: u8, n: u8, amount: u8 },
/// Vector compare (CMEQ/CMGT/CMGE/CMHI/CMHS), result = all-ones/zero per lane.
VecCmp   { op: VecCmpOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
/// Pairwise (ADDP/SMAXP/SMINP/UMAXP/UMINP).
VecPair  { op: VecPairOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
/// Across-vector reduce, same-width (ADDV/SMAXV/SMINV/UMAXV/UMINV).
VecReduce { op: VecReduceOp, size: u8, q: bool, d: u8, n: u8 },
/// Across-vector widening add (SADDLV/UADDLV) + adjacent-pair widening (SADDLP/UADDLP).
VecAddLong { across: bool, signed: bool, size: u8, q: bool, d: u8, n: u8 },
/// FP vector 3-same (FADD/FSUB/FMUL/FDIV/FMIN/FMAX, single|double via dbl).
VecFp    { op: VecFpOp, dbl: bool, q: bool, d: u8, n: u8, m: u8 },

// ───── Scalar FP / convert (V-register or GPR numbered) ─────
/// Int(GPR)->FP. from_bits = GPR width (32|64) from sf; to_bits = FP dest (16|32|64).
FpFromInt { d: u8, n_gpr: u8, from_bits: u8, to_bits: u8, signed: bool },
/// FP->int(GPR). from_bits = FP src; to_bits = GPR dest; round mode for FCVT{N,P,M,Z,A}.
FpToIntR  { d_gpr: u8, n: u8, from_bits: u8, to_bits: u8, signed: bool, round: RoundMode },
/// Round-to-integral, FP result (FRINTN/P/M/Z/A/X/I).
FpRound   { d: u8, n: u8, dbl: bool, round: RoundMode, raise_inexact: bool },
/// FP precision convert (FCVT S<->D<->H).
FpCvt2    { d: u8, n: u8, from_bits: u8, to_bits: u8 },
/// FP reg->reg move (FMOV Sd,Sn / Dd,Dn) with upper-lane zeroing.
FpMov     { d: u8, n: u8, width_bits: u8 },
/// FP scalar 3-same/2-src (FADD/FSUB/FMUL/FDIV/FMIN/FMAX/FNMUL, scalar).
FpBin     { op: FpBinOp, dbl: bool, d: u8, n: u8, m: u8 },
/// FP scalar 1-src (FABS/FNEG/FSQRT).
FpUn      { op: FpUnOp, dbl: bool, d: u8, n: u8 },
/// FP compare -> NZCV (FCMP/FCMPE), with-zero variant when zero=true.
FpCmpN    { n: u8, m: u8, dbl: bool, zero: bool },
/// FMOV between FP reg and GPR (bitwise, no convert). high_half => D[1].
FpToGpr   { d_gpr: u8, n: u8, bits: u8, high_half: bool },
FpFromGpr { d: u8, n_gpr: u8, bits: u8, high_half: bool },

// ───── Crypto (V-register numbered) ─────
/// AES round op. kind: 0=AESE 1=AESD 2=AESMC 3=AESIMC. For E/D, m = key/state reg.
CryptoAesR { kind: u8, d: u8, n: u8, m: u8 },
/// SHA1/SHA256 op (kind selects). d=use+def, n,m source V-regs.
CryptoShaR { kind: u8, d: u8, n: u8, m: u8 },
```

Supporting enums (place near `LaneType`, in `ir/value.rs` or `ir/ops.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecBinOp { Add, Sub, Mul, Mla, Mls, SqAdd, UqAdd, SqSub, UqSub,
                    SHadd, UHadd, SrHadd, UrHadd, SAbd, UAbd, SAba, UAba }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecUnOp { Abs, Neg }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecShiftOp { Shl, SShr, UShr }   // arithmetic vs logical right
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecCmpOp { Eq, SGt, SGe, UGt, UGe }   // CMEQ/CMGT/CMGE/CMHI/CMHS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecPairOp { Add, SMax, SMin, UMax, UMin }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecReduceOp { Add, SMax, SMin, UMax, UMin }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecFpOp { Add, Sub, Mul, Div, Min, Max }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpBinOp { Add, Sub, Mul, Div, Min, Max, NMul }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpUnOp { Abs, Neg, Sqrt }
/// Rounding mode shared by FpToIntR and FpRound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundMode { Nearest, NegInf, PosInf, Zero, NearestTiesAway, Current }
```

**size encoding (stable):** `0=B(8), 1=H(16), 2=S(32), 3=D(64)`.

### 2.2 Serializer: tags, helpers, encode/decode, allow-list

⚠️ The reserved range `0x80–0xBC` is bound to the **old** `IrValueId`-keyed ops in `variant_tag` (serialize.rs:642-694) and must NOT be reused. Allocate a fresh contiguous block in the **unused `0xD0–0xEF` gap** (verified: tags jump from `TlbInval=0xCC` to `ReadGpr=0xE0`; `0xCD..0xDF` are free; we use `0xD0..0xE? `, avoiding `0xE0..0xE9` which are the guest-state ops):

```
VecBin=0xCD  VecUn=0xCE  VecShift=0xCF  VecCmp=0xD0  VecPair=0xD1
VecReduce=0xD2  VecAddLong=0xD3  VecFp=0xD4
FpFromInt=0xD5  FpToIntR=0xD6  FpRound=0xD7  FpCvt2=0xD8  FpMov=0xD9
FpBin=0xDA  FpUn=0xDB  FpCmpN=0xDC  FpToGpr=0xDD  FpFromGpr=0xDE
CryptoAesR=0xDF  CryptoShaR=0xEA   (0xE0..0xE9 are ReadGpr..WritePc; 0xEA free)
```

(Place each in `variant_tag` before the `Unimplemented(_) => 0xFF` arm; the match stays exhaustive — a new enum variant forces a compile error there, which is the desired signal.)

**New enum-codec helpers** (mirror `put_nzcv` at 144-152; each returns/reads a `u8`, `SerErr::BadEnum(v)` on unknown). Byte tags follow declaration order, **AOT-cache-stable**:

```rust
fn put_vecbinop(out,&mut Vec<u8>, VecBinOp)   // Add=0..UAba=16
fn put_vecunop / put_vecshiftop / put_veccmpop / put_vecpairop /
   put_vecreduceop / put_vecfpop / put_fpbinop / put_fpunop
fn put_round(out, RoundMode)   // Nearest=0,NegInf=1,PosInf=2,Zero=3,NearestTiesAway=4,Current=5
fn put_lane(out, LaneType)     // I8=0,I16=1,I32=2,I64=3,F16=4,F32=5,F64=6 (only if a lane op is added; the new ops use size:u8, so put_lane is OPTIONAL — add only if you also codec the old ConstVec128)
```
Matching `Reader` methods: `vecbinop()`, …, `round()`, returning `Result<_, SerErr>`.

**bool fields** are `put_u8(out, x as u8)` / `r.u8()? != 0` (matches `AddS sf`).

**Encode arms** (insert before catch-all at 460). Field order = exactly the struct order; decode reads in the same order. Example pair for `VecBin`:

```rust
// encode:
IrOp::VecBin { op, size, q, d, n, m } => {
    put_vecbinop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
    put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
}
// decode (match 0xCD):
0xCD => Ok((IrOp::VecBin {
    op: r.vecbinop()?, size: r.u8()?, q: r.u8()? != 0,
    d: r.u8()?, n: r.u8()?, m: r.u8()?,
}, r.pos)),
```

Apply the identical pattern to all 21 new variants. Every new variant MUST also be added to **`is_codec_implemented`** (serialize.rs:730-806 allow-list) or `at2_ir_roundtrip` panics "codec missing".

---

## 3. New encode.rs helpers

All follow the existing private formers. **`emit_sse2_op(prefix,op,dst,src)`** → `prefix [REX] 0F op /r`. **`emit_sse4_op(esc2,op,dst,src)`** → `66 [REX] 0F esc2 op /r` (always emits 66 — correct for every `0F 38`/`0F 3A` map op below). **`emit_sse_nopfx_op(op,…)`** → `0F op /r`. Four-byte imm ops follow `emit_pblendw` (1189).

### 3.1 Saturating + extra integer SSE (via `emit_sse2_op`)

| fn | bytes | former |
|----|-------|--------|
| `emit_paddsb` | `66 0F EC` | `emit_sse2_op(0x66,0xEC,d,s)` |
| `emit_paddsw` | `66 0F ED` | `emit_sse2_op(0x66,0xED,…)` |
| `emit_paddusb` | `66 0F DC` | `emit_sse2_op(0x66,0xDC,…)` |
| `emit_paddusw` | `66 0F DD` | `emit_sse2_op(0x66,0xDD,…)` |
| `emit_psubsb` | `66 0F E8` | `emit_sse2_op(0x66,0xE8,…)` |
| `emit_psubsw` | `66 0F E9` | `emit_sse2_op(0x66,0xE9,…)` |
| `emit_psubusb` | `66 0F D8` | `emit_sse2_op(0x66,0xD8,…)` |
| `emit_psubusw` | `66 0F D9` | `emit_sse2_op(0x66,0xD9,…)` |
| `emit_packsswb` | `66 0F 63` | `emit_sse2_op(0x66,0x63,…)` |
| `emit_packuswb` | `66 0F 67` | `emit_sse2_op(0x66,0x67,…)` |
| `emit_packssdw` | `66 0F 6B` | `emit_sse2_op(0x66,0x6B,…)` |
| `emit_punpckhqdq` | `66 0F 6D` | `emit_sse2_op(0x66,0x6D,…)` |
| `emit_psadbw` | `66 0F F6` | `emit_sse2_op(0x66,0xF6,…)` |
| `emit_pmaddwd` | `66 0F F5` | `emit_sse2_op(0x66,0xF5,…)` |
| `emit_pavgb` | `66 0F E0` | `emit_sse2_op(0x66,0xE0,…)` (URHADD.8b fast path) |
| `emit_pavgw` | `66 0F E3` | `emit_sse2_op(0x66,0xE3,…)` (URHADD.4h/8h) |
| `emit_pmulhw` | `66 0F E5` | `emit_sse2_op(0x66,0xE5,…)` (SQDMULH helper) |
| `emit_pmulhuw` | `66 0F E4` | `emit_sse2_op(0x66,0xE4,…)` |

### 3.2 SSSE3 / SSE4.1 / SSE4.2 (via `emit_sse4_op(0x38,…)`)

| fn | bytes | former |
|----|-------|--------|
| `emit_pabsb` | `66 0F 38 1C` | `emit_sse4_op(0x38,0x1C,…)` |
| `emit_pabsw` | `66 0F 38 1D` | `emit_sse4_op(0x38,0x1D,…)` |
| `emit_pabsd` | `66 0F 38 1E` | `emit_sse4_op(0x38,0x1E,…)` |
| `emit_phaddw` | `66 0F 38 01` | `emit_sse4_op(0x38,0x01,…)` |
| `emit_phaddd` | `66 0F 38 02` | `emit_sse4_op(0x38,0x02,…)` |
| `emit_pmaddubsw` | `66 0F 38 04` | `emit_sse4_op(0x38,0x04,…)` |
| `emit_pcmpgtq` | `66 0F 38 37` | `emit_sse4_op(0x38,0x37,…)` (SSE4.2) |
| `emit_pblendvb` | `66 0F 38 10` | `emit_sse4_op(0x38,0x10,…)` (mask implicit in XMM0 — see §1.3 note) |
| `emit_pmovsxbw` | `66 0F 38 20` | `emit_sse4_op(0x38,0x20,…)` |
| `emit_pmovsxwd` | `66 0F 38 23` | `emit_sse4_op(0x38,0x23,…)` |
| `emit_pmovsxdq` | `66 0F 38 25` | `emit_sse4_op(0x38,0x25,…)` |
| `emit_pmovzxbw` | `66 0F 38 30` | `emit_sse4_op(0x38,0x30,…)` |
| `emit_pmovzxwd` | `66 0F 38 33` | `emit_sse4_op(0x38,0x33,…)` |
| `emit_pmovzxdq` | `66 0F 38 35` | `emit_sse4_op(0x38,0x35,…)` |
| `emit_cvtph2ps` | `66 0F 38 13` | `emit_sse4_op(0x38,0x13,…)` (F16C) |

### 3.3 Imm-bearing SSE4.1 / F16C (4-byte escape, follow `emit_pblendw`)

| fn | bytes (+ ib) |
|----|------|
| `emit_roundss(d,s,imm8)` | `66 0F 3A 0A /r ib` |
| `emit_roundsd(d,s,imm8)` | `66 0F 3A 0B /r ib` |
| `emit_roundps(d,s,imm8)` | `66 0F 3A 08 /r ib` (vector FRINT) |
| `emit_roundpd(d,s,imm8)` | `66 0F 3A 09 /r ib` |
| `emit_cvtps2ph(d,s,imm8)` | `66 0F 3A 1D /r ib` (F16C) |
| `emit_insertps(d,s,imm8)` | `66 0F 3A 21 /r ib` |
| `emit_shufps(d,s,imm8)` | `0F C6 /r ib` (no 66 — use `emit_sse_nopfx_op`-style + imm) |
| `emit_pshuflw(d,s,imm8)` | `F2 0F 70 /r ib` |
| `emit_pshufhw(d,s,imm8)` | `F3 0F 70 /r ib` |

### 3.4 Packed FP min/max + sqrt (vector & scalar)

| fn | bytes | former |
|----|-------|--------|
| `emit_minps` | `0F 5D` | `emit_sse_nopfx_op(0x5D,…)` |
| `emit_maxps` | `0F 5F` | `emit_sse_nopfx_op(0x5F,…)` |
| `emit_minpd` | `66 0F 5D` | `emit_sse2_op(0x66,0x5D,…)` |
| `emit_maxpd` | `66 0F 5F` | `emit_sse2_op(0x66,0x5F,…)` |
| `emit_minss` | `F3 0F 5D` | `emit_sse_f3_op(0x5D,…)` |
| `emit_maxss` | `F3 0F 5F` | `emit_sse_f3_op(0x5F,…)` |
| `emit_minsd` | `F2 0F 5D` | `emit_sse_f2_op(0x5D,…)` |
| `emit_maxsd` | `F2 0F 5F` | `emit_sse_f2_op(0x5F,…)` |
| `emit_andpd` | `66 0F 54` | `emit_sse2_op(0x66,0x54,…)` (FP64 abs mask) |
| `emit_orps` | `0F 56` | `emit_sse_nopfx_op(0x56,…)` (copysign) |
| `emit_orpd` | `66 0F 56` | `emit_sse2_op(0x66,0x56,…)` |
| `emit_cvtps2dq` | `66 0F 5B` | `emit_sse2_op(0x66,0x5B,…)` (round-to-int packed) |
| `emit_cvttps2dq` | `F3 0F 5B` | `emit_sse_f3_op(0x5B,…)` (trunc packed) |
| `emit_cvtdq2ps` | `0F 5B` | `emit_sse_nopfx_op(0x5B,…)` |

### 3.5 GP↔XMM 32-bit and scalar mem moves + 32-bit cvt forms

⚠️ All these are "same bytes as an existing 64-bit helper but with `rex_opt(false,…)`" — the cleanest implementation mirrors the cited line.

| fn | bytes | mirror of |
|----|-------|-----------|
| `emit_movd_xmm_r32(d,s)` | `66 0F 6E /r` (no REX.W) | `emit_movq_xmm_r64` (1117), `rex_opt(false,…)` |
| `emit_movd_r32_xmm(d,s)` | `66 0F 7E /r` (no REX.W) | `emit_movq_r64_xmm` (1126), `rex_opt(false,…)` |
| `emit_movq_xmm_xmm(d,s)` | `F3 0F 7E /r` | new — zero-upper idiom (§1.4) |
| `emit_movss_load(d,base,disp)` | `F3 0F 10 /r mem` | use `modrm_mem` (zeroes [127:32]) |
| `emit_movss_store(base,disp,s)` | `F3 0F 11 /r mem` | |
| `emit_movsd_load(d,base,disp)` | `F2 0F 10 /r mem` | (zeroes [127:64]) |
| `emit_movsd_store(base,disp,s)` | `F2 0F 11 /r mem` | |
| `emit_cvtsi2ss_r32(d,s)` | `F3 0F 2A /r` (no W) | `emit_cvtsi2ss_r64` (1256) |
| `emit_cvtsi2sd_r32(d,s)` | `F2 0F 2A /r` (no W) | `emit_cvtsi2sd_r64` (1264) |
| `emit_cvttss2si_r32(d,s)` | `F3 0F 2C /r` (no W) | `emit_cvttss2si_r64` (1272) |
| `emit_cvttsd2si_r32(d,s)` | `F2 0F 2C /r` (no W) | `emit_cvttsd2si_r64` (1280) |
| `emit_cvtss2si_r64(d,s)` | `F3 0F 2D /r` (W) | non-trunc round-by-MXCSR S→i64 |
| `emit_cvtsd2si_r64(d,s)` | `F2 0F 2D /r` (W) | non-trunc D→i64 |

### 3.6 Integer ALU/branch helpers for fixups (verify presence; add if absent)

These back the saturation/NaN/u64 fixups. Grep `encode.rs` for each; the M4a integer core almost certainly has them. Add any missing:
`emit_mov_r64_imm64` (B8+rd io, REX.W), `emit_test_r64_r64` (85 /r), `emit_cmp_r64_r64`, `emit_shr_r64_imm` (C1 /5 ib), `emit_and_r64_imm32`, `emit_or_rr64`, `emit_xor_rr64`, `emit_setcc_r8(cc,reg)` (0F 90+cc /r), conditional `emit_jcc_rel32` (0F 80+cc). `emit_ucomiss`/`emit_ucomisd` confirmed present (1304/1311). `emit_mov_rr64`/`emit_mov_rr32` confirmed present.

---

## 4. context.rs changes (exact)

1. **§1.2 prologue/epilogue edit** — delete the two XMM loops, change both `reg_count` to `count`, delete `emit_vmovdqu_mem_xmm`/`emit_vmovdqu_xmm_mem`. (This is the full reconciliation; no other change needed — the model has no XMM persistence.)

2. **VEC displacement helper** — add to `context.rs` (used by lowering and tests):

```rust
/// Byte displacement of guest V<reg> within the flat context buffer.
#[inline]
pub const fn vec_disp(reg: u8) -> i32 {
    (VEC_OFFSET + (reg as usize) * 16) as i32
}
```

`lower_int.rs` already has `CONTEXT_REG`; expose `vec_disp` (or define a `const VEC_DISP_BASE: i32 = 0x128` in lower_int and compute inline). Both work; `vec_disp` keeps the offset single-sourced with `VEC_OFFSET`.

No change to `GuestRegisterFile`, `seed_sysregs`, or layout constants — `DCZID_EL0=0x4` at `sysreg slot 44` (context.rs:117) is read by DC ZVA lowering (§7.6).

---

## 5. Decoder expansion (decoder/dp_simd_fp.rs + decoder/mod.rs)

The decoder stays the gatekeeper but is refined from coarse `AdvSimd{raw}`/`FpScalar{raw}` to typed variants. **Add these `DecodedInsn` variants** to `decoder/mod.rs` (alongside `AdvSimd`/`FpScalar`/`CryptoAes`/`CryptoSha` at ~520; reuse `VReg`):

```rust
SimdThreeSame { q: bool, u: bool, size: u8, opcode: u8, rm: VReg, rn: VReg, rd: VReg },
SimdTwoRegMisc { q: bool, u: bool, size: u8, opcode: u8, rn: VReg, rd: VReg },
SimdAcrossLanes { q: bool, u: bool, size: u8, opcode: u8, rn: VReg, rd: VReg },
SimdShiftImm { q: bool, u: bool, immh: u8, immb: u8, opcode: u8, rn: VReg, rd: VReg },
SimdCopy { q: bool, op: bool, imm5: u8, imm4: u8, rn: VReg, rd: VReg },   // DUP/INS/UMOV/SMOV
FpDataProc1 { ftype: u8, opcode: u8, rn: VReg, rd: VReg },                 // FABS/FNEG/FSQRT/FCVT/FRINT/FMOV
FpDataProc2 { ftype: u8, opcode: u8, rm: VReg, rn: VReg, rd: VReg },       // FADD/FSUB/FMUL/FDIV/FMAX/FMIN/FNMUL
FpCompare { ftype: u8, op: u8, rn: VReg, rm: VReg },                       // FCMP/FCMPE/with-zero
FpIntConv { sf: bool, ftype: u8, rmode: u8, opcode: u8, rn: u8, rd: u8 },  // SCVTF/FCVT*/FMOV gen
```

Keep `AdvSimd{raw}`/`FpScalar{raw}` as the fallback for not-yet-handled sub-groups (e.g. SQDMULH, dot product) so nothing regresses to `Reserved`.

### 5.1 Discriminator bits (verified against ARM ARM C4.1.6 + the existing gates)

**SIMD 3-same** (gate `decode_simd_3same`, dp_simd_fp.rs:326; outer mask `(word&0x9F20_8400)==0x0E20_0400` at line 69):
`Q=word[30]; U=word[29]; size=word[23:22]; opcode=word[15:11]; Rm=word[20:16]; Rn=word[9:5]; Rd=word[4:0]`. The existing reserved-rejects at 331/338/343 stay. Replace `Ok(AdvSimd{raw})` (346) with `Ok(SimdThreeSame{q,u,size,opcode,rm,rn,rd})`.

`(U,opcode)` → op:

| (U,opcode) | op | (U,opcode) | op |
|---|---|---|---|
| (0,0b10000) ADD | `VecBin::Add` | (0,0b00001) SQADD | `SqAdd` |
| (1,0b10000) SUB | `VecBin::Sub` | (1,0b00001) UQADD | `UqAdd` |
| (0,0b10011) MUL | `VecBin::Mul` | (0,0b00101) SQSUB | `SqSub` |
| (0,0b10010) MLA | `VecBin::Mla` | (1,0b00101) UQSUB | `UqSub` |
| (1,0b10010) MLS | `VecBin::Mls` | (0,0b00000) SHADD | `SHadd` |
| (0,0b01110) SABD | `SAbd` | (1,0b00000) UHADD | `UHadd` |
| (1,0b01110) UABD | `UAbd` | (0,0b00010) SRHADD | `SrHadd` |
| (0,0b01111) SABA | `SAba` | (1,0b00010) URHADD | `UrHadd` |
| (1,0b01111) UABA | `UAba` | (0,0b01100) SMAX | `VecBin`→**VecPair? no**: SMAX/SMIN/UMAX/UMIN map to min/max ops below |
| (0,0b01100) SMAX | (min/max, §7.2) | (0,0b01101) SMIN | |
| (1,0b01100) UMAX | | (1,0b01101) UMIN | |
| (0,0b10001) CMGT? | **no** — CM* are at opcodes below | | |

**Compares (3-same):** `(0,0b00110)`=CMGT(signed gt), `(0,0b00111)`=CMGE, `(1,0b00110)`=CMHI(unsigned gt), `(1,0b00111)`=CMHS, `(1,0b10001)`=CMEQ. → `VecCmp{op: SGt/SGe/UGt/UGe/Eq}`. **Pairwise:** `(0,0b10111)`=ADDP, `(0,0b10100)`=SMAXP, `(0,0b10101)`=SMINP, `(1,0b10100)`=UMAXP, `(1,0b10101)`=UMINP → `VecPair`. **Min/Max (3-same):** SMAX/SMIN/UMAX/UMIN map to a `VecBin`-style but lowered via pmins/pmaxs (§7.2); model them as `VecPair`-sibling or a dedicated `VecMinMax` — to keep the op count tight, fold non-pairwise min/max into `VecBin` with ops `SMax,SMin,UMax,UMin` added to `VecBinOp` OR reuse the existing `VMin`/`VMax`... ⚠️ since the old `VMin/VMax` are dead, **add `SMax,SMin,UMax,UMin` to `VecBinOp`** and lower them in the VecBin handler. (Updates `VecBinOp` to 21 variants; update `put_vecbinop`.)

**FP 3-same** (opcode 0b11000–0b11111 with size selecting S/D): `FADD=(0,11010)`, `FSUB=(0,11010 with size[1])`... ⚠️ precise: in 3-same FP, `size[1]`=double, `size[0]`=op-half. Use opcode `0b11010`=FADD/FSUB(U bit), `0b11011`=FMUL, `0b11111`=FDIV, `0b11110`=FMAX/FMIN. Map to `VecFp{op, dbl: size&0b10 != 0}`. (FP 3-same is "later" tier; ship after integer.)

**2-reg-misc** (`decode_simd_2reg_misc`, gate line 79): `opcode=word[16:12]`. `(0,0b01011)`=ABS, `(1,0b01011)`=NEG → `VecUn{Abs|Neg}`. `(0,0b00010)`=SADDLP, `(1,0b00010)`=UADDLP → `VecAddLong{across:false,signed:!u}`. Replace coarse with `SimdTwoRegMisc{…}`.

**Across-lanes** (`decode_simd_across_lanes`, gate line 82): `opcode=word[16:12]`. `(_,0b11011)`=ADDV → `VecReduce{Add}`. `(0,0b01010)`=SMAXV,`(0,0b11010)`=SMINV,`(1,0b01010)`=UMAXV,`(1,0b11010)`=UMINV → `VecReduce{SMax/SMin/UMax/UMin}`. `(0,0b00011)`=SADDLV,`(1,0b00011)`=UADDLV → `VecAddLong{across:true,signed:!u}`.

**FP↔int convert** (`decode_fp_int_convert`, gate `(word&0x7F3F_FC00)==0x1E20_0000`, line 58): `sf=word[31]; ftype=word[23:22]; rmode=word[20:19]; opcode=word[18:16]; Rn=word[9:5]; Rd=word[4:0]`.

| rmode | opcode | insn → IR |
|---|---|---|
| 00 | 010 SCVTF / 011 UCVTF | `FpFromInt{signed: op==010, from_bits: sf?64:32, to_bits: fpbits(ftype)}` |
| 00 | 000 FCVTNS / 001 FCVTNU | `FpToIntR{round:Nearest, signed: op==000}` |
| 00 | 100 FCVTAS / 101 FCVTAU | `FpToIntR{round:NearestTiesAway,…}` |
| 00 | 110 FMOV→GPR / 111 FMOV←GPR | `FpToGpr{high_half:false}` / `FpFromGpr{high_half:false}` |
| 01 | 000 FCVTPS / 001 FCVTPU | `FpToIntR{round:PosInf,…}` |
| 01 | 110/111 (ftype=10) FMOV X↔V.D[1] | `FpToGpr{high_half:true}` / `FpFromGpr{high_half:true}` |
| 10 | 000 FCVTMS / 001 FCVTMU | `FpToIntR{round:NegInf,…}` |
| 11 | 000 FCVTZS / 001 FCVTZU | `FpToIntR{round:Zero,…}` |

`fpbits(ftype): 00→32, 01→64, 11→16, 10→reserved` (rejected by `fp_ftype_ok`).

**FP 1-src** (`decode_fp_1src`, gates 31/34): `ftype=word[23:22]; opcode=word[20:15]; Rn,Rd`.
`000000`=FMOV→`FpMov`; `000001`=FABS→`FpUn{Abs}`; `000010`=FNEG→`FpUn{Neg}`; `000011`=FSQRT→`FpUn{Sqrt}`; `0001xx`=FCVT (dest in opcode[2:0]: 00→S,01→D,11→H)→`FpCvt2{from_bits:fpbits(ftype), to_bits:fpbits(opcode&3)}`; `0010 00..11/110/111`=FRINT{N,P,M,Z,A,X,I}→`FpRound{round, raise_inexact: opcode==0b001110, dbl: ftype==01}`. FRINT opcode map: `001000`N `001001`P `001010`M `001011`Z `001100`A `001110`X `001111`I.

**FP compare** (`decode_fp_compare`, gate line 49): `ftype=word[23:22]; Rn=word[9:5]; Rm=word[20:16]; op=word[15:14]; opcode2=word[4:0]`. `opcode2[3]`(bit3 of the 0-field) selects with-zero. → `FpCmpN{n,m,dbl: ftype==01, zero: (word>>3)&1 == 1}`. `op` bit selects FCMPE (signaling) vs FCMP — both set NZCV the same; signaling only differs in exception, ignore for now.

**FP 2-src** (`decode_fp_2src`, gate 40): `opcode=word[15:12]`: `0000`FMUL `0001`FDIV `0010`FADD `0011`FSUB `0100`FMAX `0101`FMIN `1000`FNMUL → `FpBin{op, dbl: ftype==01}`. (FMAXNM/FMINNM `0110/0111` → same min/max for non-NaN; defer NaN-propagation nuance.)

---

## 6. Lift mapping (NEW file lift/simd.rs, called from lift/mod.rs)

Create `lift/simd.rs` with `pub fn lift_simd(insn: &DecodedInsn, cx: &mut LiftCtx) -> bool` (returns true if handled). Call it from the `AdvSimd`/`FpScalar` and new typed arms in `lift/mod.rs`, replacing the `Hint{200/201}` placeholders at 985-993. Because the new IR ops are **V-register-numbered**, lift does **not** emit ReadFpr/WriteFpr around them — it emits the op directly with `d/n/m = rd.0/rn.0/rm.0`. This is the key simplification.

Mappings:

```rust
SimdThreeSame{q,u,size,opcode,rm,rn,rd} =>
    match classify_3same(u,opcode) {
        Bin(op)  => cx.push(VecBin{op,size,q,d:rd.0,n:rn.0,m:rm.0}),
        Cmp(op)  => cx.push(VecCmp{op,size,q,d:rd.0,n:rn.0,m:rm.0}),
        Pair(op) => cx.push(VecPair{op,size,q,d:rd.0,n:rn.0,m:rm.0}),
        Fp(op)   => cx.push(VecFp{op,dbl:size&2!=0,q,d:rd.0,n:rn.0,m:rm.0}),
        None     => return false,   // falls back to Hint, fail-loud later
    }
SimdTwoRegMisc{..} => VecUn / VecAddLong{across:false,..}
SimdAcrossLanes{..} => VecReduce / VecAddLong{across:true,..}
FpIntConv{..} => FpFromInt | FpToIntR | FpToGpr | FpFromGpr   (per §5.1 table)
FpDataProc1{..} => FpMov | FpUn | FpCvt2 | FpRound
FpDataProc2{..} => FpBin
FpCompare{..} => FpCmpN
CryptoAes{op,rd,rn} => CryptoAesR{kind:op-4, d:rd.0, n:rn.0, m:rn.0}   // E/D use rd as state, see §7.7
```

⚠️ FIX the existing AES lift bug (lift/mod.rs:995-1004): it currently maps *all* AES ops to `AesE` with `key=v_in`. Replace with `CryptoAesR{kind, d:rd.0, n:rn.0, m:rd.0}` where for AESE/AESD the ARM op is `Vd = round(Vd, Vn)` (Vd is state+dst, Vn is key) — see §7.7 for the exact ARM↔x86 operand decomposition.

The `Ldr/Str` QuadWord path (lift/mod.rs:580-600) already routes through `WriteFpr`/`ReadFpr` — keep it; §7.0 makes those real.

---

## 7. Lower mapping (NEW file backend/lower_simd_ctx.rs, invoked from lower_int.rs)

Add `pub mod lower_simd_ctx;` to `backend/mod.rs`. In `lower_int.rs::lower_op`, replace the `ReadFpr/WriteFpr` UD2 arm (1762) and add arms for every new op that delegate to `lower_simd_ctx::lower(op, alloc, enc)`. The function signature mirrors `IntLower` but only needs `enc` (no `alloc` for the V-numbered ops; GPR-bearing ops like `FpFromInt`/`FpToGpr` read `alloc` to resolve the GPR).

Helper used everywhere: `vd(reg)=vec_disp(reg)` (§4), `R15=CONTEXT_REG`.

### 7.0 ReadFpr / WriteFpr (the vertical-slice unblocker) + LDR/STR Q

```rust
ReadFpr { dst, reg } => {
    // SSA path: load ctx Vreg into the dst's assigned XMM (if any). On the live
    // ctx model the *consumers* read ctx directly, so emit movdqu VS0,[Vreg] only
    // when dst has an XMM assignment; otherwise no-op (value lives in ctx).
    movdqu VS0, [R15 + vd(*reg)]   // when no XMM target, VS0 is the convention
}
WriteFpr { reg, src } => {
    movdqu [R15 + vd(*reg)], VS0   // src already produced into VS0 by the prior op
}
```
For **LDR Q** (`Load{ty:Vec128}`): in lower_int.rs:1299-1324 replace the `is_fp` UD2 guard for `Vec128` with: `emit_mmu_xlate_call(ra,false,16)` → `emit_movdqu_load(VS0, SCRATCH0, 0)` → `emit_movdqu_store(R15, vd(rt), VS0)`. **Load XMM only AFTER the call returns** (XMM is volatile across the Win64 `aether_mmu_xlate`). For **STR Q**: `emit_movdqu_load(VS0, R15, vd(rt))` → `emit_mmu_xlate_call(ra,true,16)` → `emit_movdqu_store(SCRATCH0,0,VS0)`. Pass size=16 so the walker's cross-page contiguity check covers the full quadword.

### 7.1 VecBin — integer 3-same (corrected saturation)

Common prologue: `movdqu VS0,[vd(n)]; movdqu VS1,[vd(m)]`. Epilogue: if `!q` apply D-zero (§1.4) to VS0; `movdqu [vd(d)],VS0`.

- **Add/Sub:** `paddb/w/d/q` or `psubb/w/d/q` by size.
- **Mul:** size H→`pmullw`, S→`pmulld`. B→widen even/odd via `punpcklbw/punpckhbw` against a zeroed VS2, `pmullw`, mask low bytes, `packuswb`. (No 64-bit MUL — `size==3` is `Reserved` in decode.)
- **Mla/Mls:** compute product (as Mul) into VS0; `movdqu VS2,[vd(d)]`; `paddb/w/d`(Mla) or `psubb/w/d`(Mls) VS2±VS0; D-zero VS2; store VS2. **(d is use+def.)**
- **SqAdd/UqAdd/SqSub/UqSub — B/H:** direct `paddsb/w`,`paddusb/w`,`psubsb/w`,`psubusb/w`.
- ⚠️ **SqAdd/SqSub — S(32) [CORRECTED]:** no SSE signed-sat-32. Manual, **with full-lane sign broadcast** (the verdict's required fix):
  ```
  ; SQADD: r = a+b ; overflow when (a,b same sign) and (r differs sign from a)
  movdqa VS2, VS0            ; a
  paddd  VS0, VS1            ; r = a+b
  movdqa VS3, VS2            ; a
  pxor   VS3, VS1            ; a^b
  pandn  VS3, <a^r>          ; ⚠ for SQADD overflow = (~(a^b)) & (a^r):
  ; build a^r:
  movdqa VS3, VS2 ; pxor VS3, VS0     ; a^r
  movdqa VStmp, VS2 ; pxor VStmp,VS1  ; a^b
  pandn  VStmp, VS3                   ; (~(a^b)) & (a^r)  == overflow sign bit
  psrad  VStmp, 31                    ; ⚠ BROADCAST sign across whole lane -> 0xFFFFFFFF/0
  ; saturation value = a<0 ? INT_MIN : INT_MAX  == (a>>31) ^ 0x7FFFFFFF
  movdqa VSsat, VS2 ; psrad VSsat,31  ; a sign-broadcast
  pxor   VSsat, <0x7FFFFFFF x4>       ; INT_MIN if a<0 else INT_MAX
  ; merge: r = (r & ~ov) | (sat & ov)   via pand/pandn/por (NOT pblendvb)
  pand   VSsat, VStmp
  pandn  VStmp, VS0                    ; VStmp = r & ~ov
  por    VStmp, VSsat
  movdqa VS0, VStmp
  ```
  ⚠️ **SQSUB overflow predicate differs:** `ov = (a^b) & (a^r)` using **PAND** (not pandn). The verdict's required fix is applied: SQADD uses `~(a^b) & (a^r)`, SQSUB uses `(a^b) & (a^r)`. The `0x7FFFFFFF×4` constant is materialized via `pcmpeqd VSc,VSc; psrld VSc,1` (all-ones >>1 = 0x7FFFFFFF). **Drop `pblendvb` entirely** — merge with pand/pandn/por (encode.rs:943-946, all present). This removes the implicit-XMM0 hazard and the byte-broadcast requirement.
- ⚠️ **SqAdd/SqSub — D(64):** same manual sat; sign broadcast has no `psraq` → broadcast bit63 via `pshufd VStmp,VStmp,0xF5` (replicate high dword into both dwords of each qword) then `psrad ,31`. Saturation value `0x7FFF_FFFF_FFFF_FFFF` via `pcmpeqd; psrlq ,1`.
- ⚠️ **UqAdd — S(32):** bias trick. `movdqa VS2,VS0; paddd VS0,VS1` (r); materialize bias `0x80000000×4` (`pcmpeqd VSb,VSb; pslld VSb,31`); `pxor VS2,VSb` (a′); `movdqa VSr2,VS0; pxor VSr2,VSb` (r′); `pcmpgtd VS2,VSr2` (mask = a′>r′ ⇒ carry); `por VS0,VS2` (saturate carried lanes to all-ones).
- **UqAdd — D(64):** same with bias `0x8000…0000` and `pcmpgtq` (SSE4.2).
- ⚠️ **UqSub — S(32):** `result=(a≥b)?a-b:0`. `movdqa VS2,VS0; pmaxud VS2,VS1` (max); `pcmpeqd VS2,VS0` (mask a≥b); `psubd VS0,VS1` (a-b); `pand VS0,VS2` (clamp neg→0). (uses `pmaxud`/`pcmpeqd`, present.)
- ⚠️ **UqSub — D(64) [CORRECTED]:** no `pmaxud`-64. Use bias-XOR ge-mask: `ge = ~pcmpgtq(b^bias, a^bias)`; `result = (a-b) & ge`. Bias `0x8000…0000`.
- **SHadd/UHadd/SrHadd/UrHadd:** `(a&b)+((a^b)>>1)` (signed→`psra`, unsigned→`psrl`) for halving; rounding uses `(a|b)-((a^b)>>1)`. **URHADD.8b→`pavgb`, .4h/.8h→`pavgw`** (exact rounding halving, single instr). Byte arith-shift path needs `packsswb` (§3.1).
- **SAbd/UAbd:** `max(a,b)-min(a,b)` via existing `pmaxs*/pmins*` (B/H/S) and `pmaxu*/pminu*`; then `psub*`.
- **SAba/UAba:** compute Abd into VS0; `movdqu VS2,[vd(d)]; padd* VS2,VS0`; D-zero; store VS2. (d use+def.)
- **SMax/SMin/UMax/UMin (added to VecBinOp):** direct `pmaxs*/pmins*/pmaxu*/pminu*` (B/H/S; no D — not encodable in 3-same).

### 7.2 VecCmp (corrected unsigned compares)

Result is all-ones/zero per lane (ARM CM* semantics), stored to `vd(d)`:
- **CMEQ:** `pcmpeqb/w/d` (D via two pcmpeqd + pand if needed, but CMEQ.2d uses `pcmpeqq` `66 0F 38 29` — add helper if 2d compare needed).
- **CMGT(signed)/CMGE:** `pcmpgtb/w/d`(a,b) for GT; GE = `pcmpgt(b,a)` then `pxor` with all-ones (NOT). 
- ⚠️ **CMHI/CMHS (unsigned) [CORRECTED — the verdict's gap]:** bias-XOR trick. `bias = 0x80/0x8000/0x80000000/0x80…0` per size. CMHI (a>b unsigned): `pxor a,bias; pxor b,bias; pcmpgt(a,b)` (signed gt on biased = unsigned gt). CMHS (a≥b unsigned): for ≤32-bit, `pcmpeqd(pmaxud(a,b),a)` (reuse pmaxud/pcmpeqd, no bias); for 64-bit use `~pcmpgtq(b^bias, a^bias)`. Bias materialized via `pcmpeqd; pslld/psllq ,31/63` and (for B/H) shift-then-mask, or `pshufb`-broadcast from a built byte. Verify bias width matches lane.

### 7.3 VecUn (ABS/NEG)

- **ABS B/H/S:** `pabsb/w/d` (§3.2, SSSE3 — matches ARM INT_MIN-stays-INT_MIN). **D(64):** `pshufd` broadcast hi-dword + `psrad ,31` to build 64-bit sign mask; `pxor(a,mask); psubq(r,mask)`.
- **NEG:** `pxor VS0,VS0; psubb/w/d/q VS0,[a]`. D-zero if `!q`.

### 7.4 VecPair / VecReduce / VecAddLong (reductions)

- **ADDP:** H→`phaddw(VS0,VS1)`, S→`phaddd(VS0,VS1)` (bit-exact ARM ADDP). 2d→`t0=punpcklqdq(n,m); t1=punpckhqdq(n,m); paddq(t0,t1)`. B→`pshufb` even/odd gather + `paddb`.
- **SMAXP/SMINP/UMAXP/UMINP:** deinterleave even/odd then `pmaxs*/pmins*/pmaxu*/pminu*`. I32: `nE=pshufd(n,0x88); mE=pshufd(m,0x88); even=punpcklqdq(nE,mE); nO=pshufd(n,0xDD); …; odd=punpcklqdq(nO,mO); pmax/pmin(even,odd)`. I16/I8: `pshufb` even/odd masks.
- **ADDV:** I32 (4s): `pshufd(VS1,VS0,0x4E); paddd; pshufd(VS1,VS0,0xB1); paddd` → lane0=sum; mask to esize; D-zero. I16: `phaddw` tree ×3 then mask 16. I8: `pxor VS1,VS1; psadbw(VS0,VS1)` → two 16-bit sums in word0/word4; `pshufd hi→lo; paddw`; mask 8.
- **SMAXV/SMINV/UMAXV/UMINV:** tree-reduce with `pmaxs*/pmins*` + `pshufd`(64,32 levels) + `pshuflw`(16 level) + `psrlw ,8`+compare (8 level). 
- **SADDLV/UADDLV:** widen-then-sum. UADDLV.16b: `pxor VS1,VS1; psadbw` (zero-extended byte reduce) → add the two partials. SADDLV: `pmovsxbw` low+high halves, `paddw`, then horizontal-sum. H→S: `pmovsx/zxwd` + `paddd`. S→D: `pmovsx/zxdq` + `paddq`. End: mask to result width, D-zero.
- **SADDLP/UADDLP:** SADDLP H→S = `pmaddwd(VS0, ones_word_const)` (exact). Byte/unsigned: even/odd isolate via `pand 0x00FF`/`psrlw 8` (+sign-fix `psllw 8; psraw 8` for signed) then `paddw`. S→D: `pmovsx/zxdq` adjacent + `paddq`.

**Constant materialization** (ones, 0x00FF, even/odd `pshufb` masks): build in two GPRs via `emit_mov_r64_imm64` + `emit_movq_xmm_r64`(low) + `emit_pinsrq`(high). Avoids needing a RIP-relative const pool (`modrm_mem` has no RIP form). Acceptable cost; these are off the hottest path.

### 7.5 VecFp / FpBin / FpUn / scalar FP (corrected)

- **VecFp:** `addps/subps/mulps/divps`(F32) or `addpd/…`(F64); FMIN→`minps/minpd`, FMAX→`maxps/maxpd`. ⚠️ ARM FMIN/FMAX with NaN/±0 differ from x86 MINPS (x86 returns src2 on NaN). For non-NaN inputs (the common case) MINPS/MAXPS are exact; full ARM NaN-quieting is a "later" refinement — document and defer.
- **FpBin (scalar):** load `movss/movsd VS0,[vd(n)]` into PXOR-zeroed VS0; `addss/subss/mulss/divss/minss/maxss`(or sd) with VS1 (loaded from `vd(m)`); FNMUL = `mulss` then `xorps` sign. Store via `movdqu` (upper already zeroed by the movss-into-zeroed-scratch). 
- **FpUn:** FABS = `andps VS0,<0x7FFFFFFF…>`(F32)/`andpd <0x7FFF…>`(F64); FNEG = `xorps VS0,<0x80000000…>`; FSQRT = `sqrtss/sqrtsd`. Sign masks materialized via GPR roundtrip.
- ⚠️ **FpMov:** `pxor VS0,VS0; movss/movsd VS0,[vd(n)]; movdqu [vd(d)],VS0` — zeroes upper. (Even if d==n, the upper-zeroing must happen.)

### 7.6 FpFromInt / FpToIntR (corrected: rounding + saturation + NaN + unsigned)

⚠️ The current `FToInt`/`IntToF` are truncate-only and ignore signed/to_bits — fully replaced.

- **FpFromInt (SCVTF/UCVTF):**
  - to_bits S → `cvtsi2ss_r32/r64`; D → `cvtsi2sd_r32/r64`; H → int→S then `cvtps2ph(imm=0)`.
  - **Signed:** direct CVTSI2Sx from the GPR (resolve via alloc).
  - **Unsigned 32-bit:** zero-extend Wn (`mov r32,r32`) into r64, then signed `cvtsi2s?_r64` (value <2^32 is a non-negative i64 — exact).
  - ⚠️ **Unsigned 64-bit:** branchless halving fixup: `mov tmp,src; shr tmp,1; mov tmp2,src; and tmp2,1; or tmp,tmp2; cvtsi2sd VS0,tmp; addsd VS0,VS0` — doubles back. Then build into zeroed VS0, store.
  - Result: build in PXOR-zeroed VS0 (upper zeroed for free), `movdqu [vd(d)],VS0`.
- **FpToIntR (FCVT{N,P,M,Z,A}{S,U}):**
  - Load src: `movss/movsd VS0,[vd(n)]` (or H: `cvtph2ps` first).
  - **Round (non-Zero):** `roundss/roundsd VS0,VS0,imm8` with imm8 = §7.6 cheat sheet, making VS0 integral, THEN `cvtt*2si` (truncating an integral value = exact). FCVTA*/ties-away has no native mode → **copysign-half-then-trunc**: build `copysign(0.5, x)` via `andps sign,<signmask>; orps half,sign; addss x,half` then `roundss ,0x0B`.
  - **Convert:** `cvttss2si_r32/r64` or `cvttsd2si_*` per to_bits.
  - ⚠️ **ARM saturation + NaN fixup (mandatory):** after cvtt into RAX, x86 returns the indefinite `0x8000…0` on NaN/overflow. Shared helper `lower_arm_fcvt_saturate(enc, to_bits, signed)` (a lower_simd_ctx private fn, NOT an encoder): `cmp RAX, indefinite_sentinel; jne done; ucomiss/sd x,x` → PF set ⇒ NaN ⇒ RAX=0; else sign of x (carry/below) ⇒ INT_MIN else INT_MAX (or 0/UINT_MAX for unsigned). 32-bit dst uses INT32 bounds.
  - ⚠️ **Unsigned (FCVTZU etc.):** to_bits=32 → cvtt into r64 then clamp to [0, 0xFFFFFFFF]. to_bits=64 → 2^63-bias: `if x<2^63: cvttsd2si; else x2=x-2^63; cvttsd2si(x2) ^ 0x8000…0`. NaN→0, neg→0.
  - Result → `WriteGpr`-style store: `mov [R15 + d_gpr*8], RAX` (with W-zero-extend if to_bits==32).

**ROUND imm8 cheat sheet** (`roundss`=`66 0F 3A 0A`, `roundsd`=`0B`; imm bits: [3]=suppress-PE, [2]=0:use-imm-RC / 1:use-MXCSR, [1:0]=RC 00=near 01=−Inf 10=+Inf 11=zero):
FRINTN/FCVTNS=`0x08`, FRINTM/FCVTMS=`0x09`, FRINTP/FCVTPS=`0x0A`, FRINTZ/FCVTZS=`0x0B`, FRINTI=`0x0C`, FRINTX=`0x04`. FCVTA*/FRINTA(ties-away)=copysign-half-then-trunc.

### 7.6b FpRound (FRINT*) / FpCvt2 (FCVT precision)

- **FpRound:** `movss/movsd` into zeroed VS0; `roundss/roundsd VS0,VS0,imm8` (cheat sheet; FRINTX=0x04, FRINTI=0x0C, FRINTA=copysign-half-trunc but result stays FP — skip the int convert). Store.
- **FpCvt2:** S→D `cvtss2sd`; D→S `cvtsd2ss`; S→H `cvtps2ph(imm=0)`; H→S `cvtph2ps`; D→H = `cvtsd2ss`+`cvtps2ph`; H→D = `cvtph2ps`+`cvtss2sd`. Build into zeroed VS0; store. **Gate H paths on F16C** (CPUID at dispatcher init); if absent, `emit_ud2` (H-form FP is rare in Android baseline — acceptable interim, matches the decoder's conservative crypto trade-off).

### 7.6c FpCmpN (FCMP → NZCV) — corrected, was throwing flags away

⚠️ The old `FCmp` emitted a bare `ucomiss` and discarded EFLAGS. Corrected:
```
movdqu/movss VS0, [vd(n)]
if zero: pxor VS1,VS1   else  movss VS1,[vd(m)]
ucomiss VS0,VS1   (or ucomisd if dbl)   ; sets ZF,PF,CF
; transcribe x86 EFLAGS -> ARM NZCV (N@31 Z@30 C@29 V@28):
;   less    -> N=1 Z=0 C=0 V=0
;   equal   -> N=0 Z=1 C=1 V=0
;   greater -> N=0 Z=0 C=1 V=0
;   unordered-> N=0 Z=0 C=1 V=1
setb  CL          ; CF = below(less or unordered)
sete  AL          ; ZF = equal or unordered
setp  DL          ; PF = unordered
; build via the existing build_nzcv pattern (SETcc capture, then pack & store 0x108):
;   V = PF
;   C = !below | PF      (equal/greater/unordered set C)
;   Z = ZF & !PF
;   N = below & !PF
; pack into the ARM word and store [R15 + NZCV_OFFSET(0x108)]
```
Reuse the integer core's `build_nzcv` packing helper (referenced in at12_int_lower.rs:360-364 — SETcc capture + pack). The `dbl` field selects ucomisd. ⚠️ The IR op carries `dbl` (the old `FCmp` could not distinguish S vs D — fixed by `FpCmpN{dbl}`).

### 7.6d FpToGpr / FpFromGpr (FMOV bitwise)

- **FpToGpr** (FMOV Wd,Sn / Xd,Dn): `movdqu VS0,[vd(n)]`; 64→`movq_r64_xmm(RAX,VS0)`; 32→`movd_r32_xmm(EAX,VS0)`. high_half: `pextrq RAX,VS0,1`. Store to `[R15+d_gpr*8]` (W-zero-extend if 32).
- **FpFromGpr** (FMOV Sd,Wn / Dd,Xn): 64→`movq_xmm_r64(VS0,src)` (zeroes upper); 32→`movd_xmm_r32(VS0,src)` (zeroes upper); store `[vd(d)]`. high_half (Vd.D[1],Xn): `movdqu VS0,[vd(d)]` FIRST (preserve low64), `pinsrq VS0,src,1`, store.

### 7.7 Crypto (AES decomposition — corrected)

⚠️ ARM AES round ≠ a single x86 AESENC. ARM splits the round into AESE (SubBytes+ShiftRows+AddRoundKey, no MixColumns) / AESMC (MixColumns) and AESD/AESIMC. x86 AESENC = ShiftRows+SubBytes+MixColumns+XorKey (fused). Exact mapping:
- **AESE Vd, Vn** (Vd=state, Vn=key): ARM does `state ^= key` then SubBytes+ShiftRows (no MixColumns). x86 AESENC includes MixColumns, so: emulate AESE as `pxor state,key` then `aesenclast state, <zero>` (AESENCLAST = SubBytes+ShiftRows+XorKey with zero key = SubBytes+ShiftRows only). So: `movdqu VS0,[vd(d)]; movdqu VS1,[vd(n)]; pxor VS0,VS1; pxor VS1,VS1; aesenclast VS0,VS1; movdqu [vd(d)],VS0`.
- **AESMC Vd, Vn:** MixColumns only. x86 has no standalone MixColumns; use the identity `AESMC(x) = AESDECLAST(AESENC(x, 0))`? Cleaner: `aesenclast(0)` already did SubBytes+ShiftRows in AESE; **the standard FEX/QEMU trick** is AESMC = `aesenc(x, 0)` XOR'd appropriately — but the bit-exact route is: `movdqu VS0,[vd(n)]; pxor VS1,VS1; aesenc VS0,VS1` gives SubBytes+ShiftRows+MixColumns of an already-SubByted input → not pure MC. **Authoritative bit-exact AESMC:** there is no single x86 instr; emit the GF(2^8) MixColumns via the documented `AESMC(s) = AESENC(AESDECLAST(s, 0), 0)`?? — this is error-prone. **Decision:** ship AESE/AESD (the common AES-CBC/CTR path that bionic/keystore uses combines AESE+AESMC per round) by **fusing** ARM's AESE→AESMC pair-detection in lift: when lift sees `AESE Vd,Vn` immediately followed by `AESMC Vd,Vd`, emit a single `CryptoAesR{kind=FusedEnc}` lowered to `pxor state,key; aesenc state,<zero>` (exact full round). Standalone AESMC/AESIMC (rare) → `emit_ud2` interim (fail-loud). Document this as the AES coverage boundary for M4b-6.
- **AESD Vd,Vn:** `pxor state,key; aesdeclast state,<zero>`. Fused AESD→AESIMC → `pxor; aesdec state,<zero>`.
- **AESIMC standalone:** `aesimc` (encode.rs:1217, present) — direct.
- **SHA1/SHA256:** SHA-NI (`sha1rnds4`/`sha256rnds2` etc.) helpers are NOT in encode.rs. SHA is "later" tier — `emit_ud2` interim (fail-loud); add SHA-NI encoders in a follow-on. (Android dm-verity/keystore use AES heavily, SHA less on the JIT hot path.)

### 7.8 ⚠️ DC ZVA (corrected — was a silent no-op)

DC ZVA currently lifts to `Hint{imm:128}` (no-op) → leaves memory uninitialized. Fix in **lift** (the SysDc arm): detect `op1=0b011, CRn=0b0111, CRm=0b0100, op2=0b001`, read `DCZID_EL0` from ctx (`sysreg slot 44` = 64-byte block per seed), align Xt down to block_size, and emit `block_size/16` Vec128 zero-stores **through the MMU store path** (`aether_mmu_store`), not raw host memory. Lowering: `pxor VS0,VS0` once, then per 16-byte chunk: compute aligned guest addr in a GPR, `emit_mmu_xlate_call(addr,true,16)`, `emit_movdqu_store(SCRATCH0,0,VS0)`. This satisfies the No-Boundary window clamp + MMIO routing.

### 7.9 Post-index store ordering (corrected)

⚠️ `lift/mod.rs:144-157` writes base+imm BEFORE the access; for `STR Xt,[Xn],#imm` where Xt aliases Xn, the post-incremented value is stored. Fix: in `lift_addr_mode` for PostIndex, **snapshot the original base into a temp IR value, emit the access using the snapshot, THEN write back base+imm.** For loads the snapshot is already taken; ensure stores read `Rt` (and the base) before the writeback IR op is pushed.

---

## 8. IMPLEMENTATION ORDER (dependency-ordered, conflict-free)

### Tier 0 — Foundation (single-threaded; everything depends on it)
1. **context.rs §1.2 + §4** — delete XMM prologue/epilogue loops + dead VEX helpers; add `vec_disp`. Fix `at19_context` assertion. → `cargo test --lib` green.
2. **regalloc/x86_regs.rs §1.3** — add `VS0..VS3`, `XMM_ALLOC_FIRST_INDEX`; teach `linear_scan` to start XMM at index 4 (defensive). → green.
3. **encode.rs §3** — add ALL new emit_* helpers (saturation, SSSE3/SSE4, F16C, round, packed-fp-minmax, movd-32, scalar-mem, 32-bit cvt, ALU/branch fixup). Each with a byte-exact unit test in `at11_encoder.rs`. → green (pure additive).
4. **ir/ops.rs + ir/serialize.rs §2** — add the 21 new variants + enums + enum-codec helpers + encode/decode arms + `is_codec_implemented` entries + the five visitor `_ => {}` arms. Extend `at2_ir_roundtrip.rs` samples() with one of each. → `cargo test --lib at2` green.
5. **decoder/mod.rs §5** — add the new `DecodedInsn` variants (additive; AdvSimd/FpScalar stay as fallback). → green.
6. **backend/mod.rs + lower_simd_ctx.rs scaffold** — create empty `lower_simd_ctx::lower(op,alloc,enc)` with `match` over the new ops, all arms `emit_ud2()` initially. Wire `lower_int.rs` ReadFpr/WriteFpr + new-op arms to delegate. → green, nothing executes yet but compiles.

**Minimal vertical slice (gets the kernel past its FIRST SIMD instruction):** implement, in this exact order, just (a) §7.0 ReadFpr/WriteFpr + LDR/STR Q, (b) §7.1 VecBin Add/Sub/And/Or/Xor (the kernel-early `copy_page.S`/`__memcpy` use LDP/STP Q and bitwise/add NEON), (c) §7.8 DC ZVA (kernel `clear_page` uses it constantly). Wire decode→lift→lower for those. **This is the kernel-early gate.** Everything else is bionic-init or later.

### Tier 1 — per-family modules (parallelizable; each is one isolated `fn lower_<family>` + its decode/lift classifier entries; no shared mutable state ⇒ no merge conflicts)

| Family | File touch | Tier | Lower §  |
|---|---|---|---|
| VecBin add/sub/logic/min-max/abd | lower_simd_ctx.rs | **kernel-early** | 7.1/7.2 |
| LDR/STR Q, LDP/STP Q (§ below) | lower_int.rs | **kernel-early** | 7.0 |
| DC ZVA | lift/mod.rs + lower_int.rs | **kernel-early** | 7.8 |
| VecBin mul/mla/mls | lower_simd_ctx.rs | bionic-init | 7.1 |
| VecBin saturating (Sq/Uq) | lower_simd_ctx.rs | bionic-init | 7.1 |
| VecCmp (incl. CMHI/CMHS) | lower_simd_ctx.rs | bionic-init | 7.2 |
| VecUn ABS/NEG | lower_simd_ctx.rs | bionic-init | 7.3 |
| VecPair/VecReduce/VecAddLong | lower_simd_ctx.rs | bionic-init | 7.4 |
| FpFromInt/FpToIntR (+fixups) | lower_simd_ctx.rs | bionic-init | 7.6 |
| FpCmpN→NZCV | lower_simd_ctx.rs | bionic-init | 7.6c |
| FpMov/FpToGpr/FpFromGpr | lower_simd_ctx.rs | bionic-init | 7.6d |
| FpBin/FpUn/VecFp scalar+vector | lower_simd_ctx.rs | bionic-init | 7.5 |
| FpRound/FpCvt2 (F16C-gated) | lower_simd_ctx.rs | later | 7.6b |
| AES (fused E/D) | lift + lower_simd_ctx.rs | later | 7.7 |
| SHA-NI | encode.rs + lower | later | 7.7 |

⚠️ **LDP/STP Q fix** (verdict): `DecodedInsn::Ldp/Stp` have no size field, so `LDP Q0,Q1` miscompiles as a 64-bit GPR pair. Add `is_q: bool` to `Ldp`/`Stp` (decoder/mod.rs:325-337); set it in `decode_pair`'s V=1 branch; in lift, when `is_q`, emit two `Load{ty:Vec128}+WriteFpr` (at addr, addr+16) instead of `LoadPair{U64}`. Apply the rt1==rt2 reject on the V=1 path. **(kernel-early — `copy_page.S` uses LDP/STP q.)**

⚠️ **LD1/ST1 single+multiple structures** do not decode at all (verdict): add masks to `load_store.rs::decode` for the AdvSIMD ld/st classes (`(word&0xBFFF0000)==0x0C000000` no-wb multi, `0x0C800000` post-index multi, `0x0D000000`/`0x0D800000` single) → new `decode_simd_ldst_multi/single` → `SimdLdSt{load,kind,rt:VReg,count,size,q,writeback}`. Lift: LD1 single-reg = movdqu template; multi-reg = advance addr +16/reg; LD2/3/4 = de-interleave (`punpck`/`pshufb`). **Tier: bionic-init** (LD1 multi is common in memcpy/strlen NEON; LD2/3/4 in pixel/audio — later). This is its own module slice.

### Tier 2 — tests (after each family lands)

---

## 9. Test plan (`cargo test --lib`; cargo at `C:\Users\VAJRA\.cargo\bin`)

For each family, two test kinds:

**(A) Byte-exact encoder/lowering anchors** (in `at11_encoder.rs` and `at13_simd_lower.rs`):
- `emit_paddsb(1,2)` ⇒ `[0x66,0x0F,0xEC,0xCA]`; `emit_pabsd(0,1)` ⇒ `[0x66,0x0F,0x38,0x1E,0xC1]`; `emit_roundsd(0,1,0x08)` ⇒ `[0x66,0x0F,0x3A,0x0B,0xC1,0x08]`; `emit_pcmpgtq(2,3)` ⇒ `[0x66,0x0F,0x38,0x37,0xD3]`; `emit_cvtph2ps(0,1)` ⇒ `[0x66,0x0F,0x38,0x13,0xC1]`; `emit_movd_xmm_r32(0,Rax)` ⇒ `[0x66,0x0F,0x6E,0xC0]`.
- Lowering anchors: `VecBin{Add,size:2,q:true,d:0,n:1,m:2}` ⇒ `movdqu VS0,[R15+0x138]; movdqu VS1,[R15+0x148]; paddd VS0,VS1; movdqu [R15+0x128],VS0` byte sequence. `FpToGpr{Xd,Dn}` ⇒ `movdqu VS0,[Vn]; movq RAX,VS0; mov [R15+d*8],RAX`. `FpFromInt SCVTF Dd,Xn` ⇒ `pxor VS0,VS0; cvtsi2sd VS0,gpr; movdqu [Vd],VS0`.

**(B) Semantic round-trips** (decode→lift→encode→**execute on host** via the existing `at_exec_proof.rs`/`at13` harness that runs emitted bytes against a real ctx buffer):
- VecBin: `ADD V0.4s,V1.4s,V2.4s` with known lanes; assert ctx q0 == lane-wise sum, `q0[127:64]` preserved for Q=1, zeroed for Q=0 (`ADD V0.2s`).
- Saturation: `SQADD V0.4s` with a=INT_MIN,b=-1 ⇒ INT_MIN (per verdict's required test); `UQADD V0.4s` a=0xFFFFFFFF,b=1 ⇒ 0xFFFFFFFF; `SQSUB` a=INT_MIN,b=1 ⇒ INT_MIN.
- CMHI/CMHS: a=0x80000000,b=1 unsigned ⇒ CMHI all-ones (verdict gap closed).
- Reductions: `ADDV S0,V1.4s` ⇒ lane0=sum, upper zeroed; `UADDLV H0,V1.16b`.
- FP convert: `FCVTZS W0,S0` with S0=NaN ⇒ 0; S0=+3e38 ⇒ 0x7FFFFFFF; `FCVTZU X0,D0` with D0=1.8e19 ⇒ correct u64; `FCVTNS W0,S0` S0=2.5 ⇒ 2, S0=3.5 ⇒ 4 (ties-even); `SCVTF`/`UCVTF` u64≥2^63.
- FCMP: equal ⇒ NZCV=0b0110; less ⇒ 0b1000; greater ⇒ 0b0010; unordered (NaN) ⇒ 0b0011 (C=1,V=1 — the canonical bug, now tested).
- DC ZVA: pre-fill 64 bytes with 0xAA, `DC ZVA,X0`, assert all 64 zeroed via the MMU path.
- AES: fused `AESE+AESMC` round vs a reference AES round vector (FIPS-197 test vector).
- IR codec: every new variant added to `at2_ir_roundtrip.rs` samples() — assert `is_codec_implemented`, encode ok, decode ok, `len==buf.len()`, decoded==original.

**Gate:** all `at2`, `at11`, `at12`, `at13`, `at19`, `at_exec_proof` green; the kernel-early slice (LDP/STP Q + VecBin + DC ZVA) executes a real ARM64 NEON block on host without UD2.

---

## Files touched (absolute paths)

- `D:\AETHER\aether-translator\src\runtime\context.rs` — §1.2, §4
- `D:\AETHER\aether-translator\src\regalloc\x86_regs.rs` — §1.3
- `D:\AETHER\aether-translator\src\regalloc\linear_scan.rs` — honor `XMM_ALLOC_FIRST_INDEX`
- `D:\AETHER\aether-translator\src\backend\encode.rs` — §3
- `D:\AETHER\aether-translator\src\ir\ops.rs` — §2.1
- `D:\AETHER\aether-translator\src\ir\value.rs` — supporting enums (or in ops.rs)
- `D:\AETHER\aether-translator\src\ir\serialize.rs` — §2.2
- `D:\AETHER\aether-translator\src\decoder\mod.rs` — §5 new DecodedInsn variants, Ldp/Stp `is_q`
- `D:\AETHER\aether-translator\src\decoder\dp_simd_fp.rs` — §5 typed decode
- `D:\AETHER\aether-translator\src\decoder\load_store.rs` — LDP/STP Q size, LD1/ST1 masks
- `D:\AETHER\aether-translator\src\lift\mod.rs` — call lift_simd; DC ZVA; post-index fix; AES fix; QuadWord LDP/STP
- `D:\AETHER\aether-translator\src\lift\simd.rs` — **NEW** §6
- `D:\AETHER\aether-translator\src\backend\lower_simd_ctx.rs` — **NEW** §7
- `D:\AETHER\aether-translator\src\backend\lower_int.rs` — §7.0 ReadFpr/WriteFpr/Load/Store Vec128 + delegate new ops
- `D:\AETHER\aether-translator\src\backend\mod.rs` — register `lower_simd_ctx`
- Tests: `at2_ir_roundtrip.rs`, `at11_encoder.rs`, `at13_simd_lower.rs`, `at19_context.rs`, plus exec-proof additions

**Out of scope / explicitly NOT touched:** `backend/lower_simd.rs` (dead SSA path — leave or delete later); the old `IrValueId`-keyed `VAdd..FCmp` ops (deprecated, unreferenced on live path). Do not build on either.