//! AT-19: Guest context save / restore.
//!
//! On every VM exit (HLT, EPT/NPT fault, timer IRQ) the hypervisor must:
//!   1. **Save** the current translated-block register file back into the
//!      `GuestRegisterFile` stored in AETHER's `GuestContext`.
//!   2. **Restore** from `GuestRegisterFile` when re-entering the translated
//!      block after the exit is handled.
//!
//! # Layout (must match hypervisor/src/arm64/context.rs)
//!
//! ```text
//! Offset   Size   Field
//! 0x000    8×31   x0..x30       (248 bytes)
//! 0x0F8    8      sp
//! 0x100    8      pc
//! 0x108    8      nzcv
//! 0x110    24     _padding      (align vec[] to 32-byte boundary)
//! 0x128    16×32  q0..q31       (512 bytes)
//! 0x328    —      end (808 bytes total)
//! ```
//!
//! # x86_64 prologue / epilogue strategy
//!
//! The `ContextManager` emits x86_64 code that uses R15 (CONTEXT_REG) as the
//! base pointer into `GuestRegisterFile`.  This matches `lower_int::CONTEXT_REG`.
//!
//! **Save prologue** (emitted at the head of every translated block):
//!   MOV [R15 + 0],  RAX   ; x0
//!   MOV [R15 + 8],  RBX   ; x1
//!   …
//!   (for every GPR in the translated block's live-out set)
//!
//! **Restore epilogue** (emitted before every VM re-entry):
//!   MOV RAX, [R15 + 0]    ; x0
//!   …
//!
//! For the gate test (no actual x86 execution), `ContextManager` computes the
//! expected byte layout and verifies it matches the constants above.
//!
//! Gate: round-trip save→restore of all 31 GPRs + 32 NEON regs + SP + PC +
//! NZCV produces byte-identical `GuestRegisterFile`.

use alloc::vec::Vec;

// ── Layout constants ──────────────────────────────────────────────────────────

/// Byte offset of x0..x30 (31 × 8 bytes).
pub const GPR_OFFSET: usize = 0x000;
/// Byte offset of SP.
pub const SP_OFFSET: usize = 0x0F8;
/// Byte offset of PC.
pub const PC_OFFSET: usize = 0x100;
/// Byte offset of NZCV.
pub const NZCV_OFFSET: usize = 0x108;
/// Byte offset of q0..q31 (32 × 16 bytes).
pub const VEC_OFFSET: usize = 0x128;
/// Total size of `GuestRegisterFile` in bytes.
pub const GUEST_REG_FILE_SIZE: usize = 0x328;

/// Byte displacement of guest V<reg> (q0..q31) within the flat context buffer,
/// i.e. the disp32 to use with a `[R15 + disp]` movdqu in the SIMD templates.
/// Single-sourced off `VEC_OFFSET` so the q-register base can never drift.
#[inline]
pub const fn vec_disp(reg: u8) -> i32 {
    (VEC_OFFSET + (reg as usize) * 16) as i32
}

// ── M4a extended R15 context layout (beyond GuestRegisterFile) ────────────────
//
// The translated code addresses three regions off CONTEXT_REG (R15). The
// GuestRegisterFile struct stays 0x328 bytes; the sysreg + spill regions live
// ABOVE it in the flat context buffer the hypervisor / host harness allocate.
// Reconciled so no offsets collide:
//   [GuestRegisterFile 0x000..0x327][sysreg 0x328..0x527][spill 0x528..0x727]
//
//   nzcv         @ 0x108  (inside GuestRegisterFile; ARM N@31 Z@30 C@29 V@28)
//   sysreg[0..64]@ 0x328  (64 × u64; idx 40..55 = RO ID regs, idx 63 = sink)
//   spill[0..64] @ 0x528  (64 × u64; linear-scan spill slots)
//
/// First byte offset of the 64-slot system-register array.
pub const SYSREG_BASE: usize = 0x328;
/// Number of system-register slots.
pub const SYSREG_SLOTS: usize = 64;
/// u64 index (not byte offset) of sysreg slot 0 in the flat context buffer.
pub const SYSREG_SLOT0: usize = SYSREG_BASE / 8; // 101
/// Sink slot index for unmodeled / RO-on-write registers.
pub const SYSREG_SINK_IDX: usize = 63;
/// B25: single-vCPU exclusive monitor — reserved granule VA (slot 61) and a
/// valid flag (slot 62). LoadExclusive (LDXR/LDAXR) records the granule and
/// sets valid; StoreExclusive (STXR/STLXR) succeeds (status 0) only if the
/// reservation is still valid for the same granule, then clears it. (Slots
/// 56-58 = pending-fault, 59/60 = MMU scratch, 63 = sink.)
pub const RESV_VA_DISP: i32 = (SYSREG_BASE + 61 * 8) as i32; // 0x510
pub const RESV_VALID_DISP: i32 = (SYSREG_BASE + 62 * 8) as i32; // 0x518
/// First byte offset of the 64-slot linear-scan spill area.
pub const SPILL_BASE: usize = 0x528;
/// Number of spill slots.
pub const SPILL_SLOTS: usize = 64;
/// Total extended-context size in bytes (GuestRegisterFile + sysreg + spill).
pub const CTX_SIZE: usize = 0x728;
/// Total extended-context size in u64 slots — the size the hypervisor
/// `M2_REGFILE` static and the host-test ctx buffer must allocate.
pub const CTX_U64S: usize = CTX_SIZE / 8; // 229

// Compile-time guards: the regions tile exactly and do not overlap.
const _: () = assert!(SYSREG_BASE == GUEST_REG_FILE_SIZE);
const _: () = assert!(SYSREG_BASE + SYSREG_SLOTS * 8 == SPILL_BASE);
const _: () = assert!(SPILL_BASE + SPILL_SLOTS * 8 == CTX_SIZE);
const _: () = assert!(SYSREG_BASE + SYSREG_SINK_IDX * 8 < SPILL_BASE); // sink in range
const _: () = assert!(NZCV_OFFSET < SYSREG_BASE); // nzcv untouched by both regions

/// Seed the read-only ID system registers into a flat context buffer, so that
/// `MRS Xn, <ID reg>` is a plain load returning a plausible CPU identity (per
/// the CLAUDE.md hardware-authenticity rule: MIDR/MPIDR must read real values).
/// Call once after zeroing the buffer, before the first block dispatch.
///
/// `ctx` must be at least `CTX_U64S` long.
pub fn seed_sysregs(ctx: &mut [u64]) {
    debug_assert!(ctx.len() >= CTX_U64S, "context buffer too small for sysregs");
    let s = |i: usize| SYSREG_SLOT0 + i;
    // SPSel = 1 — the guest runs at EL1h (uses SP_EL1), the bring-up state the
    // ARM64 Linux kernel assumes. exceptions::vector_offset() reads this slot to
    // pick the EL1h vector group (VBAR_EL1 + 0x200); a 0 (unseeded) value would
    // route every injected abort/IRQ to the EL1t group (0x000 → Linux's
    // invalid-EL1t handler → bad_mode panic). The guest also keeps it correct
    // via `MSR SPSel,#1` once PSTATE-immediate writes are functional.
    ctx[s(23)] = 1; // SPSel_EL1 — EL1h
    ctx[s(40)] = 0x410F_D0C0; // MIDR_EL1   — ARM Cortex-A-class implementer
    ctx[s(41)] = 0x8000_0000; // MPIDR_EL1  — core0, bit31 RES1
    ctx[s(42)] = 0x4; // CurrentEL  — EL1 (bits[3:2]=01)
    ctx[s(43)] = 0x8444_4004; // CTR_EL0    — 64B I/D line
    ctx[s(44)] = 0x4; // DCZID_EL0  — 64-byte zero block
    ctx[s(45)] = 24_000_000; // CNTFRQ_EL0 — 24 MHz
    ctx[s(46)] = 0x0000_0000_1100_0011; // ID_AA64PFR0 — EL0/EL1 AArch64, FP/SIMD
    ctx[s(47)] = 0; // ID_AA64PFR1
    ctx[s(48)] = 0x0000_0000_0010_1122; // ID_AA64MMFR0 — 40-bit PA, 4K granule
    ctx[s(49)] = 0; // ID_AA64MMFR1
    ctx[s(50)] = 0; // ID_AA64MMFR2
    // ID_AA64ISAR0 — Atomic field [23:20] = 2 (FEAT_LSE present). The kernel then
    // patches cmpxchg_double/atomic alternatives to the single-instruction LSE
    // forms (CAS/CASP/LDADD/SWP), which the DBT now decodes+lowers correctly.
    // (Was 0x..1011.. = Atomic 1, an invalid value that forced the LL/SC path —
    // a workaround from before CASP was implemented; the LL/SC cmpxchg_double
    // double-allocated the SLUB vma freelist at the first fork.)
    ctx[s(51)] = 0x0000_1000_1021_0000; // ID_AA64ISAR0
    ctx[s(52)] = 0; // ID_AA64ISAR1
    ctx[s(53)] = 0x0A20_0023; // CLIDR_EL1  — L1 I+D, L2 unified
    ctx[s(54)] = 0; // REVIDR_EL1
    ctx[s(55)] = 0; // AIDR_EL1
    ctx[s(63)] = 0; // overflow sink
}

// ── Register file ─────────────────────────────────────────────────────────────

/// In-memory layout of the guest ARM64 register state as seen from EL2.
///
/// `repr(C)` so that field offsets are stable and can be cross-checked against
/// the constants above.
///
/// Vector registers are stored as `[u64; 2]` pairs rather than `u128` to
/// guarantee 8-byte alignment regardless of platform (u128 may have 16-byte
/// alignment on some ABIs, which would shift the vec[] array and break the
/// layout constants).
#[repr(C)]
pub struct GuestRegisterFile {
    /// x0..x30 (index 0 = x0, index 30 = x30).
    pub gpr: [u64; 31],
    /// Stack pointer (SP_EL0 or SP_EL1 depending on SPSEL).
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Condition flags (NZCV in bits [31:28]; remaining bits reserved).
    pub nzcv: u64,
    /// Padding to place vec[] at VEC_OFFSET (0x128).
    _pad: [u64; 3],
    /// q0..q31 as pairs of u64 (little-endian: vec[n][0]=low64, vec[n][1]=high64).
    pub vec: [[u64; 2]; 32],
}

impl GuestRegisterFile {
    /// Create a zeroed register file.
    pub fn zeroed() -> Self {
        Self {
            gpr: [0u64; 31],
            sp: 0,
            pc: 0,
            nzcv: 0,
            _pad: [0u64; 3],
            vec: [[0u64; 2]; 32],
        }
    }

    /// Return a raw byte slice view (for DMA-style copy into VMCS/VMCB).
    #[allow(unsafe_code)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `repr(C)` struct; all fields are plain integer types with
        // no padding ambiguity; the reference is valid for the struct lifetime.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Return a mutable raw byte slice view.
    #[allow(unsafe_code)]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: same as `as_bytes`.
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Read GPR `n` (0 = x0, 30 = x30).
    pub fn read_gpr(&self, n: usize) -> u64 {
        assert!(n < 31, "GPR index out of range");
        self.gpr[n]
    }

    /// Write GPR `n`.
    pub fn write_gpr(&mut self, n: usize, val: u64) {
        assert!(n < 31, "GPR index out of range");
        self.gpr[n] = val;
    }

    /// Read NEON register `n` as a u128 (0 = q0, 31 = q31).
    pub fn read_vec(&self, n: usize) -> u128 {
        assert!(n < 32, "NEON register index out of range");
        let lo = self.vec[n][0] as u128;
        let hi = self.vec[n][1] as u128;
        lo | (hi << 64)
    }

    /// Write NEON register `n`.
    pub fn write_vec(&mut self, n: usize, val: u128) {
        assert!(n < 32, "NEON register index out of range");
        self.vec[n][0] = val as u64;
        self.vec[n][1] = (val >> 64) as u64;
    }
}

/// Verify that `GuestRegisterFile` offsets match the layout constants.
pub fn verify_layout() -> bool {
    // Use `offset_of!` style check via pointer arithmetic.
    let rf = GuestRegisterFile::zeroed();
    let base = &rf as *const _ as usize;

    let gpr_ok = &rf.gpr as *const _ as usize - base == GPR_OFFSET;
    let sp_ok = &rf.sp as *const _ as usize - base == SP_OFFSET;
    let pc_ok = &rf.pc as *const _ as usize - base == PC_OFFSET;
    let nzcv_ok = &rf.nzcv as *const _ as usize - base == NZCV_OFFSET;
    let vec_ok = &rf.vec as *const _ as usize - base == VEC_OFFSET;
    let size_ok = core::mem::size_of::<GuestRegisterFile>() == GUEST_REG_FILE_SIZE;

    gpr_ok && sp_ok && pc_ok && nzcv_ok && vec_ok && size_ok
}

// ── x86_64 prologue / epilogue emitter ───────────────────────────────────────

/// x86_64 register encodings for the 15 allocatable GPRs (matching
/// `regalloc::x86_regs::ALLOCATABLE_GPRS`).
///
/// Layout: RAX=0, RCX=1, RDX=2, RBX=3, RSI=6, RDI=7, R8=8, …, R14=14.
/// R15 is the context register and is NOT allocatable.
const X86_GPRS: &[u8] = &[0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14]; // 13 regs

/// The context-base register (R15 = encoding 15).
pub const CONTEXT_REG_ENC: u8 = 15;

/// Emitted code descriptor for a save/restore sequence.
pub struct ContextCode {
    /// Raw x86_64 bytes of the prologue (save) or epilogue (restore).
    pub bytes: Vec<u8>,
    /// Number of registers saved / restored.
    pub reg_count: usize,
}

/// Emits the x86_64 save prologue: `MOV [R15+offset], reg` for each GPR.
///
/// Uses REX.W + MOV r/m64, r64 (opcode 89).
pub fn emit_save_prologue(arm_gpr_count: usize) -> ContextCode {
    let count = arm_gpr_count.min(X86_GPRS.len());
    let mut bytes = Vec::new();

    for i in 0..count {
        let x86_reg = X86_GPRS[i];
        let offset = GPR_OFFSET + i * 8;
        emit_mov_mem_reg(&mut bytes, CONTEXT_REG_ENC, offset as i32, x86_reg);
    }

    // M4b-6: the NEON q-registers are NOT saved/restored here. Under the
    // ctx-template SIMD model the guest q-register file at [R15+VEC_OFFSET] is
    // authoritative between ops and between blocks — every vector op loads its
    // operands from ctx and stores its result back to ctx, so there is nothing
    // for a block prologue/epilogue to persist. A blind "save XMM0..15 -> ctx"
    // here would clobber q0..q15 with whatever stale scratch the templates left
    // in those XMMs. (The old loop also mis-encoded the R15 base via a 2-byte
    // VEX that cannot carry REX.B.)
    ContextCode { bytes, reg_count: count }
}

/// Emits the x86_64 restore epilogue: `MOV reg, [R15+offset]` for each GPR.
pub fn emit_restore_epilogue(arm_gpr_count: usize) -> ContextCode {
    let count = arm_gpr_count.min(X86_GPRS.len());
    let mut bytes = Vec::new();

    // M4b-6: no XMM restore — the q-register file in ctx is authoritative; see
    // emit_save_prologue. Vector ops re-load from ctx on demand.
    for i in 0..count {
        let x86_reg = X86_GPRS[i];
        let offset = GPR_OFFSET + i * 8;
        emit_mov_reg_mem(&mut bytes, x86_reg, CONTEXT_REG_ENC, offset as i32);
    }

    ContextCode { bytes, reg_count: count }
}

// ── Low-level instruction emitters ───────────────────────────────────────────

/// Emit `MOV [base_reg + disp32], src_reg` (REX.W + 89 /r + disp32).
fn emit_mov_mem_reg(buf: &mut Vec<u8>, base: u8, disp: i32, src: u8) {
    // REX.W = 1 (64-bit operand); REX.R = src >= 8; REX.B = base >= 8.
    let rex = 0x48 | ((src >> 3) << 2) | (base >> 3);
    buf.push(rex);
    buf.push(0x89); // MOV r/m64, r64
    // ModRM: mod=10 (disp32), reg=src&7, rm=base&7.
    // If base == RSP (4) or R12 (12), a SIB byte is needed — handled here.
    let rm = base & 7;
    let modrm = 0x80 | ((src & 7) << 3) | rm;
    buf.push(modrm);
    if rm == 4 {
        buf.push(0x24); // SIB: index=none, base=RSP/R12
    }
    buf.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `MOV dst_reg, [base_reg + disp32]` (REX.W + 8B /r + disp32).
fn emit_mov_reg_mem(buf: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let rex = 0x48 | ((dst >> 3) << 2) | (base >> 3);
    buf.push(rex);
    buf.push(0x8B); // MOV r64, r/m64
    let rm = base & 7;
    let modrm = 0x80 | ((dst & 7) << 3) | rm;
    buf.push(modrm);
    if rm == 4 {
        buf.push(0x24);
    }
    buf.extend_from_slice(&disp.to_le_bytes());
}

// (The two VEX-prefixed VMOVDQU helpers that used to live here were removed in
// M4b-6: they were emitted only by the now-deleted XMM prologue/epilogue loops
// and were structurally mis-encoded — a 2-byte VEX (C5) cannot carry REX.B, so
// they addressed the wrong base register for R15. The ctx-template SIMD path
// uses the correctly-REX'd `emit_movdqu_load`/`emit_movdqu_store` in encode.rs.)

// ── Structural round-trip test helper ────────────────────────────────────────

/// Simulate save + restore by directly reading/writing `GuestRegisterFile`
/// fields.  Used by the AT-19 gate test.
pub fn round_trip_test() -> bool {
    let mut src = GuestRegisterFile::zeroed();
    for i in 0..31 {
        src.gpr[i] = 0xDEAD_BEEF_0000_0000 + i as u64;
    }
    src.sp = 0x1234_5678_9ABC_DEF0;
    src.pc = 0xFFFF_8000_0000_4000;
    src.nzcv = 0b1010_0000_0000_0000_0000_0000_0000_0000;
    for i in 0..32 {
        src.write_vec(i, 0xCAFE_BABE_0000_0000_CAFE_BABE_0000_0000_u128 + i as u128);
    }

    // "Save" = copy src bytes into a buffer, "restore" = copy buffer back.
    let src_bytes: Vec<u8> = src.as_bytes().to_vec();
    let mut dst = GuestRegisterFile::zeroed();
    dst.as_bytes_mut().copy_from_slice(&src_bytes);

    // Verify.
    dst.gpr == src.gpr
        && dst.sp == src.sp
        && dst.pc == src.pc
        && dst.nzcv == src.nzcv
        && dst.vec.iter().zip(src.vec.iter()).all(|(a, b)| a == b)
}
