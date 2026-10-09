//! AT-11: x86_64 machine-code encoder.
//!
//! Hand-rolled REX / ModR/M / SIB / immediate / RIP-relative encoding.
//! No external dependencies — required for UEFI link cleanliness.
//!
//! Gate: encode 100 % of opcodes consumed by AT-12/13/14 lowering;
//! byte-exact match against LLVM-MC reference vectors in `at11_encoder`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

// ── UNSAFE-op diagnostics (2026-06-30) ───────────────────────────────────────
//
// When the lowering can't translate an op it calls `emit_ud2`, which sets a
// sticky sentinel; the block-safety gate (`boot_x86.rs`) then rejects the block
// and injects an undefined-instruction exception. Previously the gate only knew
// the BLOCK's entry PC — not WHICH instruction inside the block forced the UD2.
//
// These statics close that gap. The lowering keeps `CUR_LOWER_PC` updated to the
// guest ARM PC of the instruction currently being lowered (the lifter emits a
// `StampFaultPc(pc)` IR op before every instruction's ops; `IntLower::lower_op`
// copies that PC here). Every `emit_ud2` path then snapshots `CUR_LOWER_PC` into
// `UNSAFE_OP_PC` and records a reason tag in `UNSAFE_OP_REASON`. The gate reads
// these to print the EXACT offending PC + reason, and reads the guest word back
// via the soft-MMU fetch walker. Cheap: three relaxed atomic stores per UD2,
// which only happens on the rare fail-loud path.

/// Guest ARM PC of the instruction whose ops are currently being lowered.
/// Updated by `IntLower::lower_op` on each `StampFaultPc(pc)`. 0 = unknown
/// (e.g. unit tests that lower with pc==0, where no StampFaultPc is emitted).
pub static CUR_LOWER_PC: AtomicU64 = AtomicU64::new(0);

/// Guest ARM PC of the LAST op that called `emit_ud2`. Read by the block-safety
/// gate after it detects a UD2 sentinel.
pub static UNSAFE_OP_PC: AtomicU64 = AtomicU64::new(0);

/// Reason tag for the last `emit_ud2`:
///   0 = UNIMPL  — unimplemented / decode-gap opcode arm
///   1 = SPILL   — a `requires_gpr`/`addr_in` spill-safety guard fired
pub const UNSAFE_REASON_UNIMPL: u8 = 0;
pub const UNSAFE_REASON_SPILL: u8 = 1;

/// Reason tag for the last `emit_ud2` (see `UNSAFE_REASON_*`).
pub static UNSAFE_OP_REASON: AtomicU8 = AtomicU8::new(UNSAFE_REASON_UNIMPL);

/// Set by the lowering before lowering each guest instruction's ops.
#[inline]
pub fn set_cur_lower_pc(pc: u64) {
    CUR_LOWER_PC.store(pc, Ordering::Relaxed);
}

/// Snapshot of `(UNSAFE_OP_PC, UNSAFE_OP_REASON)` for the gate's diagnostics.
pub fn unsafe_op_info() -> (u64, u8) {
    (
        UNSAFE_OP_PC.load(Ordering::Relaxed),
        UNSAFE_OP_REASON.load(Ordering::Relaxed),
    )
}

/// Raw byte buffer that accumulates x86_64 machine code.
///
/// Call the `emit_*` methods in program order, then call [`X86Encoder::finish`]
/// to extract the byte vector.  Patch sites for forward jumps are handled with
/// [`X86Encoder::reserve_rel32`] + [`X86Encoder::patch_rel32`].
pub struct X86Encoder {
    buf: Vec<u8>,
    /// Phase-E: sticky bit set by `emit_ud2`. The block-safety gate previously
    /// scanned the byte buffer for the `0F 0B` pair, which produced a FALSE
    /// POSITIVE whenever an ARM ADD immediate (e.g., `add x20, x20, #0xB0F`)
    /// lowered to `mov r/m64, imm32` and the imm32 little-endian bytes spelled
    /// `0F 0B …`. Real failure: cgroup_disable+0x48 was rejected as UNSAFE
    /// even though no UD2 was emitted; the kernel saw an injected Unknown EC
    /// exception, panicked. Track UD2 emission explicitly here so the gate is
    /// based on actual lowering decisions, not coincidental byte sequences.
    ud2_emitted: bool,
}

impl Default for X86Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl X86Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new(), ud2_emitted: false }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Reset for reuse: clear the byte buffer (KEEPS capacity) and the UD2 flag.
    /// Lets one encoder serve every translation instead of allocating a fresh
    /// `Vec<u8>` per cold block (a bump-heap leak). Pair with [`as_bytes`].
    pub fn reset(&mut self) {
        self.buf.clear();
        self.ud2_emitted = false;
    }

    /// Borrow the emitted bytes WITHOUT consuming the encoder, so the caller can
    /// copy them into the JIT code buffer and then `reset()` for the next block.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Phase-E: did any `emit_ud2` happen during this encoder's lifetime?
    /// `block_bytes_are_safe` consults this through `finish_with_ud2_flag`.
    pub fn had_ud2(&self) -> bool { self.ud2_emitted }

    /// Variant of `finish` that returns the buffer alongside the UD2 flag.
    /// Callers that gate execution on UD2 emission (the production
    /// VMEXIT/NPF resume path) MUST use this, not the byte-scanning
    /// `block_bytes_are_safe`. The two-byte scan stays as a defence-in-depth
    /// check but is no longer load-bearing for false-positive correctness.
    pub fn finish_with_ud2_flag(self) -> (Vec<u8>, bool) {
        (self.buf, self.ud2_emitted)
    }

    /// Current byte offset (used for RIP-relative calculations).
    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    // ── REX prefix helpers ────────────────────────────────────────────────────

    /// Emit REX byte if any of W/R/X/B are set.  `reg`, `idx`, `rm` are the
    /// *full* register numbers (0–15); the high bits form R/X/B.
    fn rex_opt(&mut self, w: bool, reg: u8, idx: u8, rm: u8) {
        let byte = 0x40u8
            | ((w as u8) << 3)
            | (((reg >> 3) & 1) << 2)
            | (((idx >> 3) & 1) << 1)
            | ((rm >> 3) & 1);
        if byte != 0x40 {
            self.buf.push(byte);
        }
    }

    /// Always emit a REX byte (needed when accessing SIL/DIL/SPL/BPL).
    fn rex_always(&mut self, w: bool, reg: u8, idx: u8, rm: u8) {
        let byte = 0x40u8
            | ((w as u8) << 3)
            | (((reg >> 3) & 1) << 2)
            | (((idx >> 3) & 1) << 1)
            | ((rm >> 3) & 1);
        self.buf.push(byte);
    }

    // ── ModR/M + SIB helpers ─────────────────────────────────────────────────

    /// Register-to-register ModRM (mod=11).
    fn modrm_rr(&mut self, reg: u8, rm: u8) {
        self.buf.push(0xC0 | ((reg & 7) << 3) | (rm & 7));
    }

    /// Memory operand [base + disp].  Handles RSP/R12 (need SIB) and
    /// RBP/R13 (need disp8 even when disp==0).
    fn modrm_mem(&mut self, reg: u8, base: u8, disp: i32) {
        let base3 = base & 7;
        let needs_sib = base3 == 4; // RSP / R12

        if disp == 0 && base3 != 5 {
            // mod=00
            self.buf.push(((reg & 7) << 3) | base3);
            if needs_sib {
                self.buf.push(0x24); // SIB: scale=0, index=none(4), base=RSP
            }
        } else if (-128..=127).contains(&disp) {
            // mod=01, disp8
            self.buf.push(0x40 | ((reg & 7) << 3) | base3);
            if needs_sib {
                self.buf.push(0x24);
            }
            self.buf.push(disp as i8 as u8);
        } else {
            // mod=10, disp32
            self.buf.push(0x80 | ((reg & 7) << 3) | base3);
            if needs_sib {
                self.buf.push(0x24);
            }
            self.emit_i32(disp);
        }
    }

    /// Memory operand [base + index*scale + disp].
    /// scale must be 1, 2, 4, or 8.
    fn modrm_sib(&mut self, reg: u8, base: u8, idx: u8, scale: u8, disp: i32) {
        let scale_bits = match scale {
            1 => 0u8,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        };
        let sib = (scale_bits << 6) | ((idx & 7) << 3) | (base & 7);
        let base3 = base & 7;

        if disp == 0 && base3 != 5 {
            self.buf.push(((reg & 7) << 3) | 4); // mod=00, rm=SIB
            self.buf.push(sib);
        } else if (-128..=127).contains(&disp) {
            self.buf.push(0x40 | ((reg & 7) << 3) | 4);
            self.buf.push(sib);
            self.buf.push(disp as i8 as u8);
        } else {
            self.buf.push(0x80 | ((reg & 7) << 3) | 4);
            self.buf.push(sib);
            self.emit_i32(disp);
        }
    }

    // ── Immediate emitters ────────────────────────────────────────────────────

    fn emit_i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }
    fn emit_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn emit_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ── Public instruction emitters ───────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────

    // ── Flow ──────────────────────────────────────────────────────────────────

    pub fn emit_nop(&mut self) {
        self.buf.push(0x90);
    }

    pub fn emit_ret(&mut self) {
        self.buf.push(0xC3);
    }

    pub fn emit_ud2(&mut self) {
        // Default reason: UNIMPL (an unimplemented / decode-gap opcode arm).
        // Spill-safety guards call `emit_ud2_spill` instead, which records
        // SPILL so the gate can tell a missing-opcode block from a
        // register-pressure spill-out.
        self.record_unsafe(UNSAFE_REASON_UNIMPL);
        self.emit_ud2_raw();
    }

    /// `emit_ud2` variant for the `requires_gpr`/`addr_in` spill-safety guards:
    /// records reason=SPILL so the diagnostics distinguish a register-pressure
    /// spill-out from a genuine unimplemented opcode. Same emitted bytes.
    pub fn emit_ud2_spill(&mut self) {
        self.record_unsafe(UNSAFE_REASON_SPILL);
        self.emit_ud2_raw();
    }

    /// Snapshot the lowering's current guest ARM PC + a reason tag into the
    /// UNSAFE-op diagnostics statics (read by the block-safety gate).
    #[inline]
    fn record_unsafe(&self, reason: u8) {
        let pc = CUR_LOWER_PC.load(Ordering::Relaxed);
        UNSAFE_OP_PC.store(pc, Ordering::Relaxed);
        UNSAFE_OP_REASON.store(reason, Ordering::Relaxed);
    }

    fn emit_ud2_raw(&mut self) {
        // Phase-E sentinel: prepend a unique 4-byte NOP (`0F 1F 40 00` =
        // NOP DWORD PTR [RAX+0]) before the UD2 byte pair. The full 6-byte
        // sequence `0F 1F 40 00 0F 0B` is then what the block-safety gate
        // scans for, instead of plain `0F 0B`. Plain 0F 0B appears
        // SPURIOUSLY whenever any ARM immediate happens to spell those
        // bytes — e.g. `add x20, x20, #0xB0F` (cgroup_disable+0x48) lowers
        // to `mov r/m64, imm32` with imm32 = 0x0000_0B0F whose little-endian
        // bytes are `0F 0B 00 00`. That single false positive made the
        // hypervisor inject an "Unknown" undef exception and crashed the
        // kernel after the prior RBIT/UMULH bring-up unblocked pcpu.
        // The semantic NOP is a no-op (instruction decoder ignores it),
        // so prepending it does not change execution; and the 4-byte NOP
        // pattern has effectively zero probability of appearing inside any
        // other emitted instruction. emit_ud2 is rare (the lowering's
        // fail-loud path) so a 4-byte tax per UD2 is acceptable.
        self.buf.extend_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
        self.buf.push(0x0F);
        self.buf.push(0x0B);
        self.ud2_emitted = true;
    }

    /// JMP rel32 (near unconditional).  Returns the offset of the rel32 field
    /// so callers can patch it with [`Self::patch_rel32`].
    pub fn emit_jmp_rel32(&mut self) -> usize {
        self.buf.push(0xE9);
        let patch = self.buf.len();
        self.emit_i32(0);
        patch
    }

    /// JMP r/m64 (indirect through register).
    pub fn emit_jmp_r64(&mut self, reg: u8) {
        self.rex_opt(false, 0, 0, reg);
        self.buf.push(0xFF);
        self.modrm_rr(4, reg); // /4
    }

    /// CALL r/m64 (indirect through register).
    pub fn emit_call_r64(&mut self, reg: u8) {
        self.rex_opt(false, 0, 0, reg);
        self.buf.push(0xFF);
        self.modrm_rr(2, reg); // /2
    }

    /// Conditional jump (Jcc) rel32.  `cc` is the low nibble of the 0x0F 0x8x
    /// opcode (0x4=JE, 0x5=JNE, 0x2=JB, 0x6=JBE, 0x7=JNBE, 0xC=JL,
    /// 0xD=JGE, 0xE=JLE, 0xF=JG, 0x2=JC, 0x3=JAE).
    pub fn emit_jcc_rel32(&mut self, cc: u8) -> usize {
        self.buf.push(0x0F);
        self.buf.push(0x80 | (cc & 0xF));
        let patch = self.buf.len();
        self.emit_i32(0);
        patch
    }

    /// Patch a previously-emitted rel32 field so that the jump targets
    /// `target_pos`.  `patch` is the byte offset of the 4-byte field.
    pub fn patch_rel32(&mut self, patch: usize, target_pos: usize) {
        let rel = (target_pos as i64) - (patch as i64 + 4);
        let rel32 = rel as i32;
        self.buf[patch..patch + 4].copy_from_slice(&rel32.to_le_bytes());
    }

    /// Reserve a rel32 slot and return its patch offset.  Same as
    /// [`Self::emit_jmp_rel32`] but without the leading E9 (caller emits
    /// the opcode bytes before calling this).
    pub fn reserve_rel32(&mut self) -> usize {
        let patch = self.buf.len();
        self.emit_i32(0);
        patch
    }

    // ── MOV ───────────────────────────────────────────────────────────────────

    /// MOV r64, r64
    pub fn emit_mov_rr64(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, src, 0, dst);
        self.buf.push(0x89); // MOV r/m64, r64
        self.modrm_rr(src, dst);
    }

    /// MOV r32, r32 (upper 32 bits of dst zeroed by hardware).
    pub fn emit_mov_rr32(&mut self, dst: u8, src: u8) {
        self.rex_opt(false, src, 0, dst);
        self.buf.push(0x89);
        self.modrm_rr(src, dst);
    }

    /// MOV r64, imm32 (sign-extended to 64 bits).  More compact than imm64
    /// when value fits.
    pub fn emit_mov_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xC7);
        self.modrm_rr(0, dst);
        self.emit_i32(imm);
    }

    /// MOV r64, imm64.
    pub fn emit_mov_r64_imm64(&mut self, dst: u8, imm: i64) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xB8 | (dst & 7));
        self.emit_i64(imm);
    }

    /// MOV r32, imm32 (zero-extends to 64-bit).
    pub fn emit_mov_r32_imm32(&mut self, dst: u8, imm: u32) {
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0xB8 | (dst & 7));
        self.emit_i32(imm as i32);
    }

    /// SUB qword [base + disp], imm8 (sign-extended). Sets CF on borrow.
    pub fn emit_sub_mem64_imm8(&mut self, base: u8, disp: i32, imm: i8) {
        self.rex_opt(true, 0, 0, base);
        self.buf.push(0x83);
        self.modrm_mem(5, base, disp); // /5 = SUB
        self.buf.push(imm as u8);
    }

    /// MOV r64, [base + disp].
    pub fn emit_mov_r64_mem(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x8B);
        self.modrm_mem(dst, base, disp);
    }

    /// MOV [base + disp], r64.
    pub fn emit_mov_mem_r64(&mut self, base: u8, disp: i32, src: u8) {
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x89);
        self.modrm_mem(src, base, disp);
    }

    /// MOV r8, [base + disp]  (zero-extended to 64-bit via MOVZX).
    pub fn emit_movzx_r64_mem8(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xB6); // MOVZX r64, r/m8
        self.modrm_mem(dst, base, disp);
    }

    /// MOV r16, [base + disp]  (zero-extended to 64-bit via MOVZX).
    pub fn emit_movzx_r64_mem16(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xB7); // MOVZX r64, r/m16
        self.modrm_mem(dst, base, disp);
    }

    /// MOV r32, [base + disp]  (zero-extended to 64-bit, natural).
    pub fn emit_mov_r32_mem(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(false, dst, 0, base);
        self.buf.push(0x8B);
        self.modrm_mem(dst, base, disp);
    }

    /// MOVSX r64, [base + disp] (8-bit sign-extended).
    pub fn emit_movsx_r64_mem8(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xBE);
        self.modrm_mem(dst, base, disp);
    }

    /// MOVSX r64, [base + disp] (16-bit sign-extended).
    pub fn emit_movsx_r64_mem16(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xBF);
        self.modrm_mem(dst, base, disp);
    }

    /// MOVSXD r64, [base + disp] (32-bit sign-extended).
    pub fn emit_movsxd_r64_mem32(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x63);
        self.modrm_mem(dst, base, disp);
    }

    /// MOV [base + disp], r8.
    pub fn emit_mov_mem8_r64(&mut self, base: u8, disp: i32, src: u8) {
        // An 8-bit store from SPL/BPL/SIL/DIL (src 4..=7) REQUIRES a REX prefix
        // to select the LOW byte. Without REX, ModRM reg 4..7 encodes the legacy
        // high bytes AH/CH/DH/BH — silently storing the wrong byte of the WRONG
        // register (e.g. STRB of RSI would write DH). `rex_opt` omits REX when no
        // W/R/X/B bit is set, so force one for src >= 4 (src >= 8 already gets a
        // REX from the R bit, so this also covers R8B..R15B).
        if src >= 4 {
            self.rex_always(false, src, 0, base);
        } else {
            self.rex_opt(false, src, 0, base);
        }
        self.buf.push(0x88); // MOV r/m8, r8
        self.modrm_mem(src, base, disp);
    }

    /// MOV [base + disp], r16.
    pub fn emit_mov_mem16_r64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0x66); // operand-size prefix
        self.rex_opt(false, src, 0, base);
        self.buf.push(0x89);
        self.modrm_mem(src, base, disp);
    }

    /// MOV [base + disp], r32.
    pub fn emit_mov_mem32_r64(&mut self, base: u8, disp: i32, src: u8) {
        self.rex_opt(false, src, 0, base);
        self.buf.push(0x89);
        self.modrm_mem(src, base, disp);
    }

    // ── Integer ALU (register–register, 64-bit) ───────────────────────────────

    fn emit_alu64_rr(&mut self, op: u8, dst: u8, src: u8) {
        self.rex_opt(true, src, 0, dst);
        self.buf.push(op);
        self.modrm_rr(src, dst);
    }

    /// ADD r64, r64.
    pub fn emit_add_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x01, dst, src);
    }
    /// SUB r64, r64.
    pub fn emit_sub_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x29, dst, src);
    }
    /// AND r64, r64.
    pub fn emit_and_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x21, dst, src);
    }
    /// OR r64, r64.
    pub fn emit_or_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x09, dst, src);
    }
    /// XOR r64, r64.
    pub fn emit_xor_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x31, dst, src);
    }
    /// CMP r64, r64 (sets flags, no dst written).
    pub fn emit_cmp_rr64(&mut self, a: u8, b: u8) {
        self.emit_alu64_rr(0x39, a, b); // CMP r/m64, r64
    }
    /// ADC r64, r64 — dst = dst + src + CF (M4b: ARM ADCS with carry-in).
    pub fn emit_adc_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x11, dst, src); // ADC r/m64, r64
    }
    /// SBB r64, r64 — dst = dst - src - CF, where CF is the x86 BORROW.
    /// M4b: ARM SBCS subtracts the ARM borrow `!C`, so the caller must seed
    /// CF = !ARM_C (BT then CMC) before this; see emit_cmc.
    pub fn emit_sbb_rr64(&mut self, dst: u8, src: u8) {
        self.emit_alu64_rr(0x19, dst, src); // SBB r/m64, r64
    }
    /// BT [base+disp], imm8 — copy bit `bit` of the memory operand into CF.
    /// M4b: seed x86 CF from the stored ARM NZCV C bit (bit 29) before ADC/SBB.
    /// Encoding: REX.W 0F BA /4 ib.
    pub fn emit_bt_mem(&mut self, base: u8, disp: i32, bit: u8) {
        self.rex_opt(true, 0, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xBA);
        self.modrm_mem(4, base, disp); // /4 = BT
        self.buf.push(bit);
    }
    /// CMC — complement carry flag (CF = !CF). Single byte 0xF5; touches ONLY
    /// CF (preserves OF/SF/ZF). M4b SBCS: after BT seeds CF = ARM C, CMC turns
    /// it into the x86 borrow (!C) that SBB consumes.
    pub fn emit_cmc(&mut self) {
        self.buf.push(0xF5);
    }
    /// TEST r64, r64.
    pub fn emit_test_rr64(&mut self, a: u8, b: u8) {
        self.emit_alu64_rr(0x85, a, b); // TEST r/m64, r64
    }

    // ── 32-bit ALU (register–register) — W-form flag ops ──────────────────────
    // No REX.W: x86 computes ZF/SF/CF/OF over the LOW 32 bits and zero-extends
    // the r/m32 result into the 64-bit destination. Used for ARM W-form
    // flag-setting ops so NZCV (N = bit 31, Z/C/V over 32 bits) is derived from
    // the 32-bit result — a 64-bit op would take N from bit 63 (silent miscompile
    // of every W-form compare; the M4b adversarial-review must-fix).

    fn emit_alu32_rr(&mut self, op: u8, dst: u8, src: u8) {
        self.rex_opt(false, src, 0, dst);
        self.buf.push(op);
        self.modrm_rr(src, dst);
    }
    /// ADD r/m32, r32.
    pub fn emit_add_rr32(&mut self, dst: u8, src: u8) { self.emit_alu32_rr(0x01, dst, src); }
    /// SUB r/m32, r32.
    pub fn emit_sub_rr32(&mut self, dst: u8, src: u8) { self.emit_alu32_rr(0x29, dst, src); }
    /// AND r/m32, r32.
    pub fn emit_and_rr32(&mut self, dst: u8, src: u8) { self.emit_alu32_rr(0x21, dst, src); }
    /// CMP r/m32, r32 (sets flags, no dst written).
    pub fn emit_cmp_rr32(&mut self, a: u8, b: u8) { self.emit_alu32_rr(0x39, a, b); }
    /// TEST r/m32, r32.
    pub fn emit_test_rr32(&mut self, a: u8, b: u8) { self.emit_alu32_rr(0x85, a, b); }
    /// ADC r/m32, r32 (carry-in from CF).
    pub fn emit_adc_rr32(&mut self, dst: u8, src: u8) { self.emit_alu32_rr(0x11, dst, src); }
    /// SBB r/m32, r32 (CF = borrow).
    pub fn emit_sbb_rr32(&mut self, dst: u8, src: u8) { self.emit_alu32_rr(0x19, dst, src); }

    // ── Integer ALU (register–immediate, 64-bit) ──────────────────────────────

    /// ADD r64, imm32 (or imm8 if fits).
    pub fn emit_add_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(0, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(0, dst);
            self.emit_i32(imm);
        }
    }

    /// SUB r64, imm32 (or imm8 if fits).
    pub fn emit_sub_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(5, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(5, dst);
            self.emit_i32(imm);
        }
    }

    /// AND r64, imm32.
    pub fn emit_and_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(4, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(4, dst);
            self.emit_i32(imm);
        }
    }

    /// OR r64, imm32.
    pub fn emit_or_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(1, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(1, dst);
            self.emit_i32(imm);
        }
    }

    /// XOR r64, imm32.
    pub fn emit_xor_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(6, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(6, dst);
            self.emit_i32(imm);
        }
    }

    /// CMP r64, imm32.
    pub fn emit_cmp_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.rex_always(true, 0, 0, dst);
        if (-128..=127).contains(&imm) {
            self.buf.push(0x83);
            self.modrm_rr(7, dst);
            self.emit_i8(imm as i8);
        } else {
            self.buf.push(0x81);
            self.modrm_rr(7, dst);
            self.emit_i32(imm);
        }
    }

    // ── Unary integer ─────────────────────────────────────────────────────────

    /// NEG r64.
    pub fn emit_neg_r64(&mut self, reg: u8) {
        self.rex_always(true, 0, 0, reg);
        self.buf.push(0xF7);
        self.modrm_rr(3, reg);
    }

    /// NOT r64.
    pub fn emit_not_r64(&mut self, reg: u8) {
        self.rex_always(true, 0, 0, reg);
        self.buf.push(0xF7);
        self.modrm_rr(2, reg);
    }

    // ── Shifts ────────────────────────────────────────────────────────────────

    /// SHL r64, CL.
    pub fn emit_shl_r64_cl(&mut self, dst: u8) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xD3);
        self.modrm_rr(4, dst);
    }

    /// SHR r64, CL (logical).
    pub fn emit_shr_r64_cl(&mut self, dst: u8) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xD3);
        self.modrm_rr(5, dst);
    }

    /// SAR r64, CL (arithmetic).
    pub fn emit_sar_r64_cl(&mut self, dst: u8) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xD3);
        self.modrm_rr(7, dst);
    }

    /// ROR r64, CL.
    pub fn emit_ror_r64_cl(&mut self, dst: u8) {
        self.rex_always(true, 0, 0, dst);
        self.buf.push(0xD3);
        self.modrm_rr(1, dst);
    }

    /// SHL r64, imm8.
    pub fn emit_shl_r64_imm8(&mut self, dst: u8, imm: u8) {
        self.rex_always(true, 0, 0, dst);
        if imm == 1 {
            self.buf.push(0xD1);
            self.modrm_rr(4, dst);
        } else {
            self.buf.push(0xC1);
            self.modrm_rr(4, dst);
            self.buf.push(imm);
        }
    }

    /// SHR r64, imm8.
    pub fn emit_shr_r64_imm8(&mut self, dst: u8, imm: u8) {
        self.rex_always(true, 0, 0, dst);
        if imm == 1 {
            self.buf.push(0xD1);
            self.modrm_rr(5, dst);
        } else {
            self.buf.push(0xC1);
            self.modrm_rr(5, dst);
            self.buf.push(imm);
        }
    }

    /// SAR r64, imm8.
    pub fn emit_sar_r64_imm8(&mut self, dst: u8, imm: u8) {
        self.rex_always(true, 0, 0, dst);
        if imm == 1 {
            self.buf.push(0xD1);
            self.modrm_rr(7, dst);
        } else {
            self.buf.push(0xC1);
            self.modrm_rr(7, dst);
            self.buf.push(imm);
        }
    }

    // ── Multiply / Divide ─────────────────────────────────────────────────────

    /// IMUL r64, r/m64 (two-operand; dst *= src, low 64 bits).
    pub fn emit_imul_rr64(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xAF);
        self.modrm_rr(dst, src);
    }

    /// MUL r/m64 — unsigned multiply: RDX:RAX = RAX * reg.
    pub fn emit_mul_r64(&mut self, src: u8) {
        self.rex_opt(true, 0, 0, src);
        self.buf.push(0xF7);
        self.modrm_rr(4, src);
    }

    /// IMUL r/m64 — signed multiply: RDX:RAX = RAX * reg.
    pub fn emit_imul1_r64(&mut self, src: u8) {
        self.rex_opt(true, 0, 0, src);
        self.buf.push(0xF7);
        self.modrm_rr(5, src);
    }

    /// DIV r/m64 — unsigned divide: quotient→RAX, remainder→RDX.
    pub fn emit_div_r64(&mut self, src: u8) {
        self.rex_opt(true, 0, 0, src);
        self.buf.push(0xF7);
        self.modrm_rr(6, src);
    }

    /// IDIV r/m64 — signed divide.
    pub fn emit_idiv_r64(&mut self, src: u8) {
        self.rex_opt(true, 0, 0, src);
        self.buf.push(0xF7);
        self.modrm_rr(7, src);
    }

    /// CQO — sign-extend RAX into RDX:RAX (needed before IDIV).
    pub fn emit_cqo(&mut self) {
        self.buf.push(0x48); // REX.W
        self.buf.push(0x99);
    }

    /// XOR r/m64, r64 — commonly used to zero-extend or zero a register.
    /// Note: use emit_xor_rr64 for two different regs; this is a specialisation
    /// that also sets flags.
    pub fn emit_xor_zero_r32(&mut self, reg: u8) {
        // XOR r32, r32 is shortest zero idiom; upper 32 bits zeroed by hardware.
        self.rex_opt(false, reg, 0, reg);
        self.buf.push(0x31);
        self.modrm_rr(reg, reg);
    }

    // ── Bit manipulation ──────────────────────────────────────────────────────

    /// BSWAP r64.
    pub fn emit_bswap_r64(&mut self, reg: u8) {
        self.rex_always(true, 0, 0, reg);
        self.buf.push(0x0F);
        self.buf.push(0xC8 | (reg & 7));
    }

    /// BSWAP r32 — byte-reverse the low 32 bits and zero-extend to 64. This is
    /// the correct lowering for ARM64 `REV Wd, Wn` (4-byte reverse): BSWAP r64
    /// would reverse all 8 bytes and shift the original low 32 into the high
    /// half, leaving zero in the low — which is exactly the kernel-DTB-magic
    /// bug we found at Phase B step 3b.
    pub fn emit_bswap_r32(&mut self, reg: u8) {
        // REX.B for R8..R15 (no REX.W; R32 operand size is the default).
        if reg >= 8 {
            self.buf.push(0x41);
        }
        self.buf.push(0x0F);
        self.buf.push(0xC8 | (reg & 7));
    }

    /// LZCNT r64, r/m64. B30: REQUIRES the host ABM/LZCNT feature
    /// (CPUID.80000001h:ECX[5]). On a non-ABM CPU the F3 prefix is IGNORED and
    /// this decodes as BSR (highest-set-bit index, result UNDEFINED for input 0)
    /// — wrong semantics for a leading-zero count, so Clz/Cls would return
    /// garbage. The only supported x86 hosts (Meteor Lake-H, Raphael) both
    /// implement ABM, so this is safe; a non-ABM host is unsupported.
    /// `dbt::aether_dbt_host_supports_isa()` is the runtime probe the hypervisor
    /// can call to refuse such a host before any block is dispatched.
    pub fn emit_lzcnt_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3); // mandatory F3 prefix
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xBD);
        self.modrm_rr(dst, src);
    }

    /// BSR r64, r/m64 — bit scan reverse (index of highest set bit).
    pub fn emit_bsr_r64(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xBD);
        self.modrm_rr(dst, src);
    }

    /// BSF r64, r/m64 — bit scan forward.
    pub fn emit_bsf_r64(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xBC);
        self.modrm_rr(dst, src);
    }

    // ── Sign / zero extension ─────────────────────────────────────────────────

    /// MOVSX r64, r32 (sign-extend 32→64).
    pub fn emit_movsxd_r64_r32(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x63); // MOVSXD
        self.modrm_rr(dst, src);
    }

    /// MOVSX r64, r8.
    pub fn emit_movsx_r64_r8(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xBE);
        self.modrm_rr(dst, src);
    }

    /// MOVSX r64, r16.
    pub fn emit_movsx_r64_r16(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xBF);
        self.modrm_rr(dst, src);
    }

    /// MOVZX r64, r8.
    pub fn emit_movzx_r64_r8(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xB6);
        self.modrm_rr(dst, src);
    }

    /// MOVZX r64, r16.
    pub fn emit_movzx_r64_r16(&mut self, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xB7);
        self.modrm_rr(dst, src);
    }

    // ── Conditional set ───────────────────────────────────────────────────────

    /// SETcc r8.  `cc` same as for Jcc (low nibble of 0x9X opcode).
    pub fn emit_setcc_r8(&mut self, cc: u8, dst: u8) {
        // SETcc into SPL/BPL/SIL/DIL (dst 4..=7) needs a REX prefix to select the
        // low byte (else ModRM reg 4..7 = AH/CH/DH/BH — the same high-byte hazard
        // as the 8-bit store). build_nzcv only uses dst 0..3 today, but
        // lower_atomic assigns a SETcc target from the allocatable set (which
        // includes RBP/RSI/RDI), so force REX for dst >= 4 (sibling of the STRB fix).
        if dst >= 4 {
            self.rex_always(false, 0, 0, dst);
        } else {
            self.rex_opt(false, 0, 0, dst);
        }
        self.buf.push(0x0F);
        self.buf.push(0x90 | (cc & 0xF));
        self.modrm_rr(0, dst);
    }

    /// CMOV r64, r/m64.  `cc` same as Jcc nibble.
    pub fn emit_cmov_rr64(&mut self, cc: u8, dst: u8, src: u8) {
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x40 | (cc & 0xF));
        self.modrm_rr(dst, src);
    }

    // ── Stack ─────────────────────────────────────────────────────────────────

    /// PUSH r64.
    pub fn emit_push_r64(&mut self, reg: u8) {
        self.rex_opt(false, 0, 0, reg);
        self.buf.push(0x50 | (reg & 7));
    }

    /// POP r64.
    pub fn emit_pop_r64(&mut self, reg: u8) {
        self.rex_opt(false, 0, 0, reg);
        self.buf.push(0x58 | (reg & 7));
    }

    // ── Barriers / serializing ────────────────────────────────────────────────

    /// MFENCE — full store-fence, used for ARM DMB SY / DSB.
    pub fn emit_mfence(&mut self) {
        self.buf.push(0x0F);
        self.buf.push(0xAE);
        self.buf.push(0xF0);
    }

    /// LFENCE — load-fence.
    pub fn emit_lfence(&mut self) {
        self.buf.push(0x0F);
        self.buf.push(0xAE);
        self.buf.push(0xE8);
    }

    /// SFENCE — store-fence.
    pub fn emit_sfence(&mut self) {
        self.buf.push(0x0F);
        self.buf.push(0xAE);
        self.buf.push(0xF8);
    }

    /// CPUID — serialising instruction used for ISB lowering.
    /// Caller must zero EAX first (emit_xor_zero_r32(0)).
    pub fn emit_cpuid(&mut self) {
        self.buf.push(0x0F);
        self.buf.push(0xA2);
    }

    /// Full ISB sequence: XOR EAX,EAX + CPUID, bracketed by a save/restore of
    /// the allocatable GPRs CPUID clobbers.
    ///
    /// CPUID writes EAX/EBX/ECX/EDX (zero-extending into the full 64-bit RBX/
    /// RDX). RAX/RCX are reserved scratch (safe to clobber), but RDX(2) and
    /// RBX(3) are ALLOCATABLE value registers — in fact the first two the
    /// linear-scan allocator hands out — so any guest value live across an ISB/
    /// SB would be silently corrupted without this guard. Every FFI-call helper
    /// already preserves the volatile set for the same reason; the barrier path
    /// must too. push/pop are in-block and balanced (no CALL between them), so
    /// they impose no cross-call stack-alignment requirement and leave RSP
    /// unchanged. (Latent under the current per-instruction lift — no IR value
    /// spans a barrier today — but a real ABI-correctness fix, made now so a
    /// future SSA-promotion / opt change can't turn it into silent corruption.)
    pub fn emit_isb_sequence(&mut self) {
        self.emit_push_r64(3);     // push rbx
        self.emit_push_r64(2);     // push rdx
        self.emit_xor_zero_r32(0); // XOR EAX, EAX
        self.emit_cpuid();
        self.emit_pop_r64(2);      // pop rdx
        self.emit_pop_r64(3);      // pop rbx
    }

    // ── Atomics ───────────────────────────────────────────────────────────────

    /// LOCK CMPXCHG [base + disp], src.
    /// On entry: expected value in RAX (convention).
    /// On success: ZF=1; on failure: ZF=0 and [mem] loaded into RAX.
    pub fn emit_lock_cmpxchg_mem64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF0); // LOCK prefix
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xB1); // CMPXCHG r/m64, r64
        self.modrm_mem(src, base, disp);
    }

    /// XCHG r64, [base + disp] — implicit LOCK; used for SeqCst stores.
    pub fn emit_xchg_r64_mem64(&mut self, reg: u8, base: u8, disp: i32) {
        self.rex_opt(true, reg, 0, base);
        self.buf.push(0x87); // XCHG r64, r/m64
        self.modrm_mem(reg, base, disp);
    }

    /// LOCK XADD [base + disp], src — atomic fetch-add; result in src.
    pub fn emit_lock_xadd_mem64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF0);
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0xC1); // XADD r/m64, r64
        self.modrm_mem(src, base, disp);
    }

    /// LOCK AND [base + disp], src.
    pub fn emit_lock_and_mem64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF0);
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x21); // AND r/m64, r64
        self.modrm_mem(src, base, disp);
    }

    /// LOCK OR [base + disp], src.
    pub fn emit_lock_or_mem64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF0);
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x09); // OR r/m64, r64
        self.modrm_mem(src, base, disp);
    }

    /// LOCK XOR [base + disp], src.
    pub fn emit_lock_xor_mem64(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF0);
        self.rex_opt(true, src, 0, base);
        self.buf.push(0x31); // XOR r/m64, r64
        self.modrm_mem(src, base, disp);
    }

    // ── SSE2 / SSE4 XMM instructions ─────────────────────────────────────────

    /// MOVDQA xmm_dst, xmm_src.
    pub fn emit_movdqa_rr(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x6F); // MOVDQA xmm, xmm/m128
        self.modrm_rr(dst, src);
    }

    /// MOVDQA xmm, [base + disp].
    pub fn emit_movdqa_load(&mut self, dst: u8, base: u8, disp: i32) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0x6F);
        self.modrm_mem(dst, base, disp);
    }

    /// MOVDQA [base + disp], xmm.
    pub fn emit_movdqa_store(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, src, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0x7F); // MOVDQA xmm/m128, xmm
        self.modrm_mem(src, base, disp);
    }

    /// MOVDQU xmm, [base + disp] (unaligned).
    pub fn emit_movdqu_load(&mut self, dst: u8, base: u8, disp: i32) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0x6F);
        self.modrm_mem(dst, base, disp);
    }

    /// MOVDQU [base + disp], xmm (unaligned).
    pub fn emit_movdqu_store(&mut self, base: u8, disp: i32, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, src, 0, base);
        self.buf.push(0x0F);
        self.buf.push(0x7F);
        self.modrm_mem(src, base, disp);
    }

    fn emit_sse2_op(&mut self, prefix: u8, op: u8, dst: u8, src: u8) {
        self.buf.push(prefix);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(op);
        self.modrm_rr(dst, src);
    }

    // Integer SIMD
    pub fn emit_paddb(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xFC, dst, src); }
    pub fn emit_paddw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xFD, dst, src); }
    pub fn emit_paddd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xFE, dst, src); }
    pub fn emit_paddq(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xD4, dst, src); }
    pub fn emit_psubb(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xF8, dst, src); }
    pub fn emit_psubw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xF9, dst, src); }
    pub fn emit_psubd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xFA, dst, src); }
    pub fn emit_psubq(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xFB, dst, src); }
    pub fn emit_pmullw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xD5, dst, src); }
    pub fn emit_pand(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xDB, dst, src); }
    pub fn emit_pandn(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xDF, dst, src); }
    pub fn emit_por(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xEB, dst, src); }
    pub fn emit_pxor(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xEF, dst, src); }
    pub fn emit_pcmpeqb(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x74, dst, src); }
    pub fn emit_pcmpeqw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x75, dst, src); }
    pub fn emit_pcmpeqd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x76, dst, src); }
    pub fn emit_pcmpgtb(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x64, dst, src); }
    pub fn emit_pcmpgtw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x65, dst, src); }
    pub fn emit_pcmpgtd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x66, dst, src); }
    pub fn emit_pminsb(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x38, dst, src); }
    pub fn emit_pmaxsb(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3C, dst, src); }
    pub fn emit_pminsw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xEA, dst, src); }
    pub fn emit_pmaxsw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xEE, dst, src); }
    pub fn emit_pminsd(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x39, dst, src); }
    pub fn emit_pmaxsd(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3D, dst, src); }
    pub fn emit_pminub(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xDA, dst, src); }
    pub fn emit_pmaxub(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0xDE, dst, src); }
    pub fn emit_pminuw(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3A, dst, src); }
    pub fn emit_pmaxuw(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3E, dst, src); }
    pub fn emit_pminud(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3B, dst, src); }
    pub fn emit_pmaxud(&mut self, dst: u8, src: u8) { self.emit_sse4_op(0x38, 0x3F, dst, src); }

    /// PSLLW xmm, imm8.
    pub fn emit_psllw_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x71);
        self.modrm_rr(6, dst);
        self.buf.push(imm);
    }
    /// PSLLD xmm, imm8.
    pub fn emit_pslld_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x72);
        self.modrm_rr(6, dst);
        self.buf.push(imm);
    }
    /// PSLLQ xmm, imm8.
    pub fn emit_psllq_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x73);
        self.modrm_rr(6, dst);
        self.buf.push(imm);
    }
    /// PSRLW xmm, imm8 (logical right).
    pub fn emit_psrlw_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x71);
        self.modrm_rr(2, dst);
        self.buf.push(imm);
    }
    /// PSRLD xmm, imm8.
    pub fn emit_psrld_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x72);
        self.modrm_rr(2, dst);
        self.buf.push(imm);
    }
    /// PSRLQ xmm, imm8.
    pub fn emit_psrlq_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x73);
        self.modrm_rr(2, dst);
        self.buf.push(imm);
    }
    /// PSRLDQ xmm, imm8 — byte-granular logical right shift of the whole 128-bit
    /// register (0F 73 /3). Used to bring the high 64 bits into the low 64.
    pub fn emit_psrldq_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x73);
        self.modrm_rr(3, dst);
        self.buf.push(imm);
    }
    /// PSRAW xmm, imm8.
    pub fn emit_psraw_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x71);
        self.modrm_rr(4, dst);
        self.buf.push(imm);
    }
    /// PSRAD xmm, imm8.
    pub fn emit_psrad_imm(&mut self, dst: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, 0, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x72);
        self.modrm_rr(4, dst);
        self.buf.push(imm);
    }

    // Float SIMD (no prefix = f32×4; 66 prefix = f64×2)
    pub fn emit_addps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x58, dst, src); }
    pub fn emit_subps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x5C, dst, src); }
    pub fn emit_mulps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x59, dst, src); }
    pub fn emit_divps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x5E, dst, src); }
    pub fn emit_sqrtps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x51, dst, src); }
    pub fn emit_addpd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x58, dst, src); }
    pub fn emit_subpd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x5C, dst, src); }
    pub fn emit_mulpd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x59, dst, src); }
    pub fn emit_divpd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x5E, dst, src); }
    pub fn emit_addss(&mut self, dst: u8, src: u8) { self.emit_sse_f3_op(0x58, dst, src); }
    pub fn emit_subss(&mut self, dst: u8, src: u8) { self.emit_sse_f3_op(0x5C, dst, src); }
    pub fn emit_mulss(&mut self, dst: u8, src: u8) { self.emit_sse_f3_op(0x59, dst, src); }
    pub fn emit_divss(&mut self, dst: u8, src: u8) { self.emit_sse_f3_op(0x5E, dst, src); }
    pub fn emit_sqrtss(&mut self, dst: u8, src: u8) { self.emit_sse_f3_op(0x51, dst, src); }
    pub fn emit_addsd(&mut self, dst: u8, src: u8) { self.emit_sse_f2_op(0x58, dst, src); }
    pub fn emit_subsd(&mut self, dst: u8, src: u8) { self.emit_sse_f2_op(0x5C, dst, src); }
    pub fn emit_mulsd(&mut self, dst: u8, src: u8) { self.emit_sse_f2_op(0x59, dst, src); }
    pub fn emit_divsd(&mut self, dst: u8, src: u8) { self.emit_sse_f2_op(0x5E, dst, src); }
    pub fn emit_sqrtsd(&mut self, dst: u8, src: u8) { self.emit_sse_f2_op(0x51, dst, src); }

    fn emit_sse_nopfx_op(&mut self, op: u8, dst: u8, src: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(op);
        self.modrm_rr(dst, src);
    }
    fn emit_sse_f3_op(&mut self, op: u8, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(op);
        self.modrm_rr(dst, src);
    }
    fn emit_sse_f2_op(&mut self, op: u8, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(op);
        self.modrm_rr(dst, src);
    }

    // SSE4 ops: 66 0F 38 xx /r
    fn emit_sse4_op(&mut self, esc2: u8, op: u8, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(esc2);
        self.buf.push(op);
        self.modrm_rr(dst, src);
    }

    /// PMULLD xmm, xmm (SSE4.1 — 32-bit lane multiply, low 32 bits).
    pub fn emit_pmulld(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0x40, dst, src);
    }
    /// PMULDQ xmm, xmm (SSE4.1): signed 32x32->64 on dword lanes 0 and 2.
    pub fn emit_pmuldq(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0x28, dst, src);
    }
    /// PMULUDQ xmm, xmm (SSE2): unsigned 32x32->64 on dword lanes 0 and 2.
    pub fn emit_pmuludq(&mut self, dst: u8, src: u8) {
        self.emit_sse2_op(0x66, 0xF4, dst, src);
    }

    /// PSHUFB xmm, xmm (SSSE3 — byte shuffle).
    pub fn emit_pshufb(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0x00, dst, src);
    }

    /// PSHUFD xmm, xmm, imm8.
    pub fn emit_pshufd(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x70);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    /// PUNPCKLBW xmm, xmm.
    pub fn emit_punpcklbw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x60, dst, src); }
    /// PUNPCKHBW xmm, xmm.
    pub fn emit_punpckhbw(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x68, dst, src); }
    /// PUNPCKLWD xmm, xmm.
    pub fn emit_punpcklwd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x61, dst, src); }
    /// PUNPCKHWD xmm, xmm.
    pub fn emit_punpckhwd(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x69, dst, src); }
    /// PUNPCKLDQ xmm, xmm.
    pub fn emit_punpckldq(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x62, dst, src); }
    /// PUNPCKHDQ xmm, xmm.
    pub fn emit_punpckhdq(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x6A, dst, src); }
    /// PUNPCKLQDQ xmm, xmm.
    pub fn emit_punpcklqdq(&mut self, dst: u8, src: u8) { self.emit_sse2_op(0x66, 0x6C, dst, src); }

    /// MOVQ xmm, r/m64.
    pub fn emit_movq_xmm_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x6E); // MOVD/MOVQ xmm, r/m64
        self.modrm_rr(dst, src);
    }

    /// MOVQ r/m64, xmm.
    pub fn emit_movq_r64_xmm(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(true, src, 0, dst);
        self.buf.push(0x0F);
        self.buf.push(0x7E); // MOVD/MOVQ r/m64, xmm
        self.modrm_rr(src, dst);
    }

    /// PEXTRB r32, xmm, imm8 (SSE4.1).
    pub fn emit_pextrb(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, src, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x14);
        self.modrm_rr(src, dst);
        self.buf.push(lane);
    }

    /// PEXTRD r32, xmm, imm8 (SSE4.1).
    pub fn emit_pextrd(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, src, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x16);
        self.modrm_rr(src, dst);
        self.buf.push(lane);
    }

    /// PEXTRQ r64, xmm, imm8 (SSE4.1).
    pub fn emit_pextrq(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(true, src, 0, dst);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x16);
        self.modrm_rr(src, dst);
        self.buf.push(lane);
    }

    /// PINSRB xmm, r32, imm8 (SSE4.1).
    pub fn emit_pinsrb(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x20);
        self.modrm_rr(dst, src);
        self.buf.push(lane);
    }

    /// PALIGNR xmm, xmm, imm8 (SSSE3) — `dst = (CONCAT(dst, src) >> imm*8)[127:0]`
    /// (dst is the HIGH operand). Used to lower ARM `EXT Vd,Vn,Vm,#imm`
    /// (`CONCAT(Vm,Vn) >> imm*8`): load Vm→dst, Vn→src, then `palignr dst,src,imm`.
    pub fn emit_palignr(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x0F);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    /// PINSRD xmm, r32, imm8 (SSE4.1).
    pub fn emit_pinsrd(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x22);
        self.modrm_rr(dst, src);
        self.buf.push(lane);
    }

    /// PINSRQ xmm, r64, imm8 (SSE4.1).
    pub fn emit_pinsrq(&mut self, dst: u8, src: u8, lane: u8) {
        self.buf.push(0x66);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x22);
        self.modrm_rr(dst, src);
        self.buf.push(lane);
    }

    /// VPBLENDW xmm, xmm, imm8 (SSE4.1, non-VEX).
    pub fn emit_pblendw(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x0E);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    /// AES-NI: AESENC xmm, xmm.
    pub fn emit_aesenc(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0xDC, dst, src);
    }

    /// AES-NI: AESENCLAST xmm, xmm.
    pub fn emit_aesenclast(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0xDD, dst, src);
    }

    /// AES-NI: AESDEC xmm, xmm.
    pub fn emit_aesdec(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0xDE, dst, src);
    }

    /// AES-NI: AESDECLAST xmm, xmm.
    pub fn emit_aesdeclast(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0xDF, dst, src);
    }

    /// AES-NI: AESIMC xmm, xmm.
    pub fn emit_aesimc(&mut self, dst: u8, src: u8) {
        self.emit_sse4_op(0x38, 0xDB, dst, src);
    }

    /// PCLMULQDQ xmm, xmm, imm8 (PCLMUL — used for PMULL lowering).
    pub fn emit_pclmulqdq(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x3A); self.buf.push(0x44);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    /// CRC32 r64, r/m8.
    pub fn emit_crc32_r64_r8(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x38); self.buf.push(0xF0);
        self.modrm_rr(dst, src);
    }

    /// CRC32 r32, r/m8 (CRC32CB data size). The 32-bit-destination form (no
    /// REX.W): the result is the 32-bit CRC zero-extended into the full r64, and
    /// ONLY the source's low byte participates — so it reads no garbage high bits
    /// from a 64-bit data register. rex_opt(false,…) still emits REX.R/B for r8-r15.
    pub fn emit_crc32_r32_r8(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x38); self.buf.push(0xF0);
        self.modrm_rr(dst, src);
    }

    /// CRC32 r32, r/m16 (CRC32CH data size). 66h operand-size prefix selects the
    /// 16-bit r/m form; NO REX.W (that would be the invalid r64,r/m16). Reads only
    /// the source's low 16 bits.
    pub fn emit_crc32_r32_r16(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66); // operand-size override → r/m16
        self.buf.push(0xF2); // mandatory CRC32 prefix
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x38); self.buf.push(0xF1);
        self.modrm_rr(dst, src);
    }

    /// CRC32 r32, r/m32 (CRC32CW data size). NO REX.W — the r64,r/m32 form does
    /// not exist; with REX.W this opcode is r64,r/m64 (reads 8 bytes). Reads only
    /// the source's low 32 bits and zero-extends the 32-bit result into r64.
    pub fn emit_crc32_r32_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x38); self.buf.push(0xF1);
        self.modrm_rr(dst, src);
    }

    /// CRC32 r64, r/m64.
    pub fn emit_crc32_r64_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_always(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x38); self.buf.push(0xF1);
        self.modrm_rr(dst, src);
    }

    /// CVTSI2SS xmm, r/m64.
    pub fn emit_cvtsi2ss_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x2A);
        self.modrm_rr(dst, src);
    }

    /// CVTSI2SD xmm, r/m64.
    pub fn emit_cvtsi2sd_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x2A);
        self.modrm_rr(dst, src);
    }

    /// CVTTSS2SI r64, xmm (truncating).
    pub fn emit_cvttss2si_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x2C);
        self.modrm_rr(dst, src);
    }

    /// CVTTSD2SI r64, xmm (truncating).
    pub fn emit_cvttsd2si_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x2C);
        self.modrm_rr(dst, src);
    }

    /// CVTSS2SD xmm, xmm.
    pub fn emit_cvtss2sd(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x5A);
        self.modrm_rr(dst, src);
    }

    /// CVTSD2SS xmm, xmm.
    pub fn emit_cvtsd2ss(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x5A);
        self.modrm_rr(dst, src);
    }

    // ── FMA3 scalar fused multiply-add (VEX.LIG.66.0F38.W{0,1}) ──────────────
    //
    // 3-byte VEX prefix: C4 | (~R ~X ~B m4..m0) | (W ~vvvv L pp). For scalar reg-
    // reg-reg XMM ops: map = 0F38 (mmmmm=00010), L=0 (LIG/scalar), pp=01 (66).
    // W selects the element: W=0 = single (SS), W=1 = double (SD). vvvv encodes
    // the second source (src1); ModRM.reg = dst, ModRM.rm = third source (src2).
    //
    // "213" form semantics: dst = src1(vvvv) * dst + src2(rm)  [FMADD], with the
    // sign/sub variants:
    //   VFMADD213  0xA9:  dst =  src1*dst + src2
    //   VFMSUB213  0xAB:  dst =  src1*dst - src2
    //   VFNMADD213 0xAD:  dst = -src1*dst + src2
    //   VFNMSUB213 0xAF:  dst = -src1*dst - src2
    // The fused multiply-add rounds ONCE, matching ARM FMADD/FMSUB/FNMADD/FNMSUB.
    fn emit_vex_fma213(&mut self, opcode: u8, w: bool, dst: u8, vvvv: u8, rm: u8) {
        // Byte 1: C4 (3-byte VEX escape).
        self.buf.push(0xC4);
        // Byte 2: R X B (inverted) in [7:5], mmmmm = 00010 (0F38) in [4:0].
        //   R = high bit of ModRM.reg (dst); X = high bit of index (none → 0);
        //   B = high bit of ModRM.rm (rm). Stored inverted.
        let r_inv = ((!(dst >> 3)) & 1) << 7;
        let x_inv = 1u8 << 6; // no index reg → X = 1 (inverted 0)
        let b_inv = ((!(rm >> 3)) & 1) << 5;
        self.buf.push(r_inv | x_inv | b_inv | 0b00010);
        // Byte 3: W in [7], ~vvvv in [6:3], L in [2] (0 = scalar), pp in [1:0] (01=66).
        let vvvv_inv = ((!vvvv) & 0xF) << 3;
        self.buf.push(((w as u8) << 7) | vvvv_inv | 0b01);
        // Opcode + ModRM (reg=dst, rm=rm, mod=11).
        self.buf.push(opcode);
        self.modrm_rr(dst, rm);
    }

    /// VFMADD213SS/SD xmm_dst, xmm_vvvv, xmm_rm → dst = vvvv*dst + rm (fused).
    pub fn emit_vfmadd213(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xA9, dbl, dst, vvvv, rm);
    }
    /// VFMSUB213SS/SD → dst = vvvv*dst - rm (fused).
    pub fn emit_vfmsub213(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAB, dbl, dst, vvvv, rm);
    }
    /// VFNMADD213SS/SD → dst = -(vvvv*dst) + rm (fused).
    pub fn emit_vfnmadd213(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAD, dbl, dst, vvvv, rm);
    }
    /// VFNMSUB213SS/SD → dst = -(vvvv*dst) - rm (fused).
    pub fn emit_vfnmsub213(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAF, dbl, dst, vvvv, rm);
    }

    // ── FMA3 packed 128-bit fused multiply-add (VEX.128.66.0F38.W{0,1}) ──────
    //
    // Same 3-byte VEX layout as the scalar helpers (L=0 → VEX.128, pp=01 → 66,
    // W=0 → PS / W=1 → PD). The packed opcodes are the scalar opcode − 1 (even):
    //   VFMADD213P{S,D}  0xA8:  dst =  src1(vvvv)*dst + src2(rm)
    //   VFMSUB213P{S,D}  0xAA:  dst =  src1*dst - src2
    //   VFNMADD213P{S,D} 0xAC:  dst = -src1*dst + src2
    //   VFNMSUB213P{S,D} 0xAE:  dst = -src1*dst - src2
    // The multiply-add rounds ONCE per lane, matching AArch64 Advanced-SIMD
    // FMLA/FMLS which are architecturally fused.

    /// VFMADD213PS/PD xmm_dst, xmm_vvvv, xmm_rm → dst = vvvv*dst + rm (fused, per lane).
    pub fn emit_vfmadd213p(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xA8, dbl, dst, vvvv, rm);
    }
    /// VFMSUB213PS/PD → dst = vvvv*dst - rm (fused, per lane).
    pub fn emit_vfmsub213p(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAA, dbl, dst, vvvv, rm);
    }
    /// VFNMADD213PS/PD → dst = -(vvvv*dst) + rm (fused, per lane).
    pub fn emit_vfnmadd213p(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAC, dbl, dst, vvvv, rm);
    }
    /// VFNMSUB213PS/PD → dst = -(vvvv*dst) - rm (fused, per lane).
    pub fn emit_vfnmsub213p(&mut self, dbl: bool, dst: u8, vvvv: u8, rm: u8) {
        self.emit_vex_fma213(0xAE, dbl, dst, vvvv, rm);
    }

    // ── FP precision converts (FCVTL/FCVTN family) ────────────────────────────

    /// General 3-byte VEX, VEX.128 (L=0), pp=01 (66), register-register form:
    /// `map` = mmmmm (0b00010 = 0F38, 0b00011 = 0F3A); vvvv unused (1111).
    fn emit_vex128_66(&mut self, map: u8, opcode: u8, reg: u8, rm: u8) {
        self.buf.push(0xC4);
        let r_inv = ((!(reg >> 3)) & 1) << 7;
        let b_inv = ((!(rm >> 3)) & 1) << 5;
        self.buf.push(r_inv | (1 << 6) | b_inv | map);
        self.buf.push((0xF << 3) | 0b01); // W=0, vvvv=1111 (unused), L=0, pp=66
        self.buf.push(opcode);
        self.modrm_rr(reg, rm);
    }
    /// VCVTPH2PS xmm_dst, xmm_src (F16C): 4 halves in src[63:0] → 4 singles.
    pub fn emit_vcvtph2ps(&mut self, dst: u8, src: u8) {
        self.emit_vex128_66(0b00010, 0x13, dst, src);
    }
    /// VCVTPS2PH xmm_dst, xmm_src, imm8 (F16C): 4 singles → 4 halves in dst[63:0],
    /// dst[127:64] zeroed. imm8 bits[1:0] = rounding (00 = nearest-even).
    /// ModRM.reg is the SOURCE here (the r/m operand is the destination).
    pub fn emit_vcvtps2ph(&mut self, dst: u8, src: u8, imm: u8) {
        self.emit_vex128_66(0b00011, 0x1D, src, dst);
        self.buf.push(imm);
    }
    /// CVTPS2PD xmm, xmm: 2 singles in src[63:0] → 2 doubles.
    pub fn emit_cvtps2pd(&mut self, dst: u8, src: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x5A);
        self.modrm_rr(dst, src);
    }
    /// CVTPD2PS xmm, xmm: 2 doubles → 2 singles in dst[63:0], dst[127:64] zeroed.
    pub fn emit_cvtpd2ps(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x5A);
        self.modrm_rr(dst, src);
    }
    /// MOVLHPS xmm_dst, xmm_src: dst[127:64] = src[63:0] (dst[63:0] kept).
    pub fn emit_movlhps(&mut self, dst: u8, src: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x16);
        self.modrm_rr(dst, src);
    }

    /// UCOMISS xmm, xmm.
    pub fn emit_ucomiss(&mut self, a: u8, b: u8) {
        self.rex_opt(false, a, 0, b);
        self.buf.push(0x0F); self.buf.push(0x2E);
        self.modrm_rr(a, b);
    }

    /// UCOMISD xmm, xmm.
    pub fn emit_ucomisd(&mut self, a: u8, b: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, a, 0, b);
        self.buf.push(0x0F); self.buf.push(0x2E);
        self.modrm_rr(a, b);
    }

    /// MOVAPS xmm, xmm (used for abs/neg peepholes).
    pub fn emit_movaps_rr(&mut self, dst: u8, src: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0x28);
        self.modrm_rr(dst, src);
    }

    /// XORPS xmm, xmm.
    pub fn emit_xorps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x57, dst, src); }

    /// ANDPS xmm, xmm.
    pub fn emit_andps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x54, dst, src); }

    /// ANDNPS xmm, xmm.
    pub fn emit_andnps(&mut self, dst: u8, src: u8) { self.emit_sse_nopfx_op(0x55, dst, src); }

    /// CMPLTPS / CMPEQPS / CMPUNORDPS via CMPPS xmm, xmm, imm8.
    pub fn emit_cmpps(&mut self, dst: u8, src: u8, pred: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0xC2);
        self.modrm_rr(dst, src);
        self.buf.push(pred);
    }

    /// CMPPD xmm, xmm, imm8.
    pub fn emit_cmppd(&mut self, dst: u8, src: u8, pred: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0xC2);
        self.modrm_rr(dst, src);
        self.buf.push(pred);
    }

    /// CMPSS xmm, xmm, imm8 (F3 0F C2 /r ib) — scalar single compare, low element.
    pub fn emit_cmpss(&mut self, dst: u8, src: u8, pred: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0xC2);
        self.modrm_rr(dst, src);
        self.buf.push(pred);
    }

    /// CMPSD xmm, xmm, imm8 (F2 0F C2 /r ib) — scalar double compare, low element.
    pub fn emit_cmpsd(&mut self, dst: u8, src: u8, pred: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F); self.buf.push(0xC2);
        self.modrm_rr(dst, src);
        self.buf.push(pred);
    }

    /// LEA r64, [base + disp] — used for address computation in lowering.
    pub fn emit_lea_r64_mem(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_opt(true, dst, 0, base);
        self.buf.push(0x8D);
        self.modrm_mem(dst, base, disp);
    }

    /// LEA r64, [base + index*scale + disp].
    pub fn emit_lea_r64_sib(&mut self, dst: u8, base: u8, idx: u8, scale: u8, disp: i32) {
        self.rex_opt(true, dst, idx, base);
        self.buf.push(0x8D);
        self.modrm_sib(dst, base, idx, scale, disp);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // M4b-6: SIMD/FP/crypto encoder additions (BUILDSPEC §3).
    // Pure-additive; every helper mirrors an existing former. Grouped by the
    // mandatory-prefix / escape map it lives in.
    // ═════════════════════════════════════════════════════════════════════════

    /// `66 0F 3A <op> /r ib` — SSE4.1 three-byte-escape immediate form
    /// (reg = dst, r/m = src). Used by round*, insertps. (cvtps2ph reverses the
    /// operands and is written out longhand.)
    fn emit_sse4a_imm(&mut self, op: u8, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x3A);
        self.buf.push(op);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    /// `<prefix> 0F <op> /r [base+disp]` — scalar xmm load/store. `xmm` is the
    /// reg field; load uses op 0x10, store uses op 0x11.
    fn emit_sse_mem(&mut self, prefix: u8, op: u8, xmm: u8, base: u8, disp: i32) {
        self.buf.push(prefix);
        self.rex_opt(false, xmm, 0, base);
        self.buf.push(0x0F);
        self.buf.push(op);
        self.modrm_mem(xmm, base, disp);
    }

    // ── §3.1 saturating + extra integer (66 0F xx) ───────────────────────────
    pub fn emit_paddsb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xEC, d, s); }
    pub fn emit_paddsw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xED, d, s); }
    pub fn emit_paddusb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xDC, d, s); }
    pub fn emit_paddusw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xDD, d, s); }
    pub fn emit_psubsb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE8, d, s); }
    pub fn emit_psubsw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE9, d, s); }
    pub fn emit_psubusb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xD8, d, s); }
    pub fn emit_psubusw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xD9, d, s); }
    pub fn emit_packsswb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x63, d, s); }
    pub fn emit_packuswb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x67, d, s); }
    pub fn emit_packssdw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x6B, d, s); }
    pub fn emit_punpckhqdq(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x6D, d, s); }
    pub fn emit_psadbw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xF6, d, s); }
    pub fn emit_pmaddwd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xF5, d, s); }
    pub fn emit_pavgb(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE0, d, s); }
    pub fn emit_pavgw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE3, d, s); }
    pub fn emit_pmulhw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE5, d, s); }
    pub fn emit_pmulhuw(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0xE4, d, s); }

    // ── §3.2 SSSE3 / SSE4.1 / SSE4.2 (66 0F 38 xx) ───────────────────────────
    pub fn emit_pabsb(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x1C, d, s); }
    pub fn emit_pabsw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x1D, d, s); }
    pub fn emit_pabsd(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x1E, d, s); }
    pub fn emit_phaddw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x01, d, s); }
    pub fn emit_phaddd(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x02, d, s); }
    pub fn emit_pmaddubsw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x04, d, s); }
    pub fn emit_pcmpeqq(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x29, d, s); }
    pub fn emit_pcmpgtq(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x37, d, s); }
    pub fn emit_pblendvb(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x10, d, s); }
    pub fn emit_packusdw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x2B, d, s); }
    pub fn emit_pmovsxbw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x20, d, s); }
    pub fn emit_pmovsxwd(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x23, d, s); }
    pub fn emit_pmovsxdq(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x25, d, s); }
    pub fn emit_pmovzxbw(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x30, d, s); }
    pub fn emit_pmovzxwd(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x33, d, s); }
    pub fn emit_pmovzxdq(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x35, d, s); }
    pub fn emit_cvtph2ps(&mut self, d: u8, s: u8) { self.emit_sse4_op(0x38, 0x13, d, s); }

    // ── §3.3 imm-bearing SSE4.1 / F16C ───────────────────────────────────────
    pub fn emit_roundss(&mut self, d: u8, s: u8, imm: u8) { self.emit_sse4a_imm(0x0A, d, s, imm); }
    pub fn emit_roundsd(&mut self, d: u8, s: u8, imm: u8) { self.emit_sse4a_imm(0x0B, d, s, imm); }
    pub fn emit_roundps(&mut self, d: u8, s: u8, imm: u8) { self.emit_sse4a_imm(0x08, d, s, imm); }
    pub fn emit_roundpd(&mut self, d: u8, s: u8, imm: u8) { self.emit_sse4a_imm(0x09, d, s, imm); }
    pub fn emit_insertps(&mut self, d: u8, s: u8, imm: u8) { self.emit_sse4a_imm(0x21, d, s, imm); }

    /// VCVTPS2PH xmm/m, xmm, imm8 — reg field is the SOURCE (operands reversed
    /// vs the other 0F 3A ops), so this is longhand: reg=src, r/m=dst.
    pub fn emit_cvtps2ph(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, src, 0, dst);
        self.buf.push(0x0F);
        self.buf.push(0x3A);
        self.buf.push(0x1D);
        self.modrm_rr(src, dst);
        self.buf.push(imm);
    }

    /// SHUFPS xmm, xmm, imm8 (`0F C6 /r ib` — no mandatory prefix).
    pub fn emit_shufps(&mut self, dst: u8, src: u8, imm: u8) {
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0xC6);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }
    /// PSHUFLW xmm, xmm, imm8 (`F2 0F 70 /r ib`).
    pub fn emit_pshuflw(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x70);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }
    /// PSHUFHW xmm, xmm, imm8 (`F3 0F 70 /r ib`).
    pub fn emit_pshufhw(&mut self, dst: u8, src: u8, imm: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x70);
        self.modrm_rr(dst, src);
        self.buf.push(imm);
    }

    // ── §3.4 packed FP min/max + sqrt + int<->fp convert ─────────────────────
    pub fn emit_minps(&mut self, d: u8, s: u8) { self.emit_sse_nopfx_op(0x5D, d, s); }
    pub fn emit_maxps(&mut self, d: u8, s: u8) { self.emit_sse_nopfx_op(0x5F, d, s); }
    pub fn emit_minpd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x5D, d, s); }
    pub fn emit_maxpd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x5F, d, s); }
    pub fn emit_minss(&mut self, d: u8, s: u8) { self.emit_sse_f3_op(0x5D, d, s); }
    pub fn emit_maxss(&mut self, d: u8, s: u8) { self.emit_sse_f3_op(0x5F, d, s); }
    pub fn emit_minsd(&mut self, d: u8, s: u8) { self.emit_sse_f2_op(0x5D, d, s); }
    pub fn emit_maxsd(&mut self, d: u8, s: u8) { self.emit_sse_f2_op(0x5F, d, s); }
    pub fn emit_andpd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x54, d, s); }
    pub fn emit_orps(&mut self, d: u8, s: u8) { self.emit_sse_nopfx_op(0x56, d, s); }
    pub fn emit_orpd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x56, d, s); }
    pub fn emit_sqrtpd(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x51, d, s); }
    pub fn emit_cvtps2dq(&mut self, d: u8, s: u8) { self.emit_sse2_op(0x66, 0x5B, d, s); }
    pub fn emit_cvttps2dq(&mut self, d: u8, s: u8) { self.emit_sse_f3_op(0x5B, d, s); }
    pub fn emit_cvtdq2ps(&mut self, d: u8, s: u8) { self.emit_sse_nopfx_op(0x5B, d, s); }

    // ── §3.5 GP<->XMM 32-bit, scalar mem moves, 32-bit + non-trunc cvt ───────
    /// MOVD xmm, r/m32 (`66 0F 6E /r`, no REX.W). Zeroes xmm[127:32].
    pub fn emit_movd_xmm_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x6E);
        self.modrm_rr(dst, src);
    }
    /// MOVD r/m32, xmm (`66 0F 7E /r`, no REX.W). reg = xmm src.
    pub fn emit_movd_r32_xmm(&mut self, dst: u8, src: u8) {
        self.buf.push(0x66);
        self.rex_opt(false, src, 0, dst);
        self.buf.push(0x0F);
        self.buf.push(0x7E);
        self.modrm_rr(src, dst);
    }
    /// MOVQ xmm, xmm (`F3 0F 7E /r`). Copies low 64, zeroes [127:64] — the
    /// one-instruction D-form upper-zero idiom (BUILDSPEC §1.4).
    pub fn emit_movq_xmm_xmm(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x7E);
        self.modrm_rr(dst, src);
    }
    /// MOVSS xmm, [base+disp] (`F3 0F 10`). Zeroes xmm[127:32].
    pub fn emit_movss_load(&mut self, dst: u8, base: u8, disp: i32) { self.emit_sse_mem(0xF3, 0x10, dst, base, disp); }
    /// MOVSS [base+disp], xmm (`F3 0F 11`).
    pub fn emit_movss_store(&mut self, base: u8, disp: i32, src: u8) { self.emit_sse_mem(0xF3, 0x11, src, base, disp); }
    /// MOVSD xmm, [base+disp] (`F2 0F 10`). Zeroes xmm[127:64].
    pub fn emit_movsd_load(&mut self, dst: u8, base: u8, disp: i32) { self.emit_sse_mem(0xF2, 0x10, dst, base, disp); }
    /// MOVSD [base+disp], xmm (`F2 0F 11`).
    pub fn emit_movsd_store(&mut self, base: u8, disp: i32, src: u8) { self.emit_sse_mem(0xF2, 0x11, src, base, disp); }
    /// CVTSI2SS xmm, r/m32 (`F3 0F 2A`, no REX.W).
    pub fn emit_cvtsi2ss_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2A);
        self.modrm_rr(dst, src);
    }
    /// CVTSI2SD xmm, r/m32 (`F2 0F 2A`, no REX.W).
    pub fn emit_cvtsi2sd_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2A);
        self.modrm_rr(dst, src);
    }
    /// CVTTSS2SI r32, xmm (`F3 0F 2C`, no REX.W, truncating).
    pub fn emit_cvttss2si_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2C);
        self.modrm_rr(dst, src);
    }
    /// CVTTSD2SI r32, xmm (`F2 0F 2C`, no REX.W, truncating).
    pub fn emit_cvttsd2si_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(false, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2C);
        self.modrm_rr(dst, src);
    }
    /// CVTSS2SI r64, xmm (`F3 0F 2D`, REX.W, MXCSR-rounded).
    pub fn emit_cvtss2si_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF3);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2D);
        self.modrm_rr(dst, src);
    }
    /// CVTSD2SI r64, xmm (`F2 0F 2D`, REX.W, MXCSR-rounded).
    pub fn emit_cvtsd2si_r64(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(true, dst, 0, src);
        self.buf.push(0x0F);
        self.buf.push(0x2D);
        self.modrm_rr(dst, src);
    }

    // §3.6 integer fixup helpers (emit_test_rr64 / emit_cmp_rr64 / emit_and_rr64
    // / emit_or_rr64 / emit_xor_rr64 / emit_mov_r64_imm64 / emit_setcc_r8 /
    // emit_jcc_rel32 / emit_shr_r64_imm8) all already exist on X86Encoder.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (M4b adversarial-review CRITICAL fix): an 8-bit store from
    /// SPL/BPL/SIL/DIL (regs 4..=7) MUST carry a REX prefix. Without it, ModRM
    /// reg 4..7 encodes the legacy high bytes AH/CH/DH/BH — silently storing the
    /// wrong byte of the WRONG register (a STRB of RSI would write DH). Assert a
    /// REX prefix (0x40..=0x4F) leads the encoding for those source registers.
    #[test]
    fn strb_high_reg_forces_rex() {
        for src in [5u8, 6, 7] {
            // base = RAX, as in the STR-via-walker path ([RAX] = the host PA).
            let mut e = X86Encoder::new();
            e.emit_mov_mem8_r64(0, 0, src);
            let bytes = e.finish();
            assert!(
                (0x40..=0x4F).contains(&bytes[0]),
                "8-bit store from reg {src} must lead with a REX prefix, got {:#x}",
                bytes[0]
            );
            // ...and the opcode (0x88) follows the REX, not leads.
            assert_eq!(bytes[1], 0x88, "REX precedes the 0x88 MOV r/m8,r8 opcode");
        }
        // Sibling: SETcc into a high register has the identical hazard.
        for dst in [5u8, 6, 7] {
            let mut e = X86Encoder::new();
            e.emit_setcc_r8(0x5 /* NZ */, dst);
            let bytes = e.finish();
            assert!(
                (0x40..=0x4F).contains(&bytes[0]),
                "SETcc into reg {dst} must lead with a REX prefix, got {:#x}",
                bytes[0]
            );
            assert_eq!(bytes[1], 0x0F, "REX precedes the 0F 9x SETcc opcode");
        }
    }

    /// FMA3 VEX-prefix regression: scalar 3-source fused multiply-add must encode
    /// a valid 3-byte VEX (C4 …). VFMADD213SS xmm0, xmm1, xmm2 (SS, W=0) has the
    /// canonical encoding C4 E2 71 A9 C2 — cross-checked against the SDM VEX
    /// layout. A wrong prefix would SIGILL on hardware, so pin the exact bytes.
    #[test]
    fn fma3_vfmadd213ss_vex_encoding() {
        let mut e = X86Encoder::new();
        e.emit_vfmadd213(false, 0, 1, 2); // dst=xmm0, vvvv=xmm1, rm=xmm2
        assert_eq!(e.finish(), [0xC4, 0xE2, 0x71, 0xA9, 0xC2], "VFMADD213SS x0,x1,x2");

        // Double form flips the VEX.W bit (byte 3 bit7): C4 E2 F1 A9 C2.
        let mut e = X86Encoder::new();
        e.emit_vfmadd213(true, 0, 1, 2);
        assert_eq!(e.finish(), [0xC4, 0xE2, 0xF1, 0xA9, 0xC2], "VFMADD213SD x0,x1,x2");

        // The four sign variants differ only in the opcode byte (A9/AB/AD/AF).
        let mut e = X86Encoder::new(); e.emit_vfmsub213(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAB, "VFMSUB213SS opcode");
        let mut e = X86Encoder::new(); e.emit_vfnmadd213(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAD, "VFNMADD213SS opcode");
        let mut e = X86Encoder::new(); e.emit_vfnmsub213(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAF, "VFNMSUB213SS opcode");
    }

    /// FMA3 packed 128-bit VEX-prefix regression. VFMADD213PS xmm0,xmm1,xmm2
    /// (PS, W=0, L=0, 66 prefix) is C4 E2 71 A8 C2 — identical to the scalar
    /// VFMADD213SS except the opcode byte (A8 packed vs A9 scalar). Pin the bytes
    /// so a wrong prefix/opcode (which would SIGILL) is caught here, not on HW.
    #[test]
    fn fma3_vfmadd213ps_vex_encoding() {
        let mut e = X86Encoder::new();
        e.emit_vfmadd213p(false, 0, 1, 2); // dst=xmm0, vvvv=xmm1, rm=xmm2
        assert_eq!(e.finish(), [0xC4, 0xE2, 0x71, 0xA8, 0xC2], "VFMADD213PS x0,x1,x2");

        // Double form flips VEX.W: C4 E2 F1 A8 C2.
        let mut e = X86Encoder::new();
        e.emit_vfmadd213p(true, 0, 1, 2);
        assert_eq!(e.finish(), [0xC4, 0xE2, 0xF1, 0xA8, 0xC2], "VFMADD213PD x0,x1,x2");

        // The sub/neg variants differ only in the opcode byte (A8/AA/AC/AE).
        let mut e = X86Encoder::new(); e.emit_vfmsub213p(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAA, "VFMSUB213PS opcode");
        let mut e = X86Encoder::new(); e.emit_vfnmadd213p(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAC, "VFNMADD213PS opcode");
        let mut e = X86Encoder::new(); e.emit_vfnmsub213p(false, 0, 1, 2);
        assert_eq!(e.finish()[3], 0xAE, "VFNMSUB213PS opcode");
    }
}
