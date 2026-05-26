//! AT-11: x86_64 machine-code encoder.
//!
//! Hand-rolled REX / ModR/M / SIB / immediate / RIP-relative encoding.
//! No external dependencies — required for UEFI link cleanliness.
//!
//! Gate: encode 100 % of opcodes consumed by AT-12/13/14 lowering;
//! byte-exact match against LLVM-MC reference vectors in `at11_encoder`.

use alloc::vec::Vec;

/// Raw byte buffer that accumulates x86_64 machine code.
///
/// Call the `emit_*` methods in program order, then call [`X86Encoder::finish`]
/// to extract the byte vector.  Patch sites for forward jumps are handled with
/// [`X86Encoder::reserve_rel32`] + [`X86Encoder::patch_rel32`].
pub struct X86Encoder {
    buf: Vec<u8>,
}

impl Default for X86Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl X86Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
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
        self.buf.push(0x0F);
        self.buf.push(0x0B);
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
        // Use REX so we can reach SIL/DIL etc; for the 8-bit store, no REX.W
        self.rex_opt(false, src, 0, base);
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
    /// TEST r64, r64.
    pub fn emit_test_rr64(&mut self, a: u8, b: u8) {
        self.emit_alu64_rr(0x85, a, b); // TEST r/m64, r64
    }

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

    /// LZCNT r64, r/m64 (requires LZCNT feature; falls back to BSR for AT-12).
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
        self.rex_opt(false, 0, 0, dst);
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

    /// Full ISB sequence: XOR EAX,EAX + CPUID.
    pub fn emit_isb_sequence(&mut self) {
        self.emit_xor_zero_r32(0); // XOR EAX, EAX
        self.emit_cpuid();
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

    /// CRC32 r64, r/m32.
    pub fn emit_crc32_r64_r32(&mut self, dst: u8, src: u8) {
        self.buf.push(0xF2);
        self.rex_opt(true, dst, 0, src);
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
}
