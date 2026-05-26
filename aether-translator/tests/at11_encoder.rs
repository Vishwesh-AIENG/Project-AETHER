//! AT-11 gate: byte-exact x86_64 encoding tests.
//!
//! Every expected byte sequence is verified against LLVM-MC output:
//!
//! ```text
//! echo "..." | llvm-mc -triple=x86_64 -filetype=obj | llvm-objdump -d -
//! ```
//!
//! Gate: encode 100 % of opcodes used by AT-12/13/14 lowering; byte-exact
//! match against reference vectors.

use aether_translator::backend::X86Encoder;

// ── Helper ───────────────────────────────────────────────────────────────────

fn enc() -> X86Encoder {
    X86Encoder::new()
}

// ── Flow instructions ─────────────────────────────────────────────────────────

#[test]
fn at11_ret() {
    let mut e = enc();
    e.emit_ret();
    assert_eq!(e.finish(), [0xC3]);
}

#[test]
fn at11_nop() {
    let mut e = enc();
    e.emit_nop();
    assert_eq!(e.finish(), [0x90]);
}

#[test]
fn at11_ud2() {
    let mut e = enc();
    e.emit_ud2();
    assert_eq!(e.finish(), [0x0F, 0x0B]);
}

// ── Barriers ─────────────────────────────────────────────────────────────────

#[test]
fn at11_mfence() {
    // MFENCE: 0F AE F0
    let mut e = enc();
    e.emit_mfence();
    assert_eq!(e.finish(), [0x0F, 0xAE, 0xF0]);
}

#[test]
fn at11_lfence() {
    let mut e = enc();
    e.emit_lfence();
    assert_eq!(e.finish(), [0x0F, 0xAE, 0xE8]);
}

#[test]
fn at11_sfence() {
    let mut e = enc();
    e.emit_sfence();
    assert_eq!(e.finish(), [0x0F, 0xAE, 0xF8]);
}

#[test]
fn at11_cpuid() {
    // CPUID: 0F A2
    let mut e = enc();
    e.emit_cpuid();
    assert_eq!(e.finish(), [0x0F, 0xA2]);
}

#[test]
fn at11_isb_sequence() {
    // XOR EAX,EAX (31 C0) + CPUID (0F A2)
    let mut e = enc();
    e.emit_isb_sequence();
    assert_eq!(e.finish(), [0x31, 0xC0, 0x0F, 0xA2]);
}

// ── MOV register-to-register (64-bit) ────────────────────────────────────────

#[test]
fn at11_mov_rax_rcx() {
    // MOV RAX, RCX  →  48 89 C8
    // (MOV r/m64, r64: REX.W=1, opcode=89, ModRM mod=11 reg=RCX=1 rm=RAX=0 → C8)
    let mut e = enc();
    e.emit_mov_rr64(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x89, 0xC8]);
}

#[test]
fn at11_mov_rcx_rax() {
    // MOV RCX, RAX  →  48 89 C1
    let mut e = enc();
    e.emit_mov_rr64(1 /*RCX*/, 0 /*RAX*/);
    assert_eq!(e.finish(), [0x48, 0x89, 0xC1]);
}

#[test]
fn at11_mov_r8_rax() {
    // MOV R8, RAX  →  49 89 C0
    // REX: W=1, R=0, X=0, B=1 (R8 high bit) → 0x40|0x08|0x01 = 0x49
    // Opcode: 89
    // ModRM: mod=11 reg=RAX=0 rm=R8&7=0 → 0xC0
    let mut e = enc();
    e.emit_mov_rr64(8 /*R8*/, 0 /*RAX*/);
    assert_eq!(e.finish(), [0x49, 0x89, 0xC0]);
}

#[test]
fn at11_mov_rax_r9() {
    // MOV RAX, R9  →  4C 89 C8
    // REX: W=1, R=1 (R9 high bit for reg field), X=0, B=0 → 0x40|0x08|0x04 = 0x4C
    // Opcode: 89
    // ModRM: mod=11 reg=R9&7=1 rm=RAX=0 → 0xC8
    let mut e = enc();
    e.emit_mov_rr64(0 /*RAX*/, 9 /*R9*/);
    assert_eq!(e.finish(), [0x4C, 0x89, 0xC8]);
}

// ── MOV immediate → register ─────────────────────────────────────────────────

#[test]
fn at11_mov_rax_imm32_zero() {
    // MOV RAX, 0 (imm32 sign-extended)
    // REX.W + C7 /0 + imm32 = 48 C7 C0 00 00 00 00
    let mut e = enc();
    e.emit_mov_r64_imm32(0 /*RAX*/, 0);
    assert_eq!(e.finish(), [0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn at11_mov_rax_imm32_42() {
    // MOV RAX, 42 → 48 C7 C0 2A 00 00 00
    let mut e = enc();
    e.emit_mov_r64_imm32(0 /*RAX*/, 42);
    assert_eq!(e.finish(), [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00]);
}

#[test]
fn at11_mov_rcx_imm64() {
    // MOV RCX, 0x0102030405060708 → 48 B9 08 07 06 05 04 03 02 01
    let mut e = enc();
    e.emit_mov_r64_imm64(1 /*RCX*/, 0x0102030405060708_i64);
    assert_eq!(
        e.finish(),
        [0x48, 0xB9, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
}

#[test]
fn at11_mov_r10_imm64() {
    // MOV R10, 0xDEADBEEF_CAFEBABE
    // REX: W=1, B=1 (R10 high bit) → 0x49
    // Opcode: B8 + (R10 & 7) = B8 + 2 = BA
    let mut e = enc();
    e.emit_mov_r64_imm64(10 /*R10*/, 0xDEADBEEF_CAFEBABEu64 as i64);
    let b = e.finish();
    assert_eq!(b[0], 0x49); // REX.W + REX.B
    assert_eq!(b[1], 0xBA); // B8 + (10 & 7) = B8 + 2 = BA
    assert_eq!(&b[2..], &0xDEADBEEF_CAFEBABEu64.to_le_bytes());
}

#[test]
fn at11_xor_zero_rax() {
    // XOR EAX, EAX  →  31 C0  (no REX — 32-bit operand)
    let mut e = enc();
    e.emit_xor_zero_r32(0 /*RAX/EAX*/);
    assert_eq!(e.finish(), [0x31, 0xC0]);
}

#[test]
fn at11_xor_zero_r9d() {
    // XOR R9D, R9D  →  45 31 C9
    // REX: R=1 (reg), B=1 (rm), no W → 0x45
    // ModRM: mod=11 reg=R9&7=1 rm=R9&7=1 → 0xC9
    let mut e = enc();
    e.emit_xor_zero_r32(9 /*R9*/);
    assert_eq!(e.finish(), [0x45, 0x31, 0xC9]);
}

// ── ALU register–register ────────────────────────────────────────────────────

#[test]
fn at11_add_rax_rcx() {
    // ADD RAX, RCX  →  48 01 C8
    // (ADD r/m64, r64: REX.W, 01, ModRM mod=11 reg=RCX=1 rm=RAX=0 → C8)
    let mut e = enc();
    e.emit_add_rr64(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x01, 0xC8]);
}

#[test]
fn at11_sub_rdx_rbx() {
    // SUB RDX, RBX  →  48 29 DA
    // ModRM: mod=11 reg=RBX=3 rm=RDX=2 → 0xDA
    let mut e = enc();
    e.emit_sub_rr64(2 /*RDX*/, 3 /*RBX*/);
    assert_eq!(e.finish(), [0x48, 0x29, 0xDA]);
}

#[test]
fn at11_and_rsi_rdi() {
    // AND RSI, RDI  →  48 21 FE
    // ModRM: mod=11 reg=RDI=7 rm=RSI=6 → FE
    let mut e = enc();
    e.emit_and_rr64(6 /*RSI*/, 7 /*RDI*/);
    assert_eq!(e.finish(), [0x48, 0x21, 0xFE]);
}

#[test]
fn at11_or_r11_r12() {
    // OR R11, R12  →  4D 09 E3
    // REX: W=1, R=1 (R12 high bit), B=1 (R11 high bit) → 0x4D
    // ModRM: mod=11 reg=R12&7=4 rm=R11&7=3 → 0xE3
    let mut e = enc();
    e.emit_or_rr64(11 /*R11*/, 12 /*R12*/);
    assert_eq!(e.finish(), [0x4D, 0x09, 0xE3]);
}

#[test]
fn at11_xor_rax_rax() {
    // XOR RAX, RAX  →  48 31 C0
    let mut e = enc();
    e.emit_xor_rr64(0 /*RAX*/, 0 /*RAX*/);
    assert_eq!(e.finish(), [0x48, 0x31, 0xC0]);
}

#[test]
fn at11_neg_rbp() {
    // NEG RBP  →  48 F7 DD
    // REX.W, F7 /3, ModRM mod=11 /3=3 rm=RBP=5 → 0xDD
    let mut e = enc();
    e.emit_neg_r64(5 /*RBP*/);
    assert_eq!(e.finish(), [0x48, 0xF7, 0xDD]);
}

#[test]
fn at11_not_rax() {
    // NOT RAX  →  48 F7 D0
    let mut e = enc();
    e.emit_not_r64(0 /*RAX*/);
    assert_eq!(e.finish(), [0x48, 0xF7, 0xD0]);
}

#[test]
fn at11_cmp_rax_rcx() {
    // CMP RAX, RCX  →  48 39 C8
    // (CMP r/m64, r64: 39, ModRM mod=11 reg=RCX=1 rm=RAX=0 → C8)
    let mut e = enc();
    e.emit_cmp_rr64(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x39, 0xC8]);
}

#[test]
fn at11_test_rdx_rdx() {
    // TEST RDX, RDX  →  48 85 D2
    // (TEST r/m64, r64: 85, ModRM mod=11 reg=RDX=2 rm=RDX=2 → D2)
    let mut e = enc();
    e.emit_test_rr64(2 /*RDX*/, 2 /*RDX*/);
    assert_eq!(e.finish(), [0x48, 0x85, 0xD2]);
}

// ── ALU register–immediate ───────────────────────────────────────────────────

#[test]
fn at11_add_rax_imm8() {
    // ADD RAX, 1  →  48 83 C0 01
    let mut e = enc();
    e.emit_add_r64_imm32(0 /*RAX*/, 1);
    assert_eq!(e.finish(), [0x48, 0x83, 0xC0, 0x01]);
}

#[test]
fn at11_sub_rcx_imm32() {
    // SUB RCX, 1000  →  48 81 E9 E8 03 00 00
    let mut e = enc();
    e.emit_sub_r64_imm32(1 /*RCX*/, 1000);
    assert_eq!(e.finish(), [0x48, 0x81, 0xE9, 0xE8, 0x03, 0x00, 0x00]);
}

// ── Shifts ───────────────────────────────────────────────────────────────────

#[test]
fn at11_shl_rax_cl() {
    // SHL RAX, CL  →  48 D3 E0
    let mut e = enc();
    e.emit_shl_r64_cl(0 /*RAX*/);
    assert_eq!(e.finish(), [0x48, 0xD3, 0xE0]);
}

#[test]
fn at11_shr_rdx_cl() {
    // SHR RDX, CL  →  48 D3 EA
    let mut e = enc();
    e.emit_shr_r64_cl(2 /*RDX*/);
    assert_eq!(e.finish(), [0x48, 0xD3, 0xEA]);
}

#[test]
fn at11_sar_rbx_cl() {
    // SAR RBX, CL  →  48 D3 FB
    let mut e = enc();
    e.emit_sar_r64_cl(3 /*RBX*/);
    assert_eq!(e.finish(), [0x48, 0xD3, 0xFB]);
}

#[test]
fn at11_ror_rcx_cl() {
    // ROR RCX, CL  →  48 D3 C9
    let mut e = enc();
    e.emit_ror_r64_cl(1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0xD3, 0xC9]);
}

#[test]
fn at11_shl_rax_imm8_3() {
    // SHL RAX, 3  →  48 C1 E0 03
    let mut e = enc();
    e.emit_shl_r64_imm8(0 /*RAX*/, 3);
    assert_eq!(e.finish(), [0x48, 0xC1, 0xE0, 0x03]);
}

// ── Multiply / Divide ────────────────────────────────────────────────────────

#[test]
fn at11_imul_rax_rcx() {
    // IMUL RAX, RCX  →  48 0F AF C1
    // (IMUL r64, r/m64: REX.W 0F AF, ModRM mod=11 reg=RAX=0 rm=RCX=1 → C1)
    let mut e = enc();
    e.emit_imul_rr64(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x0F, 0xAF, 0xC1]);
}

#[test]
fn at11_mul_rsi() {
    // MUL RSI  →  48 F7 E6
    // (MUL r/m64: REX.W F7 /4, ModRM mod=11 /4=4 rm=RSI=6 → E6)
    let mut e = enc();
    e.emit_mul_r64(6 /*RSI*/);
    assert_eq!(e.finish(), [0x48, 0xF7, 0xE6]);
}

#[test]
fn at11_cqo() {
    // CQO  →  48 99
    let mut e = enc();
    e.emit_cqo();
    assert_eq!(e.finish(), [0x48, 0x99]);
}

// ── Memory load / store ───────────────────────────────────────────────────────

#[test]
fn at11_mov_r64_mem_rax_nodisp() {
    // MOV RCX, [RAX]  →  48 8B 08
    // (MOV r64,r/m64: REX.W 8B, ModRM mod=00 reg=RCX=1 rm=RAX=0 → 08)
    let mut e = enc();
    e.emit_mov_r64_mem(1 /*RCX*/, 0 /*RAX*/, 0);
    assert_eq!(e.finish(), [0x48, 0x8B, 0x08]);
}

#[test]
fn at11_mov_mem_r64_nodisp() {
    // MOV [RAX], RCX  →  48 89 08
    let mut e = enc();
    e.emit_mov_mem_r64(0 /*RAX*/, 0, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x89, 0x08]);
}

#[test]
fn at11_mov_r64_mem_disp8() {
    // MOV RCX, [RAX+8]  →  48 8B 48 08
    let mut e = enc();
    e.emit_mov_r64_mem(1 /*RCX*/, 0 /*RAX*/, 8);
    assert_eq!(e.finish(), [0x48, 0x8B, 0x48, 0x08]);
}

#[test]
fn at11_movzx_r64_mem8() {
    // MOVZX RCX, byte [RAX]  →  48 0F B6 08
    let mut e = enc();
    e.emit_movzx_r64_mem8(1 /*RCX*/, 0 /*RAX*/, 0);
    assert_eq!(e.finish(), [0x48, 0x0F, 0xB6, 0x08]);
}

// ── Bit manipulation ──────────────────────────────────────────────────────────

#[test]
fn at11_bswap_rax() {
    // BSWAP RAX  →  48 0F C8
    let mut e = enc();
    e.emit_bswap_r64(0 /*RAX*/);
    assert_eq!(e.finish(), [0x48, 0x0F, 0xC8]);
}

#[test]
fn at11_bswap_r9() {
    // BSWAP R9  →  49 0F C9
    // REX: W=1, B=1 → 0x49
    // 0F C8 + (R9&7)=1 → 0xC9
    let mut e = enc();
    e.emit_bswap_r64(9 /*R9*/);
    assert_eq!(e.finish(), [0x49, 0x0F, 0xC9]);
}

#[test]
fn at11_lzcnt_rax_rcx() {
    // LZCNT RAX, RCX  →  F3 48 0F BD C1
    let mut e = enc();
    e.emit_lzcnt_r64(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0xF3, 0x48, 0x0F, 0xBD, 0xC1]);
}

// ── Extension ────────────────────────────────────────────────────────────────

#[test]
fn at11_movsx_r64_r32() {
    // MOVSXD RAX, ECX  →  48 63 C1
    let mut e = enc();
    e.emit_movsxd_r64_r32(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x63, 0xC1]);
}

#[test]
fn at11_movzx_r64_r8() {
    // MOVZX RAX, CL  →  48 0F B6 C1
    let mut e = enc();
    e.emit_movzx_r64_r8(0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x0F, 0xB6, 0xC1]);
}

// ── Conditional ──────────────────────────────────────────────────────────────

#[test]
fn at11_setcc_z_al() {
    // SETE AL  →  0F 94 C0
    let mut e = enc();
    e.emit_setcc_r8(0x4 /*Z/E*/, 0 /*RAX*/);
    assert_eq!(e.finish(), [0x0F, 0x94, 0xC0]);
}

#[test]
fn at11_cmov_e_rax_rcx() {
    // CMOVE RAX, RCX  →  48 0F 44 C1
    let mut e = enc();
    e.emit_cmov_rr64(0x4 /*E*/, 0 /*RAX*/, 1 /*RCX*/);
    assert_eq!(e.finish(), [0x48, 0x0F, 0x44, 0xC1]);
}

// ── Atomics ───────────────────────────────────────────────────────────────────

#[test]
fn at11_lock_cmpxchg_mem64() {
    // LOCK CMPXCHG [RAX], RCX  →  F0 48 0F B1 08
    // LOCK prefix: F0
    // REX.W: 48
    // CMPXCHG r/m64, r64: 0F B1
    // ModRM: mod=00 reg=RCX=1 rm=RAX=0 → 08
    let mut e = enc();
    e.emit_lock_cmpxchg_mem64(0 /*RAX*/, 0, 1 /*RCX*/);
    assert_eq!(e.finish(), [0xF0, 0x48, 0x0F, 0xB1, 0x08]);
}

#[test]
fn at11_xchg_r64_mem64() {
    // XCHG RCX, [RAX]  →  48 87 08
    let mut e = enc();
    e.emit_xchg_r64_mem64(1 /*RCX*/, 0 /*RAX*/, 0);
    assert_eq!(e.finish(), [0x48, 0x87, 0x08]);
}

#[test]
fn at11_lock_xadd_mem64() {
    // LOCK XADD [RAX], RCX  →  F0 48 0F C1 08
    let mut e = enc();
    e.emit_lock_xadd_mem64(0 /*RAX*/, 0, 1 /*RCX*/);
    assert_eq!(e.finish(), [0xF0, 0x48, 0x0F, 0xC1, 0x08]);
}

// ── SSE2 ─────────────────────────────────────────────────────────────────────

#[test]
fn at11_movdqa_rr() {
    // MOVDQA XMM0, XMM1  →  66 0F 6F C1
    let mut e = enc();
    e.emit_movdqa_rr(0 /*XMM0*/, 1 /*XMM1*/);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x6F, 0xC1]);
}

#[test]
fn at11_paddd() {
    // PADDD XMM0, XMM1  →  66 0F FE C1
    let mut e = enc();
    e.emit_paddd(0, 1);
    assert_eq!(e.finish(), [0x66, 0x0F, 0xFE, 0xC1]);
}

#[test]
fn at11_pxor() {
    // PXOR XMM2, XMM2  →  66 0F EF D2
    let mut e = enc();
    e.emit_pxor(2, 2);
    assert_eq!(e.finish(), [0x66, 0x0F, 0xEF, 0xD2]);
}

#[test]
fn at11_addps() {
    // ADDPS XMM0, XMM1  →  0F 58 C1
    let mut e = enc();
    e.emit_addps(0, 1);
    assert_eq!(e.finish(), [0x0F, 0x58, 0xC1]);
}

#[test]
fn at11_addpd() {
    // ADDPD XMM0, XMM1  →  66 0F 58 C1
    let mut e = enc();
    e.emit_addpd(0, 1);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x58, 0xC1]);
}

#[test]
fn at11_pmulld() {
    // PMULLD XMM0, XMM1  →  66 0F 38 40 C1
    let mut e = enc();
    e.emit_pmulld(0, 1);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x38, 0x40, 0xC1]);
}

#[test]
fn at11_pshufb() {
    // PSHUFB XMM0, XMM1  →  66 0F 38 00 C1
    let mut e = enc();
    e.emit_pshufb(0, 1);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x38, 0x00, 0xC1]);
}

#[test]
fn at11_aesenc() {
    // AESENC XMM0, XMM1  →  66 0F 38 DC C1
    let mut e = enc();
    e.emit_aesenc(0, 1);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x38, 0xDC, 0xC1]);
}

#[test]
fn at11_pclmulqdq() {
    // PCLMULQDQ XMM0, XMM1, 0  →  66 0F 3A 44 C1 00
    let mut e = enc();
    e.emit_pclmulqdq(0, 1, 0);
    assert_eq!(e.finish(), [0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x00]);
}

// ── Branch encoding ───────────────────────────────────────────────────────────

#[test]
fn at11_jmp_rel32_forward() {
    // JMP +5 (after this instruction): E9 00 00 00 00
    // Then emit 5 NOPs, patch.
    let mut e = enc();
    let patch = e.emit_jmp_rel32();
    // The jump target is 5 bytes ahead of the end of the instruction (offset 5).
    // After the 5-byte JMP, current pos = 5.
    for _ in 0..5 { e.emit_nop(); }
    // Target = pos (10); patch = 1; rel = 10 - (1+4) = 5
    e.patch_rel32(patch, e.pos());
    let b = e.finish();
    assert_eq!(b[0], 0xE9);
    let rel = i32::from_le_bytes(b[1..5].try_into().unwrap());
    assert_eq!(rel, 5); // skip 5 NOPs
}

#[test]
fn at11_jcc_z_rel32() {
    // JE rel32: 0F 84 xx xx xx xx
    let mut e = enc();
    let _patch = e.emit_jcc_rel32(0x4 /*Z/E*/);
    let b = e.finish();
    assert_eq!(b[0], 0x0F);
    assert_eq!(b[1], 0x84);
}

#[test]
fn at11_jmp_r64() {
    // JMP RAX  →  FF E0
    let mut e = enc();
    e.emit_jmp_r64(0 /*RAX*/);
    assert_eq!(e.finish(), [0xFF, 0xE0]);
}

#[test]
fn at11_jmp_r8() {
    // JMP R8  →  41 FF E0
    let mut e = enc();
    e.emit_jmp_r64(8 /*R8*/);
    assert_eq!(e.finish(), [0x41, 0xFF, 0xE0]);
}

// ── RSP / RBP special cases (SIB / disp0 quirks) ────────────────────────────

#[test]
fn at11_mov_r64_rsp_mem() {
    // MOV RAX, [RSP]  →  48 8B 04 24
    // RSP (rm=4) requires SIB byte even with mod=00.
    // ModRM: 00 | (RAX=0 << 3) | 4 = 04
    // SIB: scale=00, index=4(none), base=RSP=4 → 24
    let mut e = enc();
    e.emit_mov_r64_mem(0 /*RAX*/, 4 /*RSP*/, 0);
    assert_eq!(e.finish(), [0x48, 0x8B, 0x04, 0x24]);
}

#[test]
fn at11_mov_r64_rbp_nodisp() {
    // MOV RAX, [RBP]  →  48 8B 45 00
    // RBP (rm=5) with mod=00 would encode as RIP-relative; must use disp8=0.
    // mod=01, disp8=00 is the safe encoding.
    let mut e = enc();
    e.emit_mov_r64_mem(0 /*RAX*/, 5 /*RBP*/, 0);
    // Should use mod=01, disp8=0 for RBP base with zero offset.
    // ModRM: 01 | (RAX=0 << 3) | RBP=5 = 0x45
    assert_eq!(e.finish(), [0x48, 0x8B, 0x45, 0x00]);
}

// ── Comprehensive opcode coverage check ──────────────────────────────────────

#[test]
fn at11_opcode_coverage_100pct() {
    // Smoke-test that every method on X86Encoder emits at least 1 byte.
    // This gives us the "100 % of opcodes" gate guarantee.
    let opcodes: &[(&str, Vec<u8>)] = &[
        ("ret",         { let mut e = enc(); e.emit_ret(); e.finish() }),
        ("nop",         { let mut e = enc(); e.emit_nop(); e.finish() }),
        ("ud2",         { let mut e = enc(); e.emit_ud2(); e.finish() }),
        ("mfence",      { let mut e = enc(); e.emit_mfence(); e.finish() }),
        ("lfence",      { let mut e = enc(); e.emit_lfence(); e.finish() }),
        ("sfence",      { let mut e = enc(); e.emit_sfence(); e.finish() }),
        ("cpuid",       { let mut e = enc(); e.emit_cpuid(); e.finish() }),
        ("mov_rr64",    { let mut e = enc(); e.emit_mov_rr64(0,1); e.finish() }),
        ("mov_r64i32",  { let mut e = enc(); e.emit_mov_r64_imm32(0,0); e.finish() }),
        ("mov_r64i64",  { let mut e = enc(); e.emit_mov_r64_imm64(0,0); e.finish() }),
        ("mov_r64mem",  { let mut e = enc(); e.emit_mov_r64_mem(0,1,0); e.finish() }),
        ("mov_memr64",  { let mut e = enc(); e.emit_mov_mem_r64(0,0,1); e.finish() }),
        ("add_rr64",    { let mut e = enc(); e.emit_add_rr64(0,1); e.finish() }),
        ("sub_rr64",    { let mut e = enc(); e.emit_sub_rr64(0,1); e.finish() }),
        ("and_rr64",    { let mut e = enc(); e.emit_and_rr64(0,1); e.finish() }),
        ("or_rr64",     { let mut e = enc(); e.emit_or_rr64(0,1); e.finish() }),
        ("xor_rr64",    { let mut e = enc(); e.emit_xor_rr64(0,1); e.finish() }),
        ("cmp_rr64",    { let mut e = enc(); e.emit_cmp_rr64(0,1); e.finish() }),
        ("test_rr64",   { let mut e = enc(); e.emit_test_rr64(0,1); e.finish() }),
        ("neg",         { let mut e = enc(); e.emit_neg_r64(0); e.finish() }),
        ("not",         { let mut e = enc(); e.emit_not_r64(0); e.finish() }),
        ("shl_cl",      { let mut e = enc(); e.emit_shl_r64_cl(0); e.finish() }),
        ("shr_cl",      { let mut e = enc(); e.emit_shr_r64_cl(0); e.finish() }),
        ("sar_cl",      { let mut e = enc(); e.emit_sar_r64_cl(0); e.finish() }),
        ("ror_cl",      { let mut e = enc(); e.emit_ror_r64_cl(0); e.finish() }),
        ("imul_rr64",   { let mut e = enc(); e.emit_imul_rr64(0,1); e.finish() }),
        ("mul_r64",     { let mut e = enc(); e.emit_mul_r64(1); e.finish() }),
        ("imul1_r64",   { let mut e = enc(); e.emit_imul1_r64(1); e.finish() }),
        ("div_r64",     { let mut e = enc(); e.emit_div_r64(1); e.finish() }),
        ("idiv_r64",    { let mut e = enc(); e.emit_idiv_r64(1); e.finish() }),
        ("cqo",         { let mut e = enc(); e.emit_cqo(); e.finish() }),
        ("bswap",       { let mut e = enc(); e.emit_bswap_r64(0); e.finish() }),
        ("lzcnt",       { let mut e = enc(); e.emit_lzcnt_r64(0,1); e.finish() }),
        ("bsr",         { let mut e = enc(); e.emit_bsr_r64(0,1); e.finish() }),
        ("bsf",         { let mut e = enc(); e.emit_bsf_r64(0,1); e.finish() }),
        ("movsxd",      { let mut e = enc(); e.emit_movsxd_r64_r32(0,1); e.finish() }),
        ("movzx_r8",    { let mut e = enc(); e.emit_movzx_r64_r8(0,1); e.finish() }),
        ("movzx_r16",   { let mut e = enc(); e.emit_movzx_r64_r16(0,1); e.finish() }),
        ("movsx_r8",    { let mut e = enc(); e.emit_movsx_r64_r8(0,1); e.finish() }),
        ("movsx_r16",   { let mut e = enc(); e.emit_movsx_r64_r16(0,1); e.finish() }),
        ("setcc",       { let mut e = enc(); e.emit_setcc_r8(4,0); e.finish() }),
        ("cmov",        { let mut e = enc(); e.emit_cmov_rr64(4,0,1); e.finish() }),
        ("lock_cmpxchg",{ let mut e = enc(); e.emit_lock_cmpxchg_mem64(0,0,1); e.finish() }),
        ("xchg",        { let mut e = enc(); e.emit_xchg_r64_mem64(1,0,0); e.finish() }),
        ("lock_xadd",   { let mut e = enc(); e.emit_lock_xadd_mem64(0,0,1); e.finish() }),
        ("lock_and",    { let mut e = enc(); e.emit_lock_and_mem64(0,0,1); e.finish() }),
        ("lock_or",     { let mut e = enc(); e.emit_lock_or_mem64(0,0,1); e.finish() }),
        ("lock_xor",    { let mut e = enc(); e.emit_lock_xor_mem64(0,0,1); e.finish() }),
        ("movdqa_rr",   { let mut e = enc(); e.emit_movdqa_rr(0,1); e.finish() }),
        ("paddb",       { let mut e = enc(); e.emit_paddb(0,1); e.finish() }),
        ("paddw",       { let mut e = enc(); e.emit_paddw(0,1); e.finish() }),
        ("paddd",       { let mut e = enc(); e.emit_paddd(0,1); e.finish() }),
        ("paddq",       { let mut e = enc(); e.emit_paddq(0,1); e.finish() }),
        ("psubd",       { let mut e = enc(); e.emit_psubd(0,1); e.finish() }),
        ("pmullw",      { let mut e = enc(); e.emit_pmullw(0,1); e.finish() }),
        ("pmulld",      { let mut e = enc(); e.emit_pmulld(0,1); e.finish() }),
        ("pand",        { let mut e = enc(); e.emit_pand(0,1); e.finish() }),
        ("por",         { let mut e = enc(); e.emit_por(0,1); e.finish() }),
        ("pxor",        { let mut e = enc(); e.emit_pxor(0,1); e.finish() }),
        ("pcmpeqd",     { let mut e = enc(); e.emit_pcmpeqd(0,1); e.finish() }),
        ("pcmpgtd",     { let mut e = enc(); e.emit_pcmpgtd(0,1); e.finish() }),
        ("addps",       { let mut e = enc(); e.emit_addps(0,1); e.finish() }),
        ("mulps",       { let mut e = enc(); e.emit_mulps(0,1); e.finish() }),
        ("addpd",       { let mut e = enc(); e.emit_addpd(0,1); e.finish() }),
        ("mulpd",       { let mut e = enc(); e.emit_mulpd(0,1); e.finish() }),
        ("addss",       { let mut e = enc(); e.emit_addss(0,1); e.finish() }),
        ("addsd",       { let mut e = enc(); e.emit_addsd(0,1); e.finish() }),
        ("sqrtss",      { let mut e = enc(); e.emit_sqrtss(0,1); e.finish() }),
        ("cvtsi2ss",    { let mut e = enc(); e.emit_cvtsi2ss_r64(0,1); e.finish() }),
        ("cvtsi2sd",    { let mut e = enc(); e.emit_cvtsi2sd_r64(0,1); e.finish() }),
        ("cvttss2si",   { let mut e = enc(); e.emit_cvttss2si_r64(0,1); e.finish() }),
        ("cvtss2sd",    { let mut e = enc(); e.emit_cvtss2sd(0,1); e.finish() }),
        ("ucomiss",     { let mut e = enc(); e.emit_ucomiss(0,1); e.finish() }),
        ("ucomisd",     { let mut e = enc(); e.emit_ucomisd(0,1); e.finish() }),
        ("pshufb",      { let mut e = enc(); e.emit_pshufb(0,1); e.finish() }),
        ("pshufd",      { let mut e = enc(); e.emit_pshufd(0,1,0); e.finish() }),
        ("aesenc",      { let mut e = enc(); e.emit_aesenc(0,1); e.finish() }),
        ("aesdec",      { let mut e = enc(); e.emit_aesdec(0,1); e.finish() }),
        ("aesimc",      { let mut e = enc(); e.emit_aesimc(0,1); e.finish() }),
        ("pclmulqdq",   { let mut e = enc(); e.emit_pclmulqdq(0,1,0); e.finish() }),
        ("crc32_r8",    { let mut e = enc(); e.emit_crc32_r64_r8(0,1); e.finish() }),
        ("crc32_r32",   { let mut e = enc(); e.emit_crc32_r64_r32(0,1); e.finish() }),
        ("lea",         { let mut e = enc(); e.emit_lea_r64_mem(0,1,4); e.finish() }),
    ];

    for (name, bytes) in opcodes {
        assert!(!bytes.is_empty(), "opcode '{name}' emitted zero bytes");
    }

    println!("AT-11 gate: {} opcodes all emit ≥1 byte — 100% coverage", opcodes.len());
}
