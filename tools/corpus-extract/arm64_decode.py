#!/usr/bin/env python3
"""arm64_decode.py — minimal ARM64 top-level instruction classifier.

Used by the corpus extractor for two jobs:

  1. Deciding whether a 32-bit instruction word is a LOAD/STORE (Extractor A
     skips those — they need valid memory pointers; the memory corpus + Extractor
     B cover them).
  2. Naming an instruction FAMILY / MNEMONIC for the sweep report, so we can rank
     the SKIP families by count and know which ops to teach the reference next.

This is a *classifier*, not a full disassembler: it recognises the ARM ARM C4
top-level encoding groups and the common data-processing / SIMD / branch / memory
mnemonics. Anything it cannot name falls back to the group name (or UNKNOWN).
It is deliberately independent of the DBT decoder and the oracle reference.
"""

def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)

def bit(w, n):
    return (w >> n) & 1

# ── load/store detection ──────────────────────────────────────────────────────
# ARM ARM C4.1: the Loads and Stores group is op0 (bits[28:25]) == x1x0
# i.e. bit27==1 and bit25==0. This covers LDR/STR (imm/reg/literal/pair/
# unscaled/exclusive), LDP/STP, load/store SIMD, atomics (LDADD...), etc.
def is_load_store(w):
    return bit(w, 27) == 1 and bit(w, 25) == 0


# ── scalar-FP / Advanced-SIMD detection ───────────────────────────────────────
# ARM ARM C4.1: the "Data Processing -- Scalar Floating-Point and Advanced SIMD"
# group is op0 (bits[28:25]) == x111 i.e. (op0 & 0b0111) == 0b0111. This is the
# register-only NEON / scalar-FP compute space (FADD, FMUL, FCVT, DUP, TBL, ADDV,
# FCMEQ, USHL, SQADD, ...). It EXCLUDES SIMD loads/stores (those live in the
# Loads-and-Stores group and need pointers), which is exactly what we want for the
# reg-only oracle blocks. Used by the --simd-only filter and the framework-SIMD
# distinct-insn corpus.
def is_simd_fp(w):
    return top_group(w) == "simd_fp"

# ── top-level group name (ARM ARM C4.1 decode table, op0 = bits[28:25]) ───────
def top_group(w):
    op0 = bits(w, 28, 25)
    # 0000 reserved / SME / etc.
    if op0 == 0b0000:
        return "reserved"
    if op0 in (0b0010,):
        return "sve"
    # 100x  Data processing -- immediate
    if (op0 & 0b1110) == 0b1000:
        return "dp_imm"
    # 101x  Branches, exception generating, system
    if (op0 & 0b1110) == 0b1010:
        return "branch_sys"
    # x1x0  Loads and stores
    if bit(w, 27) == 1 and bit(w, 25) == 0:
        return "ldst"
    # x101  Data processing -- register
    if bit(w, 27) == 1 and bits(w, 26, 25) == 0b01 and bit(w, 28) == 0 or \
       (op0 & 0b0111) == 0b0101:
        return "dp_reg"
    # x111  Data processing -- scalar FP and SIMD
    if (op0 & 0b0111) == 0b0111:
        return "simd_fp"
    return "unknown"


# ── mnemonic naming ───────────────────────────────────────────────────────────
# Best-effort. Returns a short mnemonic string. Grouped by top-level.

def name_dp_imm(w):
    grp = bits(w, 25, 23)  # op[25:23]
    op28_24 = bits(w, 28, 24)
    if op28_24 in (0b10000, 0b10001):
        return "ADRP" if bit(w, 31) else "ADR"
    if grp == 0b010:  # add/sub imm
        s = bit(w, 29); sub = bit(w, 30)
        base = ("SUBS" if s else "SUB") if sub else ("ADDS" if s else "ADD")
        return base + "_imm"
    if grp == 0b011:  # add/sub imm with tags (ARMv8.5 MTE)
        return "ADDG_SUBG"
    if grp == 0b100:  # logical imm
        opc = bits(w, 30, 29)
        return {0: "AND_imm", 1: "ORR_imm", 2: "EOR_imm", 3: "ANDS_imm"}[opc]
    if grp == 0b101:  # move wide imm
        opc = bits(w, 30, 29)
        return {0: "MOVN", 1: "UNALLOC", 2: "MOVZ", 3: "MOVK"}[opc]
    if grp == 0b110:  # bitfield
        opc = bits(w, 30, 29)
        return {0: "SBFM", 1: "BFM", 2: "UBFM", 3: "UNALLOC"}[opc]
    if grp == 0b111:  # extract
        return "EXTR"
    return "dp_imm?"

def name_branch_sys(w):
    # Unconditional branch (imm): op[31:26] = 00x101
    top6 = bits(w, 31, 26)
    if top6 == 0b000101:
        return "B"
    if top6 == 0b100101:
        return "BL"
    # Compare & branch: op[30:24] = 0110100/0110101 (bit31 sf)
    op25 = bits(w, 30, 25)
    if bits(w, 30, 25) == 0b011010:
        return "CBZ" if bit(w, 24) == 0 else "CBNZ"
    # Test & branch: op[30:25] = 011011
    if bits(w, 30, 25) == 0b011011:
        return "TBZ" if bit(w, 24) == 0 else "TBNZ"
    # Conditional branch (imm): op[31:24] = 0101010x
    if bits(w, 31, 24) == 0b01010100:
        return "B.cond"
    # Exception generation: op[31:24] = 11010100
    if bits(w, 31, 24) == 0b11010100:
        ll = bits(w, 4, 0); opc = bits(w, 23, 21)
        if opc == 0b000 and ll == 0b00001:
            return "SVC"
        if opc == 0b000 and ll == 0b00010:
            return "HVC"
        if opc == 0b001:
            return "BRK"
        return "EXCEPTION"
    # System: op[31:22] = 1101010100
    if bits(w, 31, 22) == 0b1101010100:
        if w == 0xD503201F:
            return "NOP"
        # Encoding: 1101010100 L op0(2) op1(3) CRn(4) CRm(4) op2(3) Rt(5)
        l = bit(w, 21)
        op0 = bits(w, 20, 19)
        op1 = bits(w, 18, 16)
        crn = bits(w, 15, 12)
        op2 = bits(w, 7, 5)
        if l == 0 and op0 == 0b00:
            # System instructions with immediate / hints / barriers (CRn selects).
            if crn == 0b0100:
                return "MSR_pstate"       # MSR (immediate) to PSTATE field
            if crn == 0b0010:
                return "HINT"             # NOP/YIELD/WFE/WFI/SEV...
            if crn == 0b0011:
                return {0b100: "DSB", 0b101: "DMB", 0b110: "ISB",
                        0b010: "CLREX", 0b111: "SB"}.get(op2, "BARRIER")
            return "SYSTEM"
        if op0 == 0b01:
            return "SYSL" if l == 1 else "SYS"   # cache/TLB maintenance
        if op0 in (0b10, 0b11):
            return "MRS" if l == 1 else "MSR_reg"
        return "SYSTEM"
    # Unconditional branch (register): op[31:25] = 1101011
    if bits(w, 31, 25) == 0b1101011:
        opc = bits(w, 24, 21)
        return {0b0000: "BR", 0b0001: "BLR", 0b0010: "RET",
                0b0100: "ERET", 0b0101: "DRPS"}.get(opc, "BR_reg")
    return "branch_sys?"

def name_dp_reg(w):
    op1 = bit(w, 28); op2 = bits(w, 24, 21); op3 = bit(w, 30)
    # Logical (shifted register): op[28:24] = 0_1010
    if bits(w, 28, 24) == 0b01010:
        opc = bits(w, 30, 29); n = bit(w, 21)
        m = {(0,0):"AND", (0,1):"BIC", (1,0):"ORR", (1,1):"ORN",
             (2,0):"EOR", (2,1):"EON", (3,0):"ANDS", (3,1):"BICS"}
        return m.get((opc, n), "LOGIC_reg")
    # Add/sub (shifted register): op[28:24]=0_1011 bit21=0
    if bits(w, 28, 24) == 0b01011 and bit(w, 21) == 0:
        s = bit(w, 29); sub = bit(w, 30)
        return ("SUBS" if s else "SUB") + "_reg" if sub else ("ADDS" if s else "ADD") + "_reg"
    # Add/sub (extended register): op[28:24]=0_1011 bit21=1
    if bits(w, 28, 24) == 0b01011 and bit(w, 21) == 1:
        s = bit(w, 29); sub = bit(w, 30)
        return ("SUBS" if s else "SUB") + "_ext" if sub else ("ADDS" if s else "ADD") + "_ext"
    # Add/sub with carry: op[28:21] = 1_1010000
    if bits(w, 28, 21) == 0b11010000:
        s = bit(w, 29); sub = bit(w, 30)
        return {(0,0):"ADC",(0,1):"ADCS",(1,0):"SBC",(1,1):"SBCS"}[(sub,s)]
    # Conditional compare (reg/imm): op[28:21] = 1_1010010
    if bits(w, 28, 21) == 0b11010010:
        imm = bit(w, 11)
        return ("CCMN" if bit(w,30)==0 else "CCMP") + ("_imm" if imm else "_reg")
    # Conditional select: op[28:21] = 1_1010100
    if bits(w, 28, 21) == 0b11010100:
        op = bit(w, 30); o2 = bits(w, 11, 10)
        m = {(0,0):"CSEL",(0,1):"CSINC",(1,0):"CSINV",(1,1):"CSNEG"}
        return m.get((op, o2), "CSEL_fam")
    # Data-processing (2 source): op[28:21]=1_1010110
    if bits(w, 28, 21) == 0b11010110:
        opc = bits(w, 15, 10)
        m = {0b000010:"UDIV",0b000011:"SDIV",0b001000:"LSLV",0b001001:"LSRV",
             0b001010:"ASRV",0b001011:"RORV",0b000000:"SUBP",
             0b010000:"CRC32X",0b010100:"CRC32CX"}
        return m.get(opc, "DP2SRC")
    # Data-processing (1 source): op[30:21]=1_1010110 with bit30=1
    if bits(w, 30, 21) == 0b1011010110:
        opc = bits(w, 20, 16); opc2 = bits(w, 15, 10)
        m = {0b000000:"RBIT",0b000001:"REV16",0b000010:"REV32",
             0b000011:"REV",0b000100:"CLZ",0b000101:"CLS"}
        return m.get(opc2, "DP1SRC")
    # 3-source (madd etc): op[28:24]=1_1011
    if bits(w, 28, 24) == 0b11011:
        op31 = bits(w, 23, 21); o0 = bit(w, 15)
        m = {(0,0):"MADD",(0,1):"MSUB",(1,0):"SMADDL",(1,1):"SMSUBL",
             (2,0):"SMULH",(5,0):"UMADDL",(5,1):"UMSUBL",(6,0):"UMULH"}
        return m.get((op31, o0), "MUL3SRC")
    return "dp_reg?"

def _simd_2reg_misc(w):
    # AdvSIMD two-register misc (op[28:24]=01110 op[21:17]=10000 op[16:12]=opcode).
    # Names the reduction/convert/round/reverse ops that libhwui/Skia hammer.
    u = bit(w, 29); opc = bits(w, 16, 12); sz = bits(w, 23, 22)
    fam = {
        0b00000: "REV64", 0b00001: "REV16/REV32", 0b00010: "SADDLP/UADDLP",
        0b00011: "SUQADD/USQADD", 0b00100: "CLS/CLZ", 0b00101: "CNT/NOT/RBIT",
        0b00110: "SADALP/UADALP", 0b00111: "SQABS/SQNEG", 0b01000: "CMGT/CMGE_zero",
        0b01001: "CMEQ/CMLE_zero", 0b01010: "CMLT_zero", 0b01011: "ABS/NEG",
        0b01100: "FCMGT_zero", 0b01101: "FCMEQ_zero", 0b01110: "FCMLT_zero",
        0b01111: "FABS/FNEG", 0b10010: "XTN/SQXTN", 0b10011: "SHLL",
        0b10100: "SQXTUN", 0b10110: "FCVTN/FCVTXN", 0b10111: "FCVTL",
        0b11000: "FRINTN/FRINTP", 0b11001: "FRINTM/FRINTZ",
        0b11010: "FCVTNS/FCVTPS", 0b11011: "FCVTMS/FCVTZS",
        0b11100: "FCVTAS/URECPE", 0b11101: "SCVTF/UCVTF/FRECPE",
        0b11110: "FRINTI/FRINTX", 0b11111: "FSQRT/FRSQRTE",
    }
    return "SIMD_" + fam.get(opc, f"2misc_op{opc:05b}")


def name_simd_fp(w):
    # ARM ARM C4.1.5 Advanced-SIMD + scalar-FP naming, granular enough to drive
    # the framework-SIMD histogram (which NEON/FP families zygote->SF exercises).
    b31_24 = bits(w, 31, 24)

    # ── Advanced-SIMD, op[28:24]==01110, vector (op31==0) or scalar (bit30 set) ──
    if bits(w, 28, 24) == 0b01110:
        # Three-same: bit21==1, bit10==1
        if bit(w, 21) == 1 and bit(w, 10) == 1:
            opc = bits(w, 15, 11); u = bit(w, 29); sz = bits(w, 23, 22)
            fp = bit(w, 23)  # for FP-class three-same, size high bit selects FP op
            m = {0b10000:"ADD/SUB", 0b00110:"CMGT/CMHI",
                 0b00111:"CMGE/CMHS", 0b10001:"CMTST/CMEQ",
                 0b00011:"AND/BIC/ORR/EOR/ORN", 0b10011:"MUL/PMUL",
                 0b01100:"SMAX/UMAX", 0b01101:"SMIN/UMIN",
                 0b10100:"SMAXP/UMAXP", 0b10101:"SMINP/UMINP",
                 0b00001:"SQADD/UQADD", 0b00101:"SQSUB/UQSUB",
                 0b10110:"SQDMULH/SQRDMULH", 0b10010:"MLA/MLS",
                 0b11110:"FADD/FSUB/FMAX/FMIN", 0b11011:"FMULX/FMUL",
                 0b11111:"FDIV/FMULX", 0b11100:"FCMEQ/FCMGE/FCMGT",
                 0b11010:"FABD/FADDP", 0b11001:"FMLA/FMLS",
                 0b01000:"SSHL/USHL", 0b01010:"SRSHL/URSHL",
                 0b00000:"SHADD/UHADD", 0b00010:"SRHADD/URHADD",
                 0b01001:"SQSHL/UQSHL", 0b01011:"SQRSHL/UQRSHL",
                 0b01110:"ADDP", 0b11101:"FMLAL/FMLSL"}
            return "SIMD_" + m.get(opc, f"3same_op{opc:05b}")
        # Two-register misc: bit21==1, op[20:17]==0000, op[11:10]==10
        if bit(w, 21) == 1 and bits(w, 20, 17) == 0b0000 and bits(w, 11, 10) == 0b10:
            return _simd_2reg_misc(w)
        # Across-lanes (ADDV/SMAXV/UMINV/FMAXV...): bit21==1, op[20:17]==1000, op[11:10]==10
        if bit(w, 21) == 1 and bits(w, 20, 17) == 0b1000 and bits(w, 11, 10) == 0b10:
            opc = bits(w, 16, 12)
            m = {0b00011:"SADDLV/UADDLV", 0b01010:"SMAXV/UMAXV",
                 0b11010:"SMINV/UMINV", 0b11011:"ADDV",
                 0b01100:"FMAXNMV/FMAXV", 0b01111:"FMINNMV/FMINV"}
            return "SIMD_" + m.get(opc, f"across_op{opc:05b}")
        # Three-different (widening SMULL/UMLAL/SADDW/SSUBL...): bit21==1, op[11:10]==00
        if bit(w, 21) == 1 and bits(w, 11, 10) == 0b00:
            opc = bits(w, 15, 12)
            m = {0b0000:"SADDL/UADDL", 0b0001:"SADDW/UADDW",
                 0b0010:"SSUBL/USUBL", 0b0011:"SSUBW/USUBW",
                 0b0100:"ADDHN/RADDHN", 0b0101:"SABAL/UABAL",
                 0b0110:"SUBHN/RSUBHN", 0b0111:"SABDL/UABDL",
                 0b1000:"SMLAL/UMLAL", 0b1001:"SQDMLAL",
                 0b1010:"SMLSL/UMLSL", 0b1011:"SQDMLSL",
                 0b1100:"SMULL/UMULL", 0b1101:"SQDMULL",
                 0b1110:"PMULL"}
            return "SIMD_" + m.get(opc, f"3diff_op{opc:04b}")
        # Copy (DUP/INS/SMOV/UMOV): bit21==0, op[15]==0, bit10==1
        if bit(w, 21) == 0 and bit(w, 15) == 0 and bit(w, 10) == 1:
            imm4 = bits(w, 14, 11)
            m = {0b0000:"DUP_elt", 0b0001:"DUP_gen", 0b0101:"SMOV",
                 0b0111:"UMOV", 0b0011:"INS_gen"}
            if bit(w, 29) == 1:   # op bit -> INS (element)
                return "SIMD_INS_elt"
            return "SIMD_" + m.get(imm4, "COPY")
        # EXT (byte extract): bit21==0, op[23:22]==00, bit15==0, bit10==0
        if bit(w, 21) == 0 and bits(w, 23, 22) == 0b00 and bit(w, 15) == 0 and bit(w, 10) == 0:
            return "SIMD_EXT"
        # Permute (ZIP/UZP/TRN): bit21==0, bit15==0, bit10==0, op[14:12] selects
        if bit(w, 21) == 0 and bit(w, 15) == 0 and bit(w, 10) == 0:
            opc = bits(w, 14, 12)
            m = {0b001:"UZP1", 0b101:"UZP2", 0b010:"TRN1", 0b110:"TRN2",
                 0b011:"ZIP1", 0b111:"ZIP2"}
            return "SIMD_" + m.get(opc, "PERMUTE")
        # TBL/TBX: bit21==0, op[23:22]==00, bit15==0 handled above; explicit form
        return "SIMD_advsimd"

    # ── AdvSIMD across the 0/2 sub-encodings (TBL/TBX, modified imm, shift-imm) ──
    # These have op[28:24]==01111 or the U/immediate variants (bit24==1).
    if bits(w, 28, 24) == 0b01111 or (bits(w, 27, 24) == 0b1111 and bit(w, 28) == 0):
        # Modified immediate (MOVI/MVNI/FMOV.imm/BIC.imm/ORR.imm):
        #   op[28:19] selects; the giveaway is op[11:10]==01 and bit10 pattern.
        # objdump shows movi/mvni/fmov — bit29 U + cmode disambiguate.
        cmode = bits(w, 15, 12); o2 = bit(w, 11); u = bit(w, 29)
        if bits(w, 23, 19) == 0b00000 and bit(w, 10) == 1:
            if u == 0:
                return "SIMD_MOVI/ORR_imm" if (cmode & 1) == 0 or cmode < 0b1000 else "SIMD_MOVI/FMOV_imm"
            else:
                return "SIMD_MVNI/BIC_imm"
        # Shift-by-immediate (SSHR/USHR/SHL/SLI/SRI/SQSHL/SHRN/USHLL/SXTL...):
        # bit10==1 and immh(op[22:19]) != 0.
        if bit(w, 10) == 1 and bits(w, 22, 19) != 0:
            opc = bits(w, 15, 11); u = bit(w, 29)
            m = {0b00000:"SSHR/USHR", 0b00010:"SSRA/USRA",
                 0b00100:"SRSHR/URSHR", 0b00110:"SRSRA/URSRA",
                 0b01000:"SRI", 0b01010:"SHL/SLI",
                 0b01100:"SQSHLU", 0b01110:"SQSHL/UQSHL",
                 0b10000:"SHRN/SQSHRUN", 0b10001:"RSHRN/SQRSHRUN",
                 0b10010:"SQSHRN/UQSHRN", 0b10011:"SQRSHRN/UQRSHRN",
                 0b10100:"SSHLL/USHLL(SXTL/UXTL)", 0b11100:"SCVTF/UCVTF_fixed",
                 0b11111:"FCVTZS/FCVTZU_fixed"}
            return "SIMD_" + m.get(opc, f"shimm_op{opc:05b}")
        # Vector x element (MUL/MLA/FMUL/SQDMULL by element): bit10==0
        if bit(w, 10) == 0:
            opc = bits(w, 15, 12)
            m = {0b1000:"MUL_elt", 0b0000:"MLA_elt", 0b0100:"MLS_elt",
                 0b1001:"FMUL_elt/FMULX_elt", 0b0001:"FMLA_elt",
                 0b0101:"FMLS_elt", 0b1010:"SMULL_elt/UMULL_elt",
                 0b1011:"SQDMULL_elt", 0b0011:"SQDMLAL_elt",
                 0b0111:"SQDMLSL_elt", 0b1100:"SMLAL_elt/UMLAL_elt",
                 0b1101:"SQDMULH_elt/SQRDMULH_elt"}
            return "SIMD_" + m.get(opc, f"byelt_op{opc:04b}")
        # TBL/TBX explicit: op[23:22]==00, bit15==0, op[13:12] len, bit12 op
        return "SIMD_TBL/TBX"

    # ── Scalar FP (bit28==1): op[31:24] == 0001111x ──
    if b31_24 in (0b00011110, 0b00011111):
        # FP data-processing (2 source) op[15:12], bit21==1, op[11:10]==10
        if bit(w, 21) == 1 and bits(w, 11, 10) == 0b10:
            opc = bits(w, 15, 12)
            m = {0b0000:"FMUL",0b0001:"FDIV",0b0010:"FADD",0b0011:"FSUB",
                 0b0100:"FMAX",0b0101:"FMIN",0b0110:"FMAXNM",0b0111:"FMINNM",
                 0b1000:"FNMUL"}
            return "FP_" + m.get(opc, "2src")
        # FP compare
        if bit(w, 21) == 1 and bits(w, 15, 10) == 0b001000:
            return "FCMP"
        # FP conditional compare
        if bit(w, 21) == 1 and bits(w, 11, 10) == 0b01:
            return "FCCMP"
        # FP conditional select
        if bit(w, 21) == 1 and bits(w, 11, 10) == 0b11:
            return "FCSEL"
        # FP data-processing (1 source)
        if bit(w, 21) == 1 and bits(w, 14, 10) == 0b10000:
            opc = bits(w, 20, 15)
            m = {0b000000:"FMOV",0b000001:"FABS",0b000010:"FNEG",
                 0b000011:"FSQRT",0b000100:"FCVT",0b001000:"FRINTN",
                 0b001001:"FRINTP",0b001010:"FRINTM",0b001011:"FRINTZ",
                 0b001100:"FRINTA",0b001110:"FRINTX",0b001111:"FRINTI"}
            return "FP_" + m.get(opc, "1src")
        # FP immediate (FMOV #imm): op[12:10]==100
        if bit(w, 21) == 1 and bits(w, 12, 10) == 0b100:
            return "FMOV_imm"
        # FP<->int conversions (SCVTF/UCVTF/FCVTZS/FMOV Xd,Dn...): bit21==1, op[11:10]==00
        if bit(w, 21) == 1 and bits(w, 11, 10) == 0b00:
            return "FP_int_cvt"
        return "FP_scalar"

    # ── FP<->int conversions with sf=1 (64-bit GPR forms, bit31 set) ──
    # e.g. FMOV Xd,Dn / SCVTF Dd,Xn / FCVTZS Xd,Dn — op[28:24]==11110, bit21==1,
    # op[15:10]==000000 (scale) or the round-mode/opcode conversion forms.
    if bits(w, 28, 24) == 0b11110 and bit(w, 21) == 1 and bits(w, 15, 10) == 0b000000:
        return "FP_int_cvt"

    # ── AdvSIMD scalar (bit28==1 not FP): scalar three-same / pairwise / shift ──
    if bit(w, 28) == 1 and bits(w, 31, 30) in (0b01, 0b11):
        if bit(w, 21) == 1 and bit(w, 10) == 1:
            opc = bits(w, 15, 11)
            m = {0b10000:"ADD/SUB_s", 0b10001:"CMTST/CMEQ_s",
                 0b00110:"CMGT/CMHI_s", 0b11011:"FMULX_s",
                 0b11100:"FCMEQ/FCMGE_s", 0b11010:"FABD_s"}
            return "SIMD_" + m.get(opc, "scalar3same")
        if bit(w, 21) == 1 and bits(w, 20, 17) == 0b1000:
            return "SIMD_scalar2misc"
        if bit(w, 21) == 1 and bits(w, 20, 17) == 0b1100:
            return "SIMD_scalar_across"
        return "SIMD_scalar"

    return "simd_fp?"


def mnemonic(w):
    """Best-effort mnemonic for a 32-bit ARM64 instruction word."""
    g = top_group(w)
    try:
        if g == "dp_imm":
            return name_dp_imm(w)
        if g == "branch_sys":
            return name_branch_sys(w)
        if g == "dp_reg":
            return name_dp_reg(w)
        if g == "ldst":
            return name_ldst(w)
        if g == "simd_fp":
            return name_simd_fp(w)
    except Exception:
        pass
    return g

def name_ldst(w):
    # Coarse load/store naming for the report.
    op = bits(w, 31, 30)  # size
    v = bit(w, 26)        # SIMD/FP
    # Load/store register (unsigned immediate): op[29:27]=111 op[25:24]=x1
    if bits(w, 29, 27) == 0b111 and bit(w, 24) == 1:
        opc = bits(w, 23, 22)
        ld = opc != 0b00
        return ("LDR" if ld else "STR") + ("_v" if v else "") + "_uimm"
    # Load/store pair: op[29:27]=101
    if bits(w, 29, 27) == 0b101:
        l = bit(w, 22)
        return ("LDP" if l else "STP") + ("_v" if v else "")
    # Load register (literal): op[29:27]=011 bit24=0
    if bits(w, 29, 27) == 0b011 and bit(w, 24) == 0:
        return "LDR_lit"
    # Load/store exclusive: op[29:24]=001000
    if bits(w, 29, 24) == 0b001000:
        return "LDXR/STXR"
    # Atomic memory ops / ldapr etc: op[29:27]=111 bit24=0 bit21=1
    if bits(w, 29, 27) == 0b111 and bit(w, 24) == 0 and bit(w, 21) == 1:
        return "ATOMIC/LDADD"
    # Load/store register (register offset / unscaled / imm pre/post)
    if bits(w, 29, 27) == 0b111 and bit(w, 24) == 0:
        return "LDR/STR_reg_or_unscaled"
    return "LDST_other"


if __name__ == "__main__":
    import sys
    for line in sys.stdin:
        w = int(line.strip(), 16)
        print(f"0x{w:08x} {top_group(w):12} {mnemonic(w)}")
