#!/usr/bin/env python3
"""Decode the [el0flt-W]/[el0flt-blk] capture from com1.log.

Disassembles the 32-word faulting block and, using the captured GPR file,
flags the load/store whose computed effective address matches the fatal FAR
(default 0x7ce8274c08) — that is the crashing instruction (init or keystore2).

capstone is used when available for full disassembly. When capstone is NOT
installed (no pip/network), a minimal inline ARM64 decoder handles just the
load/store family (LDR/STR/LDP/STP imm + reg-offset, LDRB/STRB/LDRH/STRH,
LDR-literal) so the faulting instruction can still be flagged by matching its
computed effective address against FAR. Non-load/store words print as raw
hex + "(?)".

Usage:  python3 tools/el0flt_decode.py <com1.log> <FAR-hex>
"""
import re, sys

try:
    import capstone
    HAVE_CAPSTONE = True
except Exception:
    capstone = None
    HAVE_CAPSTONE = False

LOG = sys.argv[1] if len(sys.argv) > 1 else r"D:\AETHER\qemu\com1.log"
FAR = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x7ce8274c08

txt = open(LOG, "r", errors="ignore").read()

# --- registers (last [el0flt-W] block) ---
regs = {}
for m in re.finditer(r"\[el0flt-W\] x0x0*([0-9a-f]+)=0x([0-9a-f]+)", txt):
    regs[int(m.group(1), 16)] = int(m.group(2), 16)
pcm = re.findall(r"\[el0flt-W\] pc=0x([0-9a-f]+) lgpc=0x([0-9a-f]+) oppc=0x([0-9a-f]+) insn=0x([0-9a-f]+)", txt)
oppc = int(pcm[-1][2], 16) if pcm else 0   # EXACT faulting instruction PC
pc = oppc - 0x10 if oppc else 0            # block window starts 4 insns before

# --- 32-word block ---
words = {}
for m in re.finditer(r"\[el0flt-blk\] \+0x([0-9a-f]+)=0x([0-9a-f]+)", txt):
    words[int(m.group(1), 16)] = int(m.group(2), 16) & 0xFFFFFFFF
if not words:
    print("no [el0flt-blk] lines found in", LOG)
    print("(the EL0FLT re-fault latch may not have fired yet -- check that the")
    print(" guest re-faulted >= threshold times at the same PC+FAR.)")
    sys.exit(0)

print(f"block PC = 0x{pc:x}   FAR = 0x{FAR:x}"
      + ("" if HAVE_CAPSTONE else "   [capstone unavailable: inline decoder]"))
print("GPRs:")
for r in range(31):
    v = regs.get(r, 0)
    tag = ""
    if (v >> 56) == 0xb4:
        tag = " (Scudo-tagged)"
    print(f"  x{r:<2} = 0x{v:016x}{tag}")

untag = lambda v: v & 0x00FF_FFFF_FFFF_FFFF


def reg_val(n, is_sp_ctx=False):
    """Resolve register number n to its captured 64-bit value.
    n==31 means SP (we don't capture SP, so report 0) unless context says XZR."""
    if n == 31:
        return 0
    return regs.get(n, 0)


def sext(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


# ---------------------------------------------------------------------------
# Minimal inline ARM64 load/store decoder (used when capstone is absent).
# Returns (mnemonic, op_str, ea_or_None) for the load/store family only; for
# anything else returns ("(?)", raw_hex, None).
# ---------------------------------------------------------------------------
def decode_ldst(word, addr):
    w = word & 0xFFFFFFFF

    def rn_name(n, sf=1):
        if n == 31:
            return "sp"
        return ("x" if sf else "w") + str(n)

    # LDR/STR (immediate, unsigned offset)  size|111|0|01|opc|imm12|Rn|Rt
    #   bits[31:30]=size, [29:27]=111, [26]=V(0=GPR), [25:24]=01, [23:22]=opc,
    #   [21:10]=imm12, [9:5]=Rn, [4:0]=Rt
    if (w >> 27) & 0b111 == 0b111 and ((w >> 24) & 0b11) == 0b01 and ((w >> 26) & 1) == 0:
        size = (w >> 30) & 0b11
        opc = (w >> 22) & 0b11
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        scale = size
        disp = imm12 << scale
        nbytes = 1 << size
        is_load = (opc & 1) == 1
        # opc==0b10 with size<3 => signed load (LDRSW/LDRSB/LDRSH); still a load
        mn = {0: ("strb", "ldrb"), 1: ("strh", "ldrh"),
              2: ("str", "ldr"), 3: ("str", "ldr")}[size][1 if is_load else 0]
        if opc == 0b10 and size != 0b11:
            mn = {0: "ldrsb", 1: "ldrsh", 2: "ldrsw"}.get(size, "ldrs")
        sf = 1 if size == 0b11 or opc == 0b10 else 0
        base = reg_val(rn)
        ea = untag(base) + disp
        ops = f"{rn_name(rt, sf)}, [{rn_name(rn)}, #{disp}]"
        return (mn, ops, ea, nbytes)

    # LDR/STR (register offset)  size|111|0|00|opc|1|Rm|option|S|10|Rn|Rt
    #   [31:30]=size [29:27]=111 [26]=V [25:24]=00 [23:22]=opc [21]=1
    #   [20:16]=Rm [15:13]=option [12]=S [11:10]=10 [9:5]=Rn [4:0]=Rt
    if ((w >> 27) & 0b111 == 0b111 and ((w >> 24) & 0b11) == 0b00
            and ((w >> 26) & 1) == 0 and ((w >> 21) & 1) == 1
            and ((w >> 10) & 0b11) == 0b10):
        size = (w >> 30) & 0b11
        opc = (w >> 22) & 0b11
        rm = (w >> 16) & 0x1F
        option = (w >> 13) & 0b111
        s = (w >> 12) & 1
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        is_load = (opc & 1) == 1
        mn = {0: ("strb", "ldrb"), 1: ("strh", "ldrh"),
              2: ("str", "ldr"), 3: ("str", "ldr")}[size][1 if is_load else 0]
        if opc == 0b10 and size != 0b11:
            mn = {0: "ldrsb", 1: "ldrsh", 2: "ldrsw"}.get(size, "ldrs")
        sf = 1 if size == 0b11 or opc == 0b10 else 0
        base = reg_val(rn)
        idx = reg_val(rm)
        # option: 011=LSL/UXTX (64-bit), 010=UXTW, 110=SXTW, 111=SXTX
        if option in (0b010, 0b110):  # 32-bit index
            idx &= 0xFFFFFFFF
            if option == 0b110:
                idx = sext(idx, 32) & 0xFFFFFFFFFFFFFFFF
        shift = size if s else 0
        ea = untag(base) + ((idx << shift) & 0xFFFFFFFFFFFFFFFF)
        nbytes = 1 << size
        extname = {0b010: "uxtw", 0b011: "lsl", 0b110: "sxtw", 0b111: "sxtx"}.get(option, "lsl")
        ops = f"{rn_name(rt, sf)}, [{rn_name(rn)}, {rn_name(rm)}, {extname} #{shift}]"
        return (mn, ops, ea, nbytes)

    # LDP/STP (signed offset)  opc|101|0|010|L|imm7|Rt2|Rn|Rt
    #   [31:30]=opc [29:27]=101 [26]=V [25:23]=010 [22]=L [21:15]=imm7
    #   [14:10]=Rt2 [9:5]=Rn [4:0]=Rt
    if ((w >> 27) & 0b111 == 0b101 and ((w >> 26) & 1) == 0
            and ((w >> 23) & 0b111) == 0b010):
        opc = (w >> 30) & 0b11
        is_load = (w >> 22) & 1
        imm7 = (w >> 15) & 0x7F
        rt2 = (w >> 10) & 0x1F
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        sf = 1 if opc == 0b10 else 0
        scale = 3 if opc == 0b10 else 2
        disp = sext(imm7, 7) << scale
        base = reg_val(rn)
        ea = (untag(base) + disp) & 0xFFFFFFFFFFFFFFFF
        nbytes = (1 << scale) * 2
        mn = "ldp" if is_load else "stp"
        ops = f"{rn_name(rt, sf)}, {rn_name(rt2, sf)}, [{rn_name(rn)}, #{disp}]"
        return (mn, ops, ea, nbytes)

    # LDR (literal)  opc|011|0|00|imm19|Rt
    #   [31:30]=opc [29:27]=011 [26]=V [25:24]=00 [23:5]=imm19 [4:0]=Rt
    if ((w >> 27) & 0b111 == 0b011 and ((w >> 24) & 0b11) == 0b00
            and ((w >> 26) & 1) == 0):
        opc = (w >> 30) & 0b11
        imm19 = (w >> 5) & 0x7FFFF
        rt = w & 0x1F
        off = sext(imm19, 19) << 2
        ea = (addr + off) & 0xFFFFFFFFFFFFFFFF
        sf = 1 if opc == 0b01 else 0
        nbytes = 8 if opc == 0b01 else 4
        ops = f"{rn_name(rt, sf)}, 0x{ea:x}"
        return ("ldr", ops, ea, nbytes)

    return ("(?)", f"0x{w:08x}", None, 0)


print("\n--- disassembly ---")
blob = b"".join(words[o].to_bytes(4, "little") for o in sorted(words))
base = pc

if HAVE_CAPSTONE:
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for ins in md.disasm(blob, base):
        marker = "  <<< FAULTING INSN" if ins.address == oppc else ""
        line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}{marker}"
        if ins.mnemonic.startswith(("ldr", "ldp", "str", "stp", "ldur", "stur",
                                    "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "prfm")):
            try:
                for op in ins.operands:
                    if op.type == capstone.arm64.ARM64_OP_MEM:
                        bn = ins.reg_name(op.mem.base) if op.mem.base else None
                        bv = 0
                        if bn:
                            rn = bn.replace("x", "").replace("w", "").replace("sp", "31")
                            bv = regs.get(int(rn), 0) if rn.isdigit() else 0
                        ea = untag(bv) + op.mem.disp
                        hit = " <<< MATCHES FAR" if untag(ea) == FAR or ea == FAR else ""
                        line += f"   ; EA=0x{untag(ea):x} (base {bn}=0x{bv:x}, disp {op.mem.disp}){hit}"
            except Exception as e:
                line += f"  ;(ea calc err {e})"
        print(line)
else:
    for i, off in enumerate(sorted(words)):
        addr = base + i * 4
        word = words[off]
        mn, ops, ea, _ = decode_ldst(word, addr)
        marker = "  <<< FAULTING INSN" if addr == oppc else ""
        line = f"  0x{addr:x}: {mn:8} {ops}{marker}"
        if ea is not None:
            hit = " <<< MATCHES FAR" if untag(ea) == FAR or ea == FAR else ""
            line += f"   ; EA=0x{untag(ea):x}{hit}"
        print(line)
    print("\n(capstone not installed: only load/store family decoded; '(?)' = raw word.)")
