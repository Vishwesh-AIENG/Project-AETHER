#!/usr/bin/env python3
"""Find build_sched_domains+0x15d8 by scanning the kernel Image for
the 'detected buffer overflow in %s' string -> fortify_panic xref
-> BL fortify_panic call sites -> the one near a long function whose
end is 0x15ec.

Also locates build_sched_domains by tracing back from each fortify_panic
call site to its enclosing function (heuristic: function starts with
`stp x29, x30, [sp, #-N]!` or `paciasp`/`bti`).
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# ARM64 Image header at offset 0:
#  +0  branch instruction (code_0)
#  +4  branch instruction (code_1)
#  +8  text_offset (u64 LE)
#  +16 image_size  (u64 LE)
#  +24 flags       (u64 LE)
#  +56 magic       'ARM\x64' = 0x644D5241
KERNEL_VA_BASE = 0xffffffc008000000  # Boot-observed; vbar=0xffffffc008010800

def load(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())

def find_fortify_panic_msg(img):
    """Find offset of 'detected buffer overflow in %s' or similar."""
    for needle in (b"detected buffer overflow in %s",
                   b"detected buffer overflow in",
                   b"detected write beyond size",
                   b"buffer overflow"):
        idx = img.find(needle)
        if idx >= 0:
            return idx, needle
    return -1, None

def find_adrp_add_xrefs(img, target_va):
    """Find all PCs where adrp+add (or adrp+ldr-immediate) materialize
    the VA `target_va`."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    refs = []
    n = len(img)
    # Walk 4-byte instructions; check pairs adrp+add
    for off in range(0, n - 8, 4):
        w0 = struct.unpack('<I', img[off:off+4])[0]
        # adrp opcode: 1 ii 10000 immhi19 ddddd, top byte = 1xx10000
        if (w0 >> 24) & 0x9f != 0x90:
            continue
        for j in (4, 8, 12, 16):
            if off + j + 4 > n: break
            w1 = struct.unpack('<I', img[off+j:off+j+4])[0]
            # add Xd, Xn, #imm12: sf=1, 0010001 0 shift(2) imm12 Rn Rd
            if (w1 >> 22) & 0x3ff != 0x244:
                continue
            try:
                pc_a = KERNEL_VA_BASE + off
                pc_b = KERNEL_VA_BASE + off + j
                ins_a = next(md.disasm(img[off:off+4], pc_a))
                ins_b = next(md.disasm(img[off+j:off+j+4], pc_b))
            except StopIteration:
                continue
            if ins_a.mnemonic != 'adrp' or ins_b.mnemonic != 'add':
                continue
            # parse: adrp Xd, #target
            try:
                tgt_s = ins_a.op_str.split(', ')[1].lstrip('#')
                target_adrp = int(tgt_s, 0)
            except (ValueError, IndexError):
                continue
            # parse add: "Xd, Xn, #imm"
            ops = ins_b.op_str.split(', ')
            if len(ops) != 3:
                continue
            imm_s = ops[2].lstrip('#').split(' ')[0]  # drop any 'lsl'
            try:
                imm = int(imm_s, 0)
            except ValueError:
                continue
            final = target_adrp + imm
            if final == target_va:
                refs.append((pc_a, pc_b, final))
    return refs

def disasm_at(img, pc_start, n_insns):
    off = pc_start - KERNEL_VA_BASE
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for ins in md.disasm(bytes(img[off:off + n_insns*4]), pc_start):
        out.append(ins)
    return out

def find_function_start(img, pc):
    """Walk backward from pc to find function start (stp x29, x30, ...!
    or paciasp)."""
    off = pc - KERNEL_VA_BASE
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for back in range(0, 0x4000, 4):
        if off - back < 0: break
        b = bytes(img[off - back:off - back + 4])
        try:
            ins = next(md.disasm(b, pc - back))
        except StopIteration:
            continue
        if ins.mnemonic == 'paciasp':
            return pc - back
        if ins.mnemonic == 'stp':
            # stp x29, x30, [sp, #-N]! is the canonical AAPCS prologue
            if 'x29, x30' in ins.op_str and 'sp,' in ins.op_str and '!' in ins.op_str:
                return pc - back
    return None

def find_bl_targets_to(img, target_va):
    """All PCs of BL ins that branch to target_va."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    refs = []
    n = len(img)
    for off in range(0, n - 4, 4):
        w = struct.unpack('<I', img[off:off+4])[0]
        if (w >> 26) != 0x25:  # BL = 100101
            continue
        imm26 = w & 0x3ffffff
        # sign extend 26 bits
        if imm26 & (1 << 25):
            imm26 |= ~((1 << 26) - 1)
        delta = imm26 * 4
        pc = KERNEL_VA_BASE + off
        if pc + delta == target_va:
            refs.append(pc)
    return refs

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'Image'
    img = load(path)
    print(f'[+] Loaded {path} size={len(img)}')

    # Validate ARM64 magic
    if struct.unpack('<I', img[56:60])[0] != 0x644D5241:
        print('[-] Not an ARM64 Image (magic mismatch)')
        return 1

    text_off = struct.unpack('<Q', img[8:16])[0]
    img_size = struct.unpack('<Q', img[16:24])[0]
    print(f'[+] text_offset={hex(text_off)} image_size={hex(img_size)}')

    # Find fortify message
    msg_off, msg = find_fortify_panic_msg(img)
    if msg_off < 0:
        print('[-] No fortify_panic message string found')
        return 1
    msg_va = KERNEL_VA_BASE + msg_off
    print(f'[+] fortify msg "{msg.decode()}" at VA={hex(msg_va)} off={hex(msg_off)}')
    # The printk format string includes a 2-byte LOGLEVEL prefix
    # ("\x01" + '0'), placed 2 bytes before the printable text.
    fmt_va = msg_va - 2
    print(f'[+] Format-string VA (with KERN_EMERG prefix) = {hex(fmt_va)}')

    # Find adrp+add xrefs to this msg VA (page-aligned)
    page = fmt_va & ~0xfff
    print(f'[+] Searching adrp+add xrefs to page {hex(page)} ...')
    refs = find_adrp_add_xrefs(img, fmt_va)
    print(f'[+] {len(refs)} adrp+add xrefs target msg VA')
    for r in refs[:8]:
        print(f'      adrp@{hex(r[0])} add@{hex(r[1])} -> {hex(r[2])}')

    if not refs:
        print('[-] No adrp+add xref — fortify_panic is unreachable in scan')
        return 1

    # The first xref's containing function is fortify_panic.
    # Walk forward from the adrp to find BL <fn>; the fn is fortify_panic.
    # Actually — adrp+add usually appears INSIDE fortify_panic itself
    # (it loads the format string before calling panic). The function
    # containing the adrp is fortify_panic.
    candidate_pc = refs[0][0]
    fn_start = find_function_start(img, candidate_pc)
    if fn_start is None:
        # try other refs
        for r in refs:
            fn_start = find_function_start(img, r[0])
            if fn_start:
                candidate_pc = r[0]
                break
    if fn_start is None:
        print('[-] Could not find function start near msg xref')
        return 1
    print(f'[+] fortify_panic candidate start = {hex(fn_start)}')

    # Disasm around fortify_panic
    print('[+] fortify_panic disasm:')
    for ins in disasm_at(img, fn_start, 12):
        print(f'      {hex(ins.address):>14}: {ins.mnemonic:8} {ins.op_str}')

    # Now find all BL fn_start callsites
    bls = find_bl_targets_to(img, fn_start)
    print(f'[+] {len(bls)} BL sites target fortify_panic')

    # For each BL site, find enclosing function start. The one whose
    # offset (bl_pc - fn_start) is 0x15d8 OR whose end is at 0x15ec is
    # build_sched_domains.
    print('[+] Per-callsite analysis (looking for offset=0x15d8 in caller):')
    for bl_pc in bls:
        caller_start = find_function_start(img, bl_pc)
        if caller_start is None:
            continue
        off_in_caller = bl_pc - caller_start
        marker = ''
        if off_in_caller == 0x15d8:
            marker = '  <-- build_sched_domains MATCH'
        print(f'      bl@{hex(bl_pc)}  caller_start={hex(caller_start)}  off={hex(off_in_caller)}{marker}')

    # Pick the match
    for bl_pc in bls:
        caller_start = find_function_start(img, bl_pc)
        if caller_start is None: continue
        if bl_pc - caller_start == 0x15d8:
            print()
            print(f'[+] build_sched_domains @ {hex(caller_start)}')
            print(f'[+] Disasm at +0x15c0..+0x15ec (32 insns ending at fortify_panic BL):')
            for ins in disasm_at(img, caller_start + 0x15c0, 32):
                tag = '  <-- BL fortify_panic' if ins.address == bl_pc else ''
                print(f'      {hex(ins.address):>14}: {ins.mnemonic:8} {ins.op_str}{tag}')
            print()
            print(f'[+] Wider disasm of +0x1590..+0x15ec (47 insns) to find the memset call/compare path:')
            for ins in disasm_at(img, caller_start + 0x1590, 47):
                tag = '  <-- BL fortify_panic' if ins.address == bl_pc else ''
                print(f'      {hex(ins.address):>14}: {ins.mnemonic:8} {ins.op_str}{tag}')
            break

    return 0

if __name__ == '__main__':
    raise SystemExit(main())
