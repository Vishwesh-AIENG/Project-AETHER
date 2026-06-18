#!/usr/bin/env python3
"""Disassemble /init (_init.elf) at a VA, mapping VA->file offset via PT_LOAD.
Usage: python tools/dinit.py <hexVA> [count]"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

data = open('_init.elf', 'rb').read()
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]
entry = struct.unpack_from('<Q', data, 0x18)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from('<QQQQQ', data, off + 8)
    if p_type == 1:
        segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))


def va2off(va):
    for vaddr, off, filesz, memsz, fl in segs:
        if vaddr <= va < vaddr + memsz:
            if va < vaddr + filesz:
                return off + (va - vaddr), 'file', fl
            return None, 'bss', fl
    return None, 'none', 0


if __name__ == '__main__':
    print(f"entry=0x{entry:x}")
    for vaddr, off, filesz, memsz, fl in segs:
        print(f"PT_LOAD va=0x{vaddr:x} off=0x{off:x} filesz=0x{filesz:x} memsz=0x{memsz:x} flags={fl}")
    va = int(sys.argv[1], 16)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    o, kind, fl = va2off(va)
    print(f"VA 0x{va:x} -> {kind} (off={hex(o) if o else o}) segflags={fl}")
    if o is None:
        sys.exit(0)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    start = va - 0x28
    so, _, _ = va2off(start)
    code = data[so:so + (n + 10) * 4]
    for ins in md.disasm(code, start):
        if ins.address >= va + n * 4:
            break
        mark = '  <== FAULT PC' if ins.address == va else ''
        raw = struct.unpack_from('<I', code, ins.address - start)[0]
        print(f"0x{ins.address:x}  {raw:08x}  {ins.mnemonic}\t{ins.op_str}{mark}")
