#!/usr/bin/env python3
"""Read NUL-terminated strings from _init.elf at given VAs (PT_LOAD va=0x200000 off=0)."""
import sys
data = open('_init.elf', 'rb').read()
for a in sys.argv[1:]:
    va = int(a, 16)
    off = va - 0x200000
    try:
        end = data.index(b'\x00', off)
        print(f"0x{va:x}: {data[off:end].decode('latin1')!r}")
    except Exception as e:
        print(f"0x{va:x}: <err {e}>")
