#!/usr/bin/env python3
"""Disassemble kernel VAs from the decompressed ./Image.
Usage: python tools/dva.py <hexVA> [count]   # disasm count insns at VA
       python tools/dva.py word <hexword> [hexVA]  # decode a single 32-bit word
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
BASE=0xffffffc008000000
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def img():
    return open('Image','rb').read()
def vahex(s): return int(s,16)
if sys.argv[1]=='word':
    w=int(sys.argv[2],16); va=int(sys.argv[3],16) if len(sys.argv)>3 else 0
    code=struct.pack('<I',w)
    for i in md.disasm(code, va):
        print(f"{i.address:#018x}  {w:08x}  {i.mnemonic}\t{i.op_str}")
    sys.exit(0)
va=vahex(sys.argv[1]); n=int(sys.argv[2]) if len(sys.argv)>2 else 16
off=va-BASE
data=img()[off:off+n*4]
for i in md.disasm(data, va):
    raw=struct.unpack('<I', data[i.address-va:i.address-va+4])[0]
    print(f"{i.address:#018x}  {raw:08x}  {i.mnemonic}\t{i.op_str}")
