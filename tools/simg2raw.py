import struct,sys,os
# Android sparse (magic 0xed26ff3a) -> raw. Chunk types: RAW=0xCAC1 FILL=0xCAC2 DONTCARE=0xCAC3 CRC=0xCAC4
def convert(src,dst):
    f=open(src,'rb'); 
    magic,maj,minr,fhs,chs,blk,tblk,tch,crc=struct.unpack('<IHHHHIIII',f.read(28))
    assert magic==0xed26ff3a, "not sparse: %x"%magic
    if fhs>28: f.read(fhs-28)
    out=open(dst,'wb'); written=0
    for _ in range(tch):
        ct,res,csz,tsz=struct.unpack('<HHII',f.read(chs))
        if chs>12: f.read(chs-12)
        n=csz*blk
        if ct==0xCAC1:  # RAW
            out.write(f.read(n)); written+=n
        elif ct==0xCAC2: # FILL
            fill=f.read(4); out.write(fill*(n//4)); written+=n
        elif ct==0xCAC3: # DONT_CARE — write zeros in <=64MiB blocks (avoid OOM)
            rem=n; ZB=b'\0'*(64*1024*1024)
            while rem>0:
                w=min(rem,len(ZB)); out.write(ZB[:w]); rem-=w
            written+=n
        elif ct==0xCAC4: # CRC
            f.read(4)
        else:
            raise SystemExit("bad chunk 0x%x"%ct)
    out.close(); f.close()
    return written
if __name__=="__main__":
    s,d=sys.argv[1],sys.argv[2]
    w=convert(s,d)
    print("%s -> %s  raw=%d bytes (%.1f MB)"%(os.path.basename(s),os.path.basename(d),w,w/1048576))
