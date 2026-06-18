#!/usr/bin/env python3
"""Repack an Android boot.img (v3/v4) with a new kernel Image, keeping the
existing ramdisk + header cmdline. AVB signature is dropped (AETHER bypasses
verified boot for the QEMU bring-up; prepare_android_handoff locates the kernel
and ramdisk purely from the header's kernel_size/ramdisk_size at page offsets).

Usage:
  python tools/repack_bootimg.py <in_boot.img> <new_Image> <out_boot.img> [pad_to_bytes]
"""
import struct
import sys

PAGE = 4096


def roundup(x, a):
    return (x + a - 1) // a * a


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    in_img, new_kernel, out_img = sys.argv[1], sys.argv[2], sys.argv[3]
    pad_to = int(sys.argv[4]) if len(sys.argv) > 4 else None

    d = bytearray(open(in_img, "rb").read())
    assert d[:8] == b"ANDROID!", "not an Android boot image"
    old_ks, old_rs, osv, hsz = struct.unpack("<IIII", d[8:24])
    hv = struct.unpack("<I", d[40:44])[0]
    print(f"in: v{hv} kernel_size={old_ks} ramdisk_size={old_rs} header_size={hsz}")

    # Section offsets (v3/v4: fixed 4096 page size; header occupies page 0).
    old_k_off = PAGE
    old_r_off = old_k_off + roundup(old_ks, PAGE)
    ramdisk = bytes(d[old_r_off:old_r_off + old_rs])
    assert len(ramdisk) == old_rs, "truncated ramdisk in source image"

    new_kernel_bytes = open(new_kernel, "rb").read()
    new_ks = len(new_kernel_bytes)

    # Rebuild: page0 header (with kernel_size patched), then kernel, then ramdisk.
    header = bytearray(d[:PAGE])
    struct.pack_into("<I", header, 8, new_ks)        # kernel_size
    struct.pack_into("<I", header, 12, old_rs)       # ramdisk_size (unchanged)
    # v4 signature section is dropped — zero signature_size at header offset 1580.
    if hv >= 4 and hsz >= 1584:
        struct.pack_into("<I", header, 1580, 0)

    out = bytearray()
    out += header
    out += new_kernel_bytes
    out += b"\x00" * (roundup(len(out), PAGE) - len(out))
    r_off = len(out)
    out += ramdisk
    out += b"\x00" * (roundup(len(out), PAGE) - len(out))

    if pad_to:
        if len(out) > pad_to:
            print(f"WARNING: repacked size {len(out)} exceeds pad_to {pad_to}")
        else:
            out += b"\x00" * (pad_to - len(out))

    open(out_img, "wb").write(out)
    print(f"out: kernel@{PAGE} ({new_ks} B), ramdisk@{r_off} ({old_rs} B), "
          f"total={len(out)} -> {out_img}")


if __name__ == "__main__":
    main()
