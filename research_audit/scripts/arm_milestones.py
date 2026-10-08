#!/usr/bin/env python3
"""Time-stamp ARM-tier boot milestones from the serial port (host wall clock).

Two configurations, same QEMU binary / kernel / initramfs / -smp:
  aether : AAVMF -> hypervisor.efi at EL2 -> ERET -> GKI 6.1 -> proof /bin/sh
           (QEMU command identical to qemu/run-arm-auto.py)
  direct : QEMU direct kernel boot (-kernel/-initrd), no firmware, no EL2
           hypervisor; same cmdline as AETHER's DTB (console=ttyAMA0 earlycon
           rdinit=/bin/sh). Baseline for "what does the AETHER layer cost
           under emulation" -- NOT a hardware measurement.

Usage: python3 -I arm_milestones.py <aether-tree> <out-dir> <mode> <smp> <runs>
Env:   QEMU_AARCH64 (default qemu-system-aarch64), AAVMF (firmware code .fd)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

MILESTONES = [
    ("aether_start", rb"AETHER Hypervisor starting"),
    ("el2_detected", rb"EL2 detected"),
    ("stage2_ok", rb"Stage 2 tables: OK"),
    ("hyp_ready", rb"Hypervisor ready\."),
    ("eret_to_el1", rb"ERET to Linux kernel EL1"),
    ("kernel_entry", rb"Booting Linux on physical CPU"),
    ("smp_up", rb"SMP: Total of \d+ processors activated"),
    ("free_initmem", rb"Freeing unused kernel memory"),
    ("userspace", rb"PROOF ch34 userspace=1"),
    ("online_cpus", rb"PROOF ch35 online_cpus=\d+"),
    ("proof_done", rb"PROOF done"),
]


def run_once(tree, out, mode, smp, idx):
    qemu = os.environ.get("QEMU_AARCH64", "qemu-system-aarch64")
    fw = os.environ.get("AAVMF", "/usr/share/AAVMF/AAVMF_CODE.fd")
    kernel = os.path.join(tree, "_kernel_new")
    initrd = os.path.join(tree, "qemu", "initrd-proof.cpio")
    serial = os.path.join(out, f"arm_{mode}_smp{smp}_run{idx}.serial.log")
    if os.path.exists(serial):
        os.remove(serial)
    if mode == "aether":
        efidir = os.path.join(out, "_efi")
        os.makedirs(os.path.join(efidir, "EFI", "BOOT"), exist_ok=True)
        shutil.copyfile(os.path.join(tree, "target", "aarch64-unknown-uefi", "release", "hypervisor.efi"),
                        os.path.join(efidir, "EFI", "BOOT", "BOOTAA64.EFI"))
        cmd = [qemu, "-machine", "virt,gic-version=3,virtualization=on", "-cpu", "max", "-m", "4G",
               "-smp", str(smp), "-drive", f"if=pflash,format=raw,readonly=on,file={fw}",
               "-drive", f"if=none,id=hd0,format=raw,file=fat:rw:{efidir}",
               "-device", "virtio-blk-pci,drive=hd0,bootindex=0",
               "-device", f"loader,file={kernel},addr=0x40800000,force-raw=on",
               "-device", f"loader,file={initrd},addr=0x44100000,force-raw=on",
               "-serial", f"file:{serial}", "-display", "none", "-monitor", "none", "-no-reboot"]
    else:
        cmd = [qemu, "-machine", "virt,gic-version=3", "-cpu", "max", "-m", "2G", "-smp", str(smp),
               "-kernel", kernel, "-initrd", initrd,
               "-append", "console=ttyAMA0 earlycon rdinit=/bin/sh",
               "-serial", f"file:{serial}", "-display", "none", "-monitor", "none", "-no-reboot"]
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    seen = {}
    while time.monotonic() - t0 < 300:
        time.sleep(0.05)
        try:
            data = open(serial, "rb").read()
        except FileNotFoundError:
            continue
        for name, rx in MILESTONES:
            if name not in seen and re.search(rx, data):
                seen[name] = round(time.monotonic() - t0, 3)
        if "proof_done" in seen or p.poll() is not None:
            break
    p.kill()
    p.wait()
    seen["_cmd"] = " ".join(cmd)
    return seen


def main():
    tree, out, mode, smp, runs = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
    os.makedirs(out, exist_ok=True)
    res = [run_once(tree, out, mode, smp, i) for i in range(runs)]
    path = os.path.join(out, f"arm_{mode}_smp{smp}.json")
    json.dump(res, open(path, "w"), indent=1)
    names = [n for n, _ in MILESTONES]
    print(f"mode={mode} smp={smp} runs={runs}")
    for n in names:
        xs = sorted(r[n] for r in res if n in r)
        if xs:
            med = xs[len(xs) // 2] if len(xs) % 2 else (xs[len(xs) // 2 - 1] + xs[len(xs) // 2]) / 2
            print(f"  {n:14s} reached {len(xs)}/{runs}  median={med:7.3f}s  min={xs[0]:7.3f}  max={xs[-1]:7.3f}")
        else:
            print(f"  {n:14s} reached 0/{runs}")


if __name__ == "__main__":
    main()
