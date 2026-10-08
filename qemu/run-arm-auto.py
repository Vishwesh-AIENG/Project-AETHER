#!/usr/bin/env python3
"""Automated AETHER ARM-tier QEMU runner (Windows-friendly; mirrors run-ch34.sh).

Boots target/aarch64-unknown-uefi/release/hypervisor.efi as BOOTAA64.EFI on
QEMU `virt` with EL2 (virtualization=on, GICv3). The hypervisor runs at EL2 and
ERETs into whatever guest payload sits at KERNEL1_PA (0x4080_0000), placed there
by QEMU's loader device. Serial goes to qemu/arm-serial.log.

Usage:
  py -3 qemu/run-arm-auto.py [--kernel PATH] [--initrd PATH] [--timeout SEC]
                             [--until REGEX] [--smmu] [--extra "qemu args"]

Exits when the serial log matches --until, goes quiet for SETTLE_S, or hits
--timeout. Prints the tail of the log and exits 0 if --until matched, else 1.
"""
import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

QEMU_BIN = os.environ.get("QEMU_AARCH64", r"D:\qemu\qemu-system-aarch64.exe")
FW_CODE = os.environ.get("AAVMF", r"D:\qemu\share\edk2-aarch64-code.fd")
EFI_DIR = os.path.join(HERE, "efi")
EFI_BINARY = os.path.join(REPO, "target", "aarch64-unknown-uefi", "release", "hypervisor.efi")
BOOT_PATH = os.path.join(EFI_DIR, "EFI", "BOOT", "BOOTAA64.EFI")
SERIAL_LOG = os.path.join(HERE, "arm-serial.log")
KERNEL1_PA = 0x4080_0000
MON_PORT = 4446
REGS_DUMP = os.path.join(HERE, "arm-regs.txt")
INITRD1_PA = 0x4410_0000  # main.rs INITRD1_PA; EL2 sizes it via cpio::archive_len


def dump_registers() -> None:
    """Stop the VM and save 'info registers -a' (all vCPUs) to qemu/arm-regs.txt."""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", MON_PORT), timeout=10)
        out = b""
        for cmd in (b"stop\n", b"info registers -a\n"):
            s.sendall(cmd)
            time.sleep(2.0)
        s.settimeout(3.0)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        s.close()
        with open(REGS_DUMP, "wb") as f:
            f.write(out)
        print(f"==> vCPU registers saved to {REGS_DUMP} ({len(out)} bytes)")
    except OSError as e:
        print(f"==> register dump failed: {e}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", default=os.path.join(REPO, "Image"))
    ap.add_argument("--initrd", default=None)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--settle", type=float, default=float(os.environ.get("SETTLE_S", "60")))
    ap.add_argument("--until", default=None, help="regex that ends the run successfully")
    ap.add_argument("--smmu", action="store_true", help="virt,iommu=smmuv3")
    ap.add_argument("--smp", type=int, default=1)
    ap.add_argument("--extra", default="")
    ap.add_argument("--dump-on-stop", action="store_true",
                    help="at stop, dump every vCPU's registers via the QEMU monitor")
    a = ap.parse_args()

    os.makedirs(os.path.dirname(BOOT_PATH), exist_ok=True)
    shutil.copyfile(EFI_BINARY, BOOT_PATH)
    if os.path.exists(SERIAL_LOG):
        os.remove(SERIAL_LOG)

    machine = "virt,gic-version=3,virtualization=on"
    if a.smmu:
        machine += ",iommu=smmuv3"
    cmd = [
        QEMU_BIN, "-machine", machine, "-cpu", "max", "-m", "4G", "-smp", str(a.smp),
        "-drive", f"if=pflash,format=raw,readonly=on,file={FW_CODE}",
        "-drive", f"if=none,id=hd0,format=raw,file=fat:rw:{EFI_DIR}",
        "-device", "virtio-blk-pci,drive=hd0,bootindex=0",
        "-device", f"loader,file={a.kernel},addr={KERNEL1_PA:#x},force-raw=on",
        "-serial", f"file:{SERIAL_LOG}", "-display", "none",
        "-monitor", (f"tcp:127.0.0.1:{MON_PORT},server,nowait" if a.dump_on_stop else "none"),
        "-no-reboot",
    ]
    if a.initrd:
        # UEFI boot ignores -initrd; place it where EL2 looks for it.
        cmd += ["-device", f"loader,file={a.initrd},addr={INITRD1_PA:#x},force-raw=on"]
    # QEMU on Windows accepts "/" paths; POSIX shlex would eat "\".
    cmd += shlex.split(a.extra.replace("\\", "/"))
    print("==> " + " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    start = time.time()
    last_sz, last_change = -1, start
    matched = False
    until = re.compile(a.until) if a.until else None
    while True:
        time.sleep(1.0)
        if proc.poll() is not None:
            print(f"==> QEMU exited rc={proc.returncode}")
            break
        sz = os.path.getsize(SERIAL_LOG) if os.path.exists(SERIAL_LOG) else 0
        if sz != last_sz:
            last_sz, last_change = sz, time.time()
            if until and sz:
                with open(SERIAL_LOG, "rb") as f:
                    if until.search(f.read().decode("utf-8", "replace")):
                        matched = True
                        print(f"==> matched --until after {time.time()-start:.1f}s")
                        break
        if time.time() - last_change > a.settle:
            print(f"==> serial quiet {a.settle:.0f}s; stopping")
            break
        if time.time() - start > a.timeout:
            print(f"==> timeout {a.timeout:.0f}s")
            break
    if a.dump_on_stop and proc.poll() is None:
        dump_registers()
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    out = proc.stdout.read().decode("utf-8", "replace") if proc.stdout else ""
    if out.strip():
        print("==> qemu stdout/stderr:\n" + out.strip()[-2000:])
    if os.path.exists(SERIAL_LOG):
        with open(SERIAL_LOG, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        print(f"==> serial log {len(text)} bytes; tail:")
        print("\n".join(text.splitlines()[-40:]))
    return 0 if matched else 1


if __name__ == "__main__":
    sys.exit(main())
