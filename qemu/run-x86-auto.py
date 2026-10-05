#!/usr/bin/env python3
"""Automated AETHER x86 hypervisor QEMU runner for the build->run->screenshot->read loop.

Launches QEMU with:
  - COM1 serial  -> qemu/com1.log
  - QMP monitor  -> TCP 127.0.0.1:4445 (drive screendump + quit)
  - VGA std framebuffer

Waits for the serial log to settle (no growth for SETTLE_S) or HARD_TIMEOUT,
then takes a framebuffer screenshot (PPM -> PNG) and quits QEMU cleanly.

Usage:
  python qemu/run-x86-auto.py [--boot-img PATH] [--timeout SEC]

Outputs:
  qemu/com1.log      serial trace
  qemu/screen.png    framebuffer screenshot (for the Read tool)
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

QEMU_BIN = os.environ.get("QEMU_BIN", r"D:\qemu\qemu-system-x86_64.exe")
OVMF = os.environ.get("OVMF", r"D:\qemu\share\edk2-x86_64-code.fd")
EFI_DIR = os.path.join(HERE, "efi-x86")
EFI_BINARY = os.path.join(REPO, "target", "x86_64-unknown-uefi", "release", "hypervisor.efi")
BOOT_PATH = os.path.join(EFI_DIR, "EFI", "BOOT", "BOOTX64.EFI")
SERIAL_LOG = os.path.join(HERE, "com1.log")
SCREEN_PPM = os.path.join(HERE, "screen.ppm")
SCREEN_PNG = os.path.join(HERE, "screen.png")
QMP_PORT = 4445

SETTLE_S = float(os.environ.get("SETTLE_S", "4.0"))   # serial quiet => "done"
HARD_TIMEOUT = float(os.environ.get("HARD_TIMEOUT", "45.0"))  # absolute cap
POLL = 0.5


def stage_binary():
    os.makedirs(os.path.dirname(BOOT_PATH), exist_ok=True)
    import shutil
    shutil.copyfile(EFI_BINARY, BOOT_PATH)
    if os.path.exists(SERIAL_LOG):
        os.remove(SERIAL_LOG)


def qmp(sock, cmd, **args):
    obj = {"execute": cmd}
    if args:
        obj["arguments"] = args
    sock.sendall((json.dumps(obj) + "\r\n").encode())
    # read one reply line
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace")


def ppm_to_png(ppm_path, png_path):
    with open(ppm_path, "rb") as f:
        data = f.read()
    # Parse binary PPM (P6)
    if not data.startswith(b"P6"):
        return False
    idx = 2
    fields = []
    while len(fields) < 3:
        # skip whitespace/comments
        while idx < len(data) and data[idx:idx+1].isspace():
            idx += 1
        if data[idx:idx+1] == b"#":
            while idx < len(data) and data[idx:idx+1] != b"\n":
                idx += 1
            continue
        start = idx
        while idx < len(data) and not data[idx:idx+1].isspace():
            idx += 1
        fields.append(int(data[start:idx]))
    width, height, maxval = fields
    idx += 1  # single whitespace after maxval
    pixels = data[idx:idx + width * height * 3]
    # Build PNG
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)  # filter type none
        raw.extend(pixels[y * stride:(y + 1) * stride])
    def chunk(typ, payload):
        c = struct.pack(">I", len(payload)) + typ + payload
        c += struct.pack(">I", zlib.crc32(typ + payload) & 0xffffffff)
        return c
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 6)
    with open(png_path, "wb") as f:
        f.write(sig)
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))
    return True


def main():
    boot_img = None
    timeout = HARD_TIMEOUT
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--boot-img":
            boot_img = args[i + 1]; i += 2
        elif args[i] == "--timeout":
            timeout = float(args[i + 1]); i += 2
        else:
            i += 1

    stage_binary()

    # Default 16G: the translator JIT cache lives at PA 0x2_0000_0000 (8 GiB)
    # and the bump arena at 0x2_0100_0000. With less than ~10 GiB QEMU has
    # nothing backing those PAs and the JIT path silently corrupts staged
    # kernel bytes (seen as iter-1 insn=0 UD2). Override via MEM=… if needed.
    mem = os.environ.get("MEM", "16G")
    # WHPX=1 selects Windows Hypervisor Platform hardware acceleration instead of
    # TCG software emulation. Requires the AETHER hypervisor.efi built with the
    # `whpx_hostmode` Cargo feature (skips VMXON so no nested VMX is needed — WHPX
    # does not expose it). ~10-100x faster than TCG; the only realistic way to
    # drive the Android boot to the display gate. -cpu host (TCG uses -cpu max).
    if os.environ.get("WHPX"):
        # kernel-irqchip=off is REQUIRED for WHPX (split irqchip unsupported).
        accel = "whpx,kernel-irqchip=off"
        # VMX-less explicit model (NOT -cpu host). Root cause of the prior OVMF
        # #GP: with -cpu host under WHPX, QEMU's forced-nested injects VMX into
        # guest CPUID; OVMF's PlatformPei then programs IA32_FEATURE_CONTROL
        # (MSR 0x3A), and WHPX #GPs that wrmsr (no WRMSR permission — QEMU #2461).
        # A named model carries no vmx/svm unless +vmx is added -> no VMX in
        # CPUID -> OVMF never programs FEATURE_CONTROL -> no #GP. Under WHPX the
        # guest executes on the real Ryzen, so the DBT's SSE4.1/SSSE3/LZCNT/AES
        # (no AVX) run natively regardless of the model's advertised flags.
        # hv_* enlightenments prevent OVMF rdmsr #GPs; enforce=off stops QEMU
        # aborting if WHPX can't provide a model feature. Proven WHPX+OVMF combo
        # (FreeBSD-on-WHPX). Override the model via WHPX_CPU=… (e.g. EPYC-Milan).
        cpu = os.environ.get(
            "WHPX_CPU", "kvm64,hv_relaxed,hv_time,hv_synic,enforce=off")
    else:
        accel = "tcg,tb-size=512"
        cpu = "max"
    cmd = [
        QEMU_BIN,
        "-machine", "q35",
        "-accel", accel,
        "-cpu", cpu,
        "-m", mem,
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF}",
        "-drive", f"format=raw,file=fat:rw:{EFI_DIR}",
        "-serial", f"file:{SERIAL_LOG}",
        "-vga", "std",
        "-no-reboot",
        "-qmp", f"tcp:127.0.0.1:{QMP_PORT},server,nowait",
        "-display", "none",
    ]
    if boot_img:
        cmd += ["-drive", f"file={boot_img},if=none,id=android0,format=raw",
                "-device", "virtio-blk-pci,drive=android0"]

    # Phase 3 PIVOT — AOSP system image as a PMEM block device. The GKI kernel
    # has NO virtio-blk driver (CONFIG_VIRTIO_* unset) but CONFIG_OF_PMEM=y, so
    # we stage system.raw straight into a FIXED high-RAM region with QEMU's
    # generic loader (native memcpy at machine init — no DMA loop, no driver).
    # AETHER exposes [PMEM_BASE, PMEM_BASE+size) to the guest as a
    # `compatible="pmem-region"` DT node → /dev/pmem0 → first-stage `/system`.
    #
    # PMEM_BASE MUST match hypervisor::android_handoff::PMEM_SYSTEM_PA (12 GiB).
    # 12 GiB sits in the high-RAM band (q35, -m 16G → RAM at [4G, ~17.25G)),
    # above the low-4-GiB hypervisor heap/staging/PCI-hole AND clear of the
    # translator JIT cache + bump arena at 8 GiB. PML4[0]'s PDPT has free 1-GiB
    # slots [12..15] for AETHER's host-CR3 identity map.
    PMEM_SYSTEM_PA = 0x3_0000_0000
    # vendor.raw staged CONTIGUOUS right after system.raw (3 GiB) → 15 GiB. Exposed
    # as the 2nd pmem-region DT node → /dev/pmem1 → /vendor (SELinux policy +
    # HALs). MUST match hypervisor::android_handoff::PMEM_VENDOR_PA.
    PMEM_VENDOR_PA = PMEM_SYSTEM_PA + 0xC000_0000  # 0x3_C000_0000 (15 GiB)
    IMG_DIR = os.path.join(HERE, "images")
    sys_raw = os.path.join(IMG_DIR, "system.raw")
    if os.path.exists(sys_raw):
        cmd += ["-device",
                f"loader,file={sys_raw},addr={PMEM_SYSTEM_PA:#x},force-raw=on"]
    ven_raw = os.path.join(IMG_DIR, "vendor.raw")
    if os.path.exists(ven_raw):
        cmd += ["-device",
                f"loader,file={ven_raw},addr={PMEM_VENDOR_PA:#x},force-raw=on"]

    # /data — PRIMARY path is a tmpfs /data mounted by the DT fstab
    # (hypervisor::kernel::build_android_dtb emits an android,data node with
    # type=tmpfs; no encryption, no /metadata). That needs NO staged image, so
    # by default there is nothing to load here and /data is volatile in RAM.
    #
    # OPTIONAL: if you want a PERSISTENT /data instead of tmpfs, drop a blank
    # ext4 image at qemu/images/userdata.raw (e.g.
    #   dd if=/dev/zero of=userdata.raw bs=1M count=2048 &&
    #   mkfs.ext4 -F userdata.raw
    # ), stage it as a THIRD pmem-region here (/dev/pmem2), and switch the DT
    # /data fstab entry to dev=/dev/block/pmem2 type=ext4. Staged CONTIGUOUS
    # right after vendor.raw (15 GiB + 1 GiB = 16 GiB → bump MEM above 16G so
    # the high-RAM band actually backs it). Left commented/guarded so the
    # default tmpfs path stays the simple, image-free one.
    PMEM_USERDATA_PA = PMEM_VENDOR_PA + 0x4000_0000  # 0x4_0000_0000 (16 GiB)
    data_raw = os.path.join(IMG_DIR, "userdata.raw")
    if os.path.exists(data_raw):
        cmd += ["-device",
                f"loader,file={data_raw},addr={PMEM_USERDATA_PA:#x},force-raw=on"]

    # ── Checkpoint / restore (resume a boot across crashes) ──────────────────
    # WHPX BLOCKS QEMU savevm/snapshot (non-migratable vCPU), but `pmemsave`
    # works. The ARM64 guest's writable DRAM is host PA [0x8000_0000, +1 GiB);
    # the efi periodically writes a magic header (M2_REGFILE + resume PC) into the
    # top page and prints CHECKPOINT_READY, then busy-waits while we pmemsave the
    # 1 GiB to checkpoint.raw. On RESTORE=1 we reload it at the same PA; the efi
    # sees the magic and re-enters the DBT dispatch loop at the saved PC (the x86
    # vCPU is fresh — never migrated). CHECKPOINT=1 enables the periodic save.
    # Guest DRAM relocated to [4 GiB, 8 GiB) — raw, hole-free `-m 16G` high-RAM,
    # below the JIT cache at 8 GiB. Must match
    # aether_translator::runtime::mmu::GUEST_PA_BASE/SIZE and the host-CR3
    # identity map in boot_x86 (host_pt_map_identity_1g(GUEST_PA_BASE, 4)).
    CHECKPOINT_RAW = os.path.join(HERE, "checkpoint.raw")
    GUEST_DRAM_PA = 0x1_0000_0000
    GUEST_DRAM_SIZE = 0x1_0000_0000
    if os.environ.get("RESTORE") and os.path.exists(CHECKPOINT_RAW):
        cmd += ["-device",
                f"loader,file={CHECKPOINT_RAW},addr={GUEST_DRAM_PA:#x},force-raw=on"]
        print(f"==> RESTORE: reloading {CHECKPOINT_RAW} at {GUEST_DRAM_PA:#x}")

    # QDBG=1: log host CPU exceptions + resets to qemu/qdbg.log. `int` shows each
    # exception vector + RIP + error code as it is taken (so a #PF -> #DF -> reset
    # nested-fault triple-fault is visible with the ORIGINAL faulting RIP/CR2);
    # `cpu_reset` shows the state at the triple-fault reset.
    if os.environ.get("QDBG"):
        cmd += ["-d", "int,cpu_reset", "-D", os.path.join(HERE, "qdbg.log")]

    print(f"==> Launching QEMU (timeout={timeout}s)")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # connect QMP. QEMU only sends the QMP greeting AFTER machine init completes,
    # and the `-device loader,file=system.raw` stages a multi-GiB image into
    # guest RAM during init (host memcpy — seconds, not the 1 s a tight timeout
    # allows). Use a generous socket timeout so the greeting / capabilities
    # handshake survives the load, and dump QEMU stderr if it dies.
    sock = None
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", QMP_PORT), timeout=120)
            break
        except OSError:
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace")
                print("QEMU exited early:\n" + err)
                return 2
            time.sleep(0.2)
    if sock is None:
        print("Could not connect to QMP")
        proc.kill()
        return 2
    sock.settimeout(120)
    try:
        sock.recv(4096)  # greeting (waits out the image-load init)
        qmp(sock, "qmp_capabilities")
    except (socket.timeout, TimeoutError):
        # If QEMU is wedged during init, surface whatever it printed.
        if proc.poll() is not None:
            err = proc.stderr.read().decode(errors="replace")
            print("QEMU exited during QMP handshake:\n" + err)
        else:
            print("QMP handshake timed out (QEMU still running)")
        proc.kill()
        return 2

    # wait for serial log to settle
    start = time.time()
    last_size = -1
    last_change = time.time()
    last_ckpt = 0  # count of CHECKPOINT_READY markers already handled
    do_checkpoint = bool(os.environ.get("CHECKPOINT"))
    while time.time() - start < timeout:
        if proc.poll() is not None:
            print("==> QEMU process exited on its own")
            break
        # Checkpoint monitor: when the efi prints CHECKPOINT_READY it then
        # busy-waits ~40 s WITHOUT mutating guest DRAM, giving us a consistent
        # window to pmemsave the 1 GiB DRAM (incl. the magic header) to disk.
        if do_checkpoint and os.path.exists(SERIAL_LOG):
            try:
                with open(SERIAL_LOG, "rb") as f:
                    n = f.read().count(b"CHECKPOINT_READY")
                if n > last_ckpt:
                    last_ckpt = n
                    tmp = CHECKPOINT_RAW + ".tmp"
                    print(f"==> CHECKPOINT_READY #{n} — pmemsave {GUEST_DRAM_SIZE>>20} MiB ...")
                    t0 = time.time()
                    sock.settimeout(300)
                    qmp(sock, "pmemsave", val=GUEST_DRAM_PA, size=GUEST_DRAM_SIZE,
                        filename=tmp.replace("\\", "/"))
                    sock.settimeout(120)
                    if os.path.exists(tmp) and os.path.getsize(tmp) == GUEST_DRAM_SIZE:
                        os.replace(tmp, CHECKPOINT_RAW)  # atomic: a crash mid-save keeps the old one
                        print(f"==> CHECKPOINT saved ({time.time()-t0:.1f}s) -> {CHECKPOINT_RAW}")
                    else:
                        got = os.path.getsize(tmp) if os.path.exists(tmp) else -1
                        print(f"==> CHECKPOINT pmemsave INCOMPLETE (got {got} of {GUEST_DRAM_SIZE})")
            except Exception as e:
                print("checkpoint error:", e)
        sz = os.path.getsize(SERIAL_LOG) if os.path.exists(SERIAL_LOG) else 0
        if sz != last_size:
            last_size = sz
            last_change = time.time()
        elif time.time() - last_change >= SETTLE_S and sz > 0:
            print(f"==> Serial settled at {sz} bytes after {time.time()-start:.1f}s")
            break
        time.sleep(POLL)
    else:
        print(f"==> Hard timeout {timeout}s reached")

    # screenshot
    try:
        if os.path.exists(SCREEN_PPM):
            os.remove(SCREEN_PPM)
        r = qmp(sock, "screendump", filename=SCREEN_PPM)
        print("screendump reply:", r.strip()[:200])
        # screendump is async-ish; wait for file
        for _ in range(20):
            if os.path.exists(SCREEN_PPM) and os.path.getsize(SCREEN_PPM) > 0:
                break
            time.sleep(0.2)
        if ppm_to_png(SCREEN_PPM, SCREEN_PNG):
            print(f"==> Wrote {SCREEN_PNG}")
        else:
            print("==> PPM->PNG conversion failed (not P6?)")
    except Exception as e:
        print("screenshot error:", e)

    try:
        qmp(sock, "quit")
    except Exception:
        pass
    time.sleep(0.5)
    if proc.poll() is None:
        proc.kill()
    sock.close()
    print("==> Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
