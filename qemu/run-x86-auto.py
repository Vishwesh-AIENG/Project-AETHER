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
    cmd = [
        QEMU_BIN,
        "-machine", "q35,accel=tcg",
        "-cpu", "max",
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

    print(f"==> Launching QEMU (timeout={timeout}s)")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # connect QMP
    sock = None
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", QMP_PORT), timeout=1)
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
    sock.recv(4096)  # greeting
    qmp(sock, "qmp_capabilities")

    # wait for serial log to settle
    start = time.time()
    last_size = -1
    last_change = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            print("==> QEMU process exited on its own")
            break
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
