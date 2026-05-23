#!/usr/bin/env bash
# Boot AETHER hypervisor.efi (x86_64 target) in QEMU.
#
# Pairs with sandbox/x86_64-port boot_x86.rs.  Outputs:
#   - COM1 serial -> qemu/com1.log  (diagnostic trace)
#   - GOP framebuffer (VGA std)     (status colour: green/blue/amber/red)
#
# Prerequisites:
#   QEMU for Windows / Linux / Mac with x86_64 system emulation and edk2 OVMF.
#   On Windows the bundled paths are:
#     QEMU_BIN=/d/qemu/qemu-system-x86_64.exe
#     OVMF=D:\\qemu\\share\\edk2-x86_64-code.fd
#   Adjust QEMU_BIN / OVMF below for your install.
#
# Usage:
#   ./qemu/run-x86.sh             # rebuild + boot
#   ./qemu/run-x86.sh --no-build  # skip cargo
#
# Exit: Ctrl-A X  to quit QEMU from the serial console (or close the QEMU
# window if you have a graphical display).

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
OVMF="${OVMF:-/d/qemu/share/edk2-x86_64-code.fd}"
EFI_DIR="$SCRIPT_DIR/efi-x86"
EFI_BINARY="$REPO_DIR/target/x86_64-unknown-uefi/release/hypervisor.efi"
BOOT_PATH="$EFI_DIR/EFI/BOOT/BOOTX64.EFI"
SERIAL_LOG="$SCRIPT_DIR/com1.log"

# 1. Build (unless skipped)
if [[ "${1:-}" != "--no-build" ]]; then
    echo "==> Building hypervisor.efi (x86_64-unknown-uefi)..."
    cd "$REPO_DIR"
    cargo +nightly build \
        -Z build-std=core,compiler_builtins \
        -Z build-std-features=compiler-builtins-mem \
        --release \
        --target x86_64-unknown-uefi \
        -p hypervisor
    echo "==> Build OK"
fi

# 2. Stage EFI binary
mkdir -p "$EFI_DIR/EFI/BOOT"
cp "$EFI_BINARY" "$BOOT_PATH"
echo "==> Staged: $(basename "$EFI_BINARY") -> EFI/BOOT/BOOTX64.EFI"
rm -f "$SERIAL_LOG"

# 3. Launch QEMU
# accel=tcg is the portable software emulator (no kernel module needed); use
# accel=kvm on Linux with KVM for full-speed real virtualisation, or accel=
# whpx on Windows with WHPX enabled.  TCG presents the CPU as AuthenticAMD
# (so the AMD path of boot_x86.rs is exercised by default).
echo "==> Launching QEMU"
echo "    Serial log: $SERIAL_LOG"
echo "    On success the screen turns solid green; serial reports:"
echo "      [x86] VMCB exit_code = 0x078 HLT (Ch51 gate PASSED)"
echo ""

ANDROID_DRIVES=()
if [[ -n "${BOOT_IMG:-}" ]]; then
    if [[ ! -r "$BOOT_IMG" ]]; then
        echo "BOOT_IMG=$BOOT_IMG is not readable" >&2
        exit 2
    fi
    echo "==> Attaching BOOT_IMG=$BOOT_IMG as virtio-blk-pci"
    ANDROID_DRIVES+=(-drive "file=$BOOT_IMG,if=none,id=android0,format=raw"
                     -device "virtio-blk-pci,drive=android0")
fi

exec "$QEMU_BIN" \
    -machine q35,accel=tcg \
    -cpu      max \
    -m        1G \
    -drive    if=pflash,format=raw,readonly=on,file="$OVMF" \
    -drive    format=raw,file=fat:rw:"$EFI_DIR" \
    -serial   file:"$SERIAL_LOG" \
    -vga      std \
    -no-reboot \
    "${ANDROID_DRIVES[@]}"
