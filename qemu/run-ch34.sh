#!/usr/bin/env bash
# ch34: Linux Kernel Boot in QEMU
#
# Gate: ARM64 GKI boots to a /bin/sh shell prompt on the QEMU serial console.
#
# Prerequisites:
#   brew install qemu            — provides qemu-system-aarch64 + edk2-aarch64-code.fd
#   cargo +nightly build ...     — produces target/aarch64-unknown-uefi/release/hypervisor.efi
#   A pre-built ARM64 GKI Image  — place at $KERNEL_IMAGE (default: qemu/Image)
#     Build: from Android Common Kernel source (android13-5.15 or android14-6.1 branch)
#       ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make gki_defconfig
#       ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make -j$(nproc) Image
#     Or download a pre-built GKI from:
#       https://ci.android.com (search for kernel_aarch64 build artifacts)
#
#   An initramfs with /bin/sh    — place at $INITRD_IMAGE (default: qemu/initrd.img)
#     Minimal initrd (busybox-based):
#       dd if=/dev/zero bs=1M count=8 | mke2fs -t ext2 -F - initrd.img
#       Or use a pre-built one from buildroot / Android initrd
#     AETHER passes rdinit=/bin/sh via DTB cmdline; the initrd must contain /bin/sh.
#
# Memory layout for this test:
#   0x4000_0000  DRAM start      (ANDROID_IPA_BASE)
#   0x4080_0000  KERNEL1_PA      — QEMU loader places ARM64 Image here
#   0x4400_0000  DTB1_PA         — AETHER writes the FDT blob here at runtime
#
# Usage:
#   ./qemu/run-ch34.sh               — rebuild + boot (requires Image + initrd.img in qemu/)
#   ./qemu/run-ch34.sh --no-build    — boot existing binary (skip cargo)
#
# Exit: Ctrl-A X to quit QEMU.

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OVMF_CODE="/opt/homebrew/Cellar/qemu/11.0.0/share/qemu/edk2-aarch64-code.fd"
EFI_DIR="$SCRIPT_DIR/efi"
EFI_BINARY="$REPO_DIR/target/aarch64-unknown-uefi/release/hypervisor.efi"
BOOT_PATH="$EFI_DIR/EFI/BOOT/BOOTAA64.EFI"

# ARM64 GKI Image path (caller must supply a real kernel Image).
KERNEL_IMAGE="${KERNEL_IMAGE:-$SCRIPT_DIR/Image}"

# Initramfs image (must contain /bin/sh for the gate test).
INITRD_IMAGE="${INITRD_IMAGE:-$SCRIPT_DIR/initrd.img}"

# ── Preflight checks ─────────────────────────────────────────────────────────

if [[ ! -f "$KERNEL_IMAGE" ]]; then
    echo "[ERROR] ARM64 GKI Image not found: $KERNEL_IMAGE"
    echo "  Build or download a GKI Image and place it at $KERNEL_IMAGE"
    echo "  See the comments at the top of this script for instructions."
    exit 1
fi

if [[ ! -f "$INITRD_IMAGE" ]]; then
    echo "[WARN] Initramfs not found: $INITRD_IMAGE"
    echo "  Continuing without initrd — kernel will panic unless rootfs is provided."
    echo "  For the gate test, supply an initrd containing /bin/sh."
    INITRD_ARGS=()
else
    INITRD_ARGS=(-initrd "$INITRD_IMAGE")
fi

# ── 1. Build ─────────────────────────────────────────────────────────────────

if [[ "${1:-}" != "--no-build" ]]; then
    echo "==> Building hypervisor.efi (ch34)..."
    cd "$REPO_DIR"
    cargo +nightly build \
        -Z build-std=core,compiler_builtins \
        -Z build-std-features=compiler-builtins-mem \
        --release \
        --target aarch64-unknown-uefi \
        -p hypervisor
    echo "==> Build OK"
fi

# ── 2. Stage EFI binary ───────────────────────────────────────────────────────

cp "$EFI_BINARY" "$BOOT_PATH"
echo "==> Staged: $(basename "$EFI_BINARY") → EFI/BOOT/BOOTAA64.EFI"

# ── 3. Launch QEMU with GKI Image pre-loaded at KERNEL1_PA ───────────────────
#
# -device loader,file=Image,addr=0x40800000,force-raw=on
#   Loads the raw ARM64 Image binary at physical address 0x40800000 (KERNEL1_PA).
#   AETHER reads the 64-byte header at this address and ERets to it.
#
# -m 4G       DRAM size: 4 GiB. AETHER maps 2 GiB for Android (ANDROID_RAM_SIZE).
# -smp 1      Single core; AETHER assigns it to the Android partition.
# -nographic  Serial console to host terminal.

echo "==> Kernel:  $KERNEL_IMAGE"
echo "==> Initrd:  ${INITRD_IMAGE:-none}"
echo "==> Launching QEMU ch34 (Ctrl-A X to exit)..."
echo ""
echo "Gate: wait for the /bin/sh prompt on the serial console."
echo ""

exec qemu-system-aarch64 \
    -machine  virt,gic-version=3,virtualization=on \
    -cpu      max \
    -m        4G \
    -smp      1 \
    -nographic \
    -drive    if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive    if=none,id=hd0,format=raw,file=fat:rw:"$EFI_DIR" \
    -device   virtio-blk-device,drive=hd0 \
    -device   loader,file="$KERNEL_IMAGE",addr=0x40800000,force-raw=on \
    "${INITRD_ARGS[@]+"${INITRD_ARGS[@]}"}"
