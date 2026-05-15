#!/usr/bin/env bash
# ch35: Multi-Core SMP
#
# Gate: `nproc` inside the guest shows all 4 assigned cores, or the kernel
#       boot log shows "SMP: Brought up 1 node, 4 CPUs".
#
# Differences from run-ch34.sh:
#   -smp 4        Four cores (Aff0=0..3). AETHER wakes secondaries via PSCI HVC.
#
# Prerequisites: same as run-ch34.sh (QEMU, GKI Image, initrd with /bin/sh).
#
# Memory layout:
#   0x4000_0000  DRAM start      (ANDROID_IPA_BASE)
#   0x4080_0000  KERNEL1_PA      — QEMU loader places ARM64 Image here
#   0x4400_0000  DTB1_PA         — AETHER writes 4-CPU FDT blob here at runtime
#
# Usage:
#   ./qemu/run-ch35.sh               — rebuild + boot
#   ./qemu/run-ch35.sh --no-build    — boot existing binary (skip cargo)
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

KERNEL_IMAGE="${KERNEL_IMAGE:-$SCRIPT_DIR/Image}"
INITRD_IMAGE="${INITRD_IMAGE:-$SCRIPT_DIR/initrd.img}"

# ── Preflight checks ─────────────────────────────────────────────────────────

if [[ ! -f "$KERNEL_IMAGE" ]]; then
    echo "[ERROR] ARM64 GKI Image not found: $KERNEL_IMAGE"
    echo "  See run-ch34.sh comments for build/download instructions."
    exit 1
fi

if [[ ! -f "$INITRD_IMAGE" ]]; then
    echo "[WARN] Initramfs not found: $INITRD_IMAGE"
    echo "  Continuing without initrd — kernel will panic without rootfs."
    INITRD_ARGS=()
else
    INITRD_ARGS=(-initrd "$INITRD_IMAGE")
fi

# ── 1. Build ─────────────────────────────────────────────────────────────────

if [[ "${1:-}" != "--no-build" ]]; then
    echo "==> Building hypervisor.efi (ch35 SMP)..."
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

# ── 3. Launch QEMU with 4-core SMP ───────────────────────────────────────────
#
# -smp 4
#   Four cores. AETHER wakes cores 1-3 via PSCI CPU_ON HVC (QEMU intercepts
#   at TCG level). Each secondary initialises EL2 regs and parks in WFE until
#   the Android kernel issues PSCI CPU_ON.
#
# -m 4G   DRAM size: 4 GiB. AETHER maps 2 GiB for Android.

echo "==> Kernel:  $KERNEL_IMAGE"
echo "==> Initrd:  ${INITRD_IMAGE:-none}"
echo "==> Launching QEMU ch35 SMP (Ctrl-A X to exit)..."
echo ""
echo "Gate: kernel log shows 'Brought up 1 node, 4 CPUs' or nproc == 4."
echo ""

exec qemu-system-aarch64 \
    -machine  virt,gic-version=3,virtualization=on \
    -cpu      max \
    -m        4G \
    -smp      4 \
    -nographic \
    -drive    if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive    if=none,id=hd0,format=raw,file=fat:rw:"$EFI_DIR" \
    -device   virtio-blk-device,drive=hd0 \
    -device   loader,file="$KERNEL_IMAGE",addr=0x40800000,force-raw=on \
    "${INITRD_ARGS[@]+"${INITRD_ARGS[@]}"}"
