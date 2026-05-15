#!/usr/bin/env bash
# ch36: Physical IRQ Forwarding — Validated
#
# Gate: inside the Android guest, `cat /proc/interrupts` shows non-zero
#       counts on both the arch_timer and uart-pl011 (or GIC-0 33) lines
#       after 5 seconds of guest uptime.
#
# What changed from ch35:
#   - aether_vgic_init() is now called during boot so ICH_LRn injection works.
#     Without this call VGicState::lr_count = 0 and all IRQ injection silently
#     fails (find_free_lr iterates zero times, inject_hw always returns false).
#   - setup_irq_forwarding() enables:
#       INTID 27 (virtual timer PPI) per-core in GICR_ISENABLER0
#       INTID 30 (NS physical timer PPI) per-core in GICR_ISENABLER0
#       INTID 33 (PL011 UART SPI) in GICD_ISENABLER1
#   - handle_physical_irq() (gic.rs) forwards every acknowledged IRQ as a
#     hardware-backed LR (ICH_LRn.HW=1); the GIC auto-deactivates on guest EOI.
#   - handle_maintenance_irq() (gic.rs) clears stale LRs when ICH_MISR.EOI fires.
#
# Gate procedure (manual):
#   1. Run this script.
#   2. Wait for the /bin/sh prompt (or shell banner).
#   3. Run: cat /proc/interrupts
#   4. Verify:
#      - "arch_timer" row has a non-zero count in the CPU columns.
#      - "uart-pl011" or "GIC-0  33" row has a non-zero count.
#   5. Run: sleep 5; cat /proc/interrupts
#      Verify the timer count has increased (confirming live periodic delivery).
#
# Primary sources:
#   - IHI0069 §8.2.3 (ICH_LR hardware-backed forwarding)
#   - Linux /proc/interrupts format (arch/arm64/kernel/irq.c)
#   - QEMU hw/arm/virt.c (INTID assignments)
#
# Prerequisites: same as run-ch35.sh (QEMU, GKI Image, initrd with /bin/sh).
#
# Usage:
#   ./qemu/run-ch36.sh               — rebuild + boot
#   ./qemu/run-ch36.sh --no-build    — boot existing binary (skip cargo)
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
    echo "==> Building hypervisor.efi (ch36 IRQ forwarding)..."
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

# ── 3. Launch QEMU ────────────────────────────────────────────────────────────
#
# Same as ch35 (4-core SMP). The change is purely in the hypervisor binary:
#   - aether_vgic_init() wires up ICH_VTR_EL2 so LR injection works.
#   - setup_irq_forwarding() enables timer PPIs + UART SPI in GIC.
#
# -m 4G     DRAM: 4 GiB. AETHER maps 2 GiB as Android IPA.
# -smp 4    Four cores; AETHER wakes secondaries via PSCI HVC.

echo "==> Kernel:  $KERNEL_IMAGE"
echo "==> Initrd:  ${INITRD_IMAGE:-none}"
echo "==> Launching QEMU ch36 (Ctrl-A X to exit)..."
echo ""
echo "Gate: after /bin/sh prompt, run:"
echo "  cat /proc/interrupts"
echo "Expected: non-zero counts on 'arch_timer' and 'uart-pl011' (or GIC-0 33)."
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
