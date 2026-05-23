#!/usr/bin/env bash
# Boot AETHER hypervisor.efi in QEMU ARM64 (Tier 1 smoke test).
#
# Prerequisites (already satisfied if you followed CLAUDE.md):
#   brew install qemu         — provides qemu-system-aarch64 + edk2-aarch64-code.fd
#   cargo +nightly build ...  — produces target/aarch64-unknown-uefi/release/hypervisor.efi
#
# Usage:
#   ./qemu/run.sh             — rebuild + boot
#   ./qemu/run.sh --no-build  — boot existing binary (skip cargo)
#
# Exit: Ctrl-A X  to quit QEMU from the serial console.

set -euo pipefail

# Rust toolchain — not in PATH for non-interactive shells
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OVMF_CODE="/opt/homebrew/Cellar/qemu/11.0.0/share/qemu/edk2-aarch64-code.fd"
EFI_DIR="$SCRIPT_DIR/efi"
EFI_BINARY="$REPO_DIR/target/aarch64-unknown-uefi/release/hypervisor.efi"
BOOT_PATH="$EFI_DIR/EFI/BOOT/BOOTAA64.EFI"

# ── 1. Build (unless skipped) ────────────────────────────────────────────────
if [[ "${1:-}" != "--no-build" ]]; then
    echo "==> Building hypervisor.efi..."
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

# ── 3. Phase 3: optional Android image attachment ────────────────────────────
#
# When BOOT_IMG is set, load it at 0x80000000 via QEMU's loader device. The
# hypervisor's virtio_blk::register_memory_backed() consumes that PA range.
# SYSTEM_IMG / VENDOR_IMG / VBMETA_IMG are reserved for Phase 4.
ANDROID_LOADERS=()
if [[ -n "${BOOT_IMG:-}" ]]; then
    if [[ ! -r "$BOOT_IMG" ]]; then
        echo "BOOT_IMG=$BOOT_IMG is not readable" >&2
        exit 2
    fi
    echo "==> Loading BOOT_IMG=$BOOT_IMG at 0x80000000"
    ANDROID_LOADERS+=(-device "loader,file=$BOOT_IMG,addr=0x80000000,force-raw=on")
fi

# ── 4. Launch QEMU ────────────────────────────────────────────────────────────
echo "==> Launching QEMU (Ctrl-A X to exit)..."
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
    "${ANDROID_LOADERS[@]}"
