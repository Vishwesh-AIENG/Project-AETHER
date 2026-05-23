#!/usr/bin/env bash
# run-android.sh — convenience wrapper that boots AETHER under QEMU with the
# AOSP boot.img attached as the paravirt virtio-blk backing.
#
# Usage:
#   BOOT_IMG=./out/target/product/aether/boot.img ./qemu/run-android.sh
#   BOOT_IMG=./out/target/product/aether/boot.img KERNEL_IMAGE=./qemu/Image \
#       INITRD_IMAGE=./qemu/initrd.img ./qemu/run-android.sh
#
# Phase 3 wires only BOOT_IMG. SYSTEM_IMG / VENDOR_IMG / VBMETA_IMG are
# accepted and forwarded but currently ignored by the hypervisor side until
# Phase 4 lands.
#
# After QEMU is up, at the guest /bin/sh prompt the Phase 3 gate is:
#
#   dd if=/dev/vda bs=512 count=1 2>/dev/null | xxd | head -1
#   00000000: 414e 4452 4f49 4421 ...  ANDROID!

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "${BOOT_IMG:-}" ]]; then
    echo "BOOT_IMG=<path> must be set." >&2
    exit 64
fi

# Pass through to whichever tier the user already prefers; ARM is the default
# QEMU target for AETHER. Override with TARGET_ARCH=x86_64 to use run-x86.sh.
case "${TARGET_ARCH:-aarch64}" in
    aarch64) exec "$SCRIPT_DIR/run.sh"     "$@" ;;
    x86_64)  exec "$SCRIPT_DIR/run-x86.sh" "$@" ;;
    *)
        echo "TARGET_ARCH must be aarch64 or x86_64" >&2
        exit 64
        ;;
esac
