#!/bin/bash
# Build the ARM-tier proof initramfs: qemu/initrd-proof.cpio (newc).
# Runs in WSL (root, for mknod). Uses the local Bootlin aarch64 toolchain.
set -euo pipefail
HERE="${HERE:-$(cd "$(dirname "$0")" && pwd)}"
TC="${TC:-/root/aarch64--glibc--stable-2024.02-1/bin/aarch64-linux-gcc}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK"/{bin,dev,proc}
"$TC" -static -O2 -Wall -o "$WORK/bin/sh" "$HERE/aether_proof.c" -lpthread
mknod -m 600 "$WORK/dev/console" c 5 1
(cd "$WORK" && find . | cpio -o -H newc --quiet) > "$HERE/../initrd-proof.cpio"
echo "built $(stat -c %s "$HERE/../initrd-proof.cpio") bytes: $(file -b "$WORK/bin/sh" | cut -c1-60)"
