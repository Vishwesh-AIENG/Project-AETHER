#!/bin/bash
set -e
export PATH="$HOME/.cargo/bin:$PATH"
cd /mnt/d/AETHER

echo "=== 4.2 ARM tier hypervisor (aarch64-unknown-uefi) ==="
cargo +nightly build \
  -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem \
  --release --target aarch64-unknown-uefi -p hypervisor --bin hypervisor 2>&1 | tail -5

echo
echo "=== 4.2 x86 tier hypervisor (x86_64-unknown-uefi) ==="
cargo +nightly build \
  -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem \
  --release --target x86_64-unknown-uefi -p hypervisor --bin hypervisor 2>&1 | tail -5

echo
echo "=== 4.3 file type verification ==="
file target/aarch64-unknown-uefi/release/hypervisor.efi
file target/x86_64-unknown-uefi/release/hypervisor.efi

echo
echo "=== sizes ==="
ls -lh target/aarch64-unknown-uefi/release/hypervisor.efi
ls -lh target/x86_64-unknown-uefi/release/hypervisor.efi
