#!/bin/bash
set -e
echo "=== 6.x stage EFI binaries for ESP ==="
STAGE=/mnt/d/AETHER/esp-staging
mkdir -p "$STAGE/EFI/AETHER" "$STAGE/EFI/BOOT"

# Hypervisor (x86 tier) — registered boot entry path
cp /mnt/d/AETHER/target/x86_64-unknown-uefi/release/hypervisor.efi \
   "$STAGE/EFI/AETHER/hypervisor.efi"

# Removable-media auto-boot — \EFI\BOOT\BOOTX64.EFI is what firmware tries
# when no registered entry exists.
cp /mnt/d/AETHER/target/x86_64-unknown-uefi/release/hypervisor.efi \
   "$STAGE/EFI/BOOT/BOOTX64.EFI"

# Also stage the ARM tier binary alongside it (lives at \EFI\AETHER\
# hypervisor-aarch64.efi to disambiguate from the x86 one).
cp /mnt/d/AETHER/target/aarch64-unknown-uefi/release/hypervisor.efi \
   "$STAGE/EFI/AETHER/hypervisor-aarch64.efi"

# AOSP images go in once the build finishes (Phase 5). Placeholder note:
cat > "$STAGE/EFI/AETHER/README.txt" <<EOF
AETHER ESP layout
=================

\\EFI\\BOOT\\BOOTX64.EFI       Auto-boot entry (x86_64 hypervisor)
\\EFI\\AETHER\\hypervisor.efi  x86_64 hypervisor (Intel/AMD/Ryzen)
\\EFI\\AETHER\\hypervisor-aarch64.efi
                              ARM64 hypervisor (Snapdragon X Elite)
\\EFI\\AETHER\\boot.img        Android boot image (PENDING — set after
                              \`m -j\$(nproc)\` produces it from AOSP)
\\EFI\\AETHER\\vbmeta.img      AVB metadata (PENDING — same as above)

To install: copy the contents of this folder onto the FAT32 ESP of a
USB stick. The hypervisor will boot automatically on systems whose UEFI
firmware tries removable media.
EOF

echo
echo "=== staged so far ==="
find "$STAGE" -type f -exec ls -la {} +
echo
echo "=== boot.img + vbmeta.img copy commands ready to run after Phase 5 ==="
echo "cp ~/aosp/out/target/product/aether_arm64/boot.img   $STAGE/EFI/AETHER/boot.img"
echo "cp ~/aosp/out/target/product/aether_arm64/vbmeta.img $STAGE/EFI/AETHER/vbmeta.img"
