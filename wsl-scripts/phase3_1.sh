#!/bin/bash
set -e
echo "=== 3.1 copy device tree ==="
mkdir -p ~/aosp/device/aether
cp -r /mnt/d/AETHER/aosp/device/aether/aether_arm64 ~/aosp/device/aether/
echo
echo "=== 3.2 verify ==="
ls ~/aosp/device/aether/aether_arm64/
echo
echo "=== sizes ==="
du -sh ~/aosp/device/aether/aether_arm64/
