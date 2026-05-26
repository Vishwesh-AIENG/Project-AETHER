#!/bin/bash
# AOSP 14 introduced a three-segment lunch combo: <product>-<release>-<variant>.
# Find the available release names and verify the right one for r74.
export PATH=~/.bin:$PATH
cd ~/aosp
source build/envsetup.sh 2>&1 >/dev/null

echo "=== available release configs ==="
ls build/release/aconfig/ 2>/dev/null | head
echo
echo "=== or via build/release/build_flags.bzl release-tags ==="
ls build/release/release_configs/ 2>/dev/null | head
echo
echo "=== try lunch with no args to see the menu ==="
echo q | lunch 2>&1 | head -40
echo
echo "=== combos that exist ==="
print_lunch_menu 2>&1 | head -30 || true
