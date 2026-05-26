#!/bin/bash
echo "=== first 73 lines of build.log (before the 'Timed out exiting...' line) ==="
sed -n '1,73p' ~/aosp/build.log
echo
echo "=== look for soong/kati/blueprint error messages anywhere ==="
grep -nE 'error:|Error:|FAILED|cannot|unable|undefined|missing|panic[^W]|Cannot|invalid' ~/aosp/build.log \
    | grep -vE 'goroutine|syscall|/src/' | head -40
echo
echo "=== look for any reference to device/aether or vendor/microg in the log ==="
grep -nE 'device/aether|vendor/microg|aether_arm64' ~/aosp/build.log | head -20
