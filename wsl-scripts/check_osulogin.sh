#!/usr/bin/env bash
F="/root/aosp/out/soong/.intermediates/packages/modules/Wifi/OsuLogin/OsuLogin/android_common_apex30/737f09fcc0b17bc4650c68e8a26b3dd4/manifest_fixer/AndroidManifest.xml"
echo "=== file info ==="
ls -la "$F" 2>&1
echo
echo "=== size ==="
stat -c '%s bytes' "$F" 2>&1
echo
echo "=== first 500 chars ==="
head -c 500 "$F" 2>&1
echo
echo
echo "=== last 200 chars ==="
tail -c 200 "$F" 2>&1
echo
echo
echo "=== source manifest (input to manifest_fixer) ==="
SRC="/root/aosp/packages/modules/Wifi/OsuLogin/AndroidManifest.xml"
ls -la "$SRC" 2>&1
echo "src head:"
head -10 "$SRC" 2>&1
