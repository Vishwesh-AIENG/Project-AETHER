#!/bin/bash
cd ~/aosp
echo "=== power HAL modules in this AOSP tree ==="
grep -rln 'name: "android.hardware.power' --include=Android.bp 2>/dev/null \
    | head -3 \
    | xargs -I{} grep -E 'name: "android.hardware.power' {} \
    | sort -u | head -20

echo
echo "=== power AIDL versions ==="
ls hardware/interfaces/power/aidl/ 2>/dev/null

echo
echo "=== radio modem AIDL/HIDL ==="
grep -rln 'name: "android.hardware.radio.modem' --include=Android.bp 2>/dev/null | head -5
ls hardware/interfaces/radio/aidl/ 2>/dev/null

echo
echo "=== health AIDL/HIDL versions ==="
ls hardware/interfaces/health/ 2>/dev/null
grep -rln 'name: "android.hardware.health' --include=Android.bp 2>/dev/null \
    | head -3 \
    | xargs -I{} grep -E 'name: "android.hardware.health' {} \
    | sort -u | head -10

echo
echo "=== sample default health service Android.bp (we can mimic its shape) ==="
find hardware/interfaces/health -name Android.bp 2>/dev/null | head -3 | while read f; do
    echo "--- $f ---"
    grep -A8 'cc_binary\|cc_binary_host' "$f" | head -30
done
