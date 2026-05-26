#!/bin/bash
# Audit every dependency Android.bp references against AOSP 14's source tree.
cd ~/aosp
echo "=== verifying each named lib/module from device/aether/aether_arm64/Android.bp ==="

# Extract the dep names we use in Android.bp
deps=(
    "android.hardware.sensors@2.1"
    "android.hardware.sensors@2.X-shared-impl"
    "android.hardware.radio@1.6"
    "android.hardware.radio.modem@1.0"
    "android.hardware.camera.provider@2.7"
    "android.hardware.power-V5-ndk"
    "android.hardware.health@2.1"
    "libhealthservice"
    "libdrm"
    "android.hardware.graphics.allocator-V2-ndk"
    "android.hardware.graphics.mapper@4.0"
    "libbase"
    "libcutils"
    "libutils"
    "libbinder_ndk"
    "liblog"
    "libhardware"
)

for d in "${deps[@]}"; do
    # Grep all Android.bp files for `name: "<dep>"` to find the canonical declaration.
    hits=$(grep -rln "name: \"$d\"" --include=Android.bp 2>/dev/null | head -3)
    if [ -z "$hits" ]; then
        printf "  %-55s MISSING — no Android.bp declares this module name\n" "$d"
    else
        # Show the first hit + what kind of cc_* module it is.
        first=$(echo "$hits" | head -1)
        kind=$(grep -B0 -A0 "name: \"$d\"" "$first" 2>/dev/null \
            | head -1)
        # Look at the module type declared on the previous line
        line=$(grep -n "name: \"$d\"" "$first" | head -1 | cut -d: -f1)
        prev=$(sed -n "$((line-3)),$((line+1))p" "$first" \
            | grep -E "^(cc_|java_|hidl_|aidl_|prebuilt_|filegroup|cc_defaults)" \
            | head -1 | awk '{print $1}')
        printf "  %-55s %-25s %s\n" "$d" "${prev:-?}" "$first"
    fi
done

echo
echo "=== specifically for sensors@2.X-shared-impl — what variants does it expose? ==="
loc=$(grep -rln 'name: "android.hardware.sensors@2.X-shared-impl"' --include=Android.bp 2>/dev/null | head -1)
if [ -n "$loc" ]; then
    echo "found in: $loc"
    # Print the surrounding module body so we can see the cc_* type and link options.
    awk '/name: "android.hardware.sensors@2.X-shared-impl"/{c=1} c{print; if($0~/^}/){exit}}' "$loc" | head -40
fi
