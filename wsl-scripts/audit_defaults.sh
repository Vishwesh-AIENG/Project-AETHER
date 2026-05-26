#!/bin/bash
cd ~/aosp
for hal_path in \
    hardware/interfaces/sensors/2.1/default \
    hardware/interfaces/radio/1.6/Android.bp \
    hardware/interfaces/health/2.1/default \
    hardware/interfaces/camera/provider/2.7/default \
    hardware/interfaces/power/aidl/default \
    hardware/google/gchips/gralloc4/src
do
    echo
    echo "=============================================================="
    echo "=== $hal_path ==="
    echo "=============================================================="
    bp=""
    if [ -d "$hal_path" ]; then
        bp="$hal_path/Android.bp"
    elif [ -f "$hal_path" ]; then
        bp="$hal_path"
    fi
    if [ -n "$bp" ] && [ -f "$bp" ]; then
        cat "$bp" | head -80
    else
        echo "(not found at this path; searching)"
        find hardware/interfaces -path "*/default/Android.bp" -name Android.bp 2>/dev/null \
            | grep -E "$(basename $hal_path)|$(dirname $hal_path | xargs basename)" \
            | head -3
    fi
done
