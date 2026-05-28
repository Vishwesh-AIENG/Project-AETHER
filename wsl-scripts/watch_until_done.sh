#!/usr/bin/env bash
# Poll the build every 30s. Exit codes:
#   0 = images produced (system.img + vbmeta.img present)
#   1 = build failed; FAILED block printed for diagnosis
#   2 = timed out (30 min hard cap)
#   3 = build went away without succeeding or failing (weird)
set -u
DEADLINE=$(( $(date +%s) + 1800 ))   # 30 min cap
LAST_STEP=""
while true; do
    NOW=$(date +%s)
    if [ "$NOW" -ge "$DEADLINE" ]; then
        echo "TIMEOUT after 30 min"
        exit 2
    fi
    # Check if images present
    if [ -f /root/aosp/out/target/product/aether_arm64/system.img ] \
       && [ -f /root/aosp/out/target/product/aether_arm64/vbmeta.img ]; then
        echo "DONE - system.img + vbmeta.img exist"
        ls -la /root/aosp/out/target/product/aether_arm64/*.img
        exit 0
    fi
    # Check if build is still alive
    if ! pgrep -f "phase5_build.sh" > /dev/null && ! pgrep -f "soong_ui" > /dev/null && ! pgrep -f "ninja " > /dev/null; then
        # No build running. Did it fail?
        if grep -q "^FAILED:" /root/aosp/build.log; then
            echo "BUILD FAILED - extracting block:"
            grep -B1 -A12 "^FAILED:" /root/aosp/build.log | tail -25
            echo
            echo "---LAST 10 LINES---"
            tail -10 /root/aosp/build.log
            exit 1
        else
            echo "BUILD ENDED without FAILED marker — check log"
            tail -15 /root/aosp/build.log
            exit 3
        fi
    fi
    # Still running. Show progress.
    STEP=$(grep -oE '\[[ 0-9]+% [0-9]+/[0-9]+\]' /root/aosp/build.log | tail -1)
    if [ "$STEP" != "$LAST_STEP" ]; then
        echo "$(date -u +%T) $STEP"
        LAST_STEP="$STEP"
    fi
    sleep 30
done
