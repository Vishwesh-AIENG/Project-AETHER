#!/bin/bash
# Phase 5 — full AOSP build of aether_arm64-ap2a-user. Long-running (2-6 h).
# Logged to ~/aosp/build.log.
#
# Concurrency note: AOSP's nproc-default for `m -j` is the host's full core
# count (16 here). At ~2 GB peak RAM per worker, that overshoots this box's
# 15.6 GB RAM cap; the linker phase OOM-kills. We pin -j8 instead — slower
# wall time but actually finishes.
export PATH=~/.bin:$PATH
cd ~/aosp
exec > ~/aosp/build.log 2>&1

echo "=== build started $(date) ==="
echo "=== using -j8 (host has 15.6 GB RAM, AOSP wants ~2 GB per worker) ==="
df -h ~ | tail -1
free -h
echo

echo "=== source build/envsetup.sh ==="
source build/envsetup.sh
echo "envsetup OK; lunch is now: $(type -t lunch 2>/dev/null)"

echo
echo "=== lunch aether_arm64-ap2a-user ==="
lunch aether_arm64-ap2a-user
LUNCH_EXIT=$?
if [ $LUNCH_EXIT -ne 0 ]; then
    echo "LUNCH FAILED with exit=$LUNCH_EXIT — aborting."
    exit $LUNCH_EXIT
fi
echo "    TARGET_PRODUCT=$TARGET_PRODUCT"
echo "    TARGET_BUILD_VARIANT=$TARGET_BUILD_VARIANT"

echo
echo "=== m -j8 ==="
echo "    start: $(date)"
m -j8
M_EXIT=$?
echo "    end:   $(date) with exit=$M_EXIT"

echo
echo "=== disk after build ==="
df -h ~ | tail -1

echo
echo "=== expected outputs ==="
ls -lh out/target/product/aether_arm64/{boot,system,vendor,vbmeta,userdata}.img 2>/dev/null \
    || echo "(some images missing)"

exit $M_EXIT
