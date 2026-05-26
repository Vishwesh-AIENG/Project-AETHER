#!/bin/bash
# Phase 5 restart: refresh device tree from /mnt/d, then kick off build.
set -e
export PATH=~/.bin:$PATH

echo "=== sync device tree from Windows ==="
SRC=/mnt/d/AETHER/aosp/device/aether/aether_arm64
DST=~/aosp/device/aether/aether_arm64
# Use rsync to preserve directory structure and delete obsolete files.
rsync -a --delete \
    --exclude='*.tmp' \
    "$SRC/" "$DST/"
echo "    files in DST:"
find "$DST" -type f | wc -l
echo
echo "=== verify the new files ==="
ls "$DST/hal/sensors/" "$DST/init/" "$DST/vintf/" 2>&1 | head -20
echo
echo "=== spawn m -j8 (setsid + nohup) ==="
setsid nohup bash /mnt/d/AETHER/wsl-scripts/phase5_build.sh > /dev/null 2>&1 < /dev/null &
disown
echo "    spawned"
sleep 8
echo
echo "=== processes ==="
ps -eo pid,etime,stat,cmd | grep -E "soong_ui|phase5_build" | grep -v grep | head -5
echo
echo "=== build.log tail ==="
tail -20 ~/aosp/build.log 2>/dev/null
