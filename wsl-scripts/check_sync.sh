#!/bin/bash
echo "=== process state ==="
if pgrep -f "repo.*sync" >/dev/null; then
    echo "STATUS: STILL RUNNING"
    ps -eo pid,etime,pcpu,pmem,cmd | grep -E "repo.*sync|aosp" | grep -v grep | head -5
else
    echo "STATUS: NOT RUNNING (either finished or crashed)"
fi
echo
echo "=== sync.log tail (last 25 lines) ==="
tail -25 ~/aosp/sync.log 2>/dev/null || echo "(no sync.log)"
echo
echo "=== sync.log stats ==="
if [ -f ~/aosp/sync.log ]; then
    wc -l ~/aosp/sync.log
    echo "--- error count ---"
    grep -c "^error" ~/aosp/sync.log || echo 0
    grep -c "Cannot checkout" ~/aosp/sync.log || echo 0
    echo "--- 'Syncing:' progress lines (recent 5) ---"
    grep -E "Syncing|Updating|Fetching" ~/aosp/sync.log | tail -5
fi
echo
echo "=== disk usage ==="
du -sh ~/aosp 2>/dev/null
df -h ~ | tail -1
echo
echo "=== top-level dirs present so far ==="
ls -d ~/aosp/*/ 2>/dev/null | head -30
echo
echo "=== smoke checks (the 4 paths the original script verifies) ==="
for p in build/make device frameworks/base packages/apps/Settings external/avb; do
    if [ -d ~/aosp/$p ]; then echo "  OK    ~/aosp/$p"; else echo "  MISS  ~/aosp/$p"; fi
done
