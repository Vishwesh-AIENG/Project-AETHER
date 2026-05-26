#!/bin/bash
echo "=== process state ==="
if pgrep -fa "soong_ui\|phase5_build\|kati\|^ninja" 2>/dev/null | head -3; then
    echo
    pgrep -fa "phase5_build" 2>/dev/null | head -1 \
        | awk '{print "  build wrapper PID="$1, "elapsed="; system("ps -o etime= -p "$1)}'
fi
echo
echo "=== build.log tail (last 30) ==="
tail -30 ~/aosp/build.log 2>/dev/null
echo
echo "=== build.log error/warning counts ==="
[ -f ~/aosp/build.log ] && {
    echo "  log lines:  $(wc -l < ~/aosp/build.log)"
    echo "  error:      $(grep -c -E '^FAILED|^error:|^Error:|^ninja: error|ERROR ' ~/aosp/build.log)"
    echo "  warning:    $(grep -c -i 'warning' ~/aosp/build.log)"
}
echo
echo "=== disk usage ==="
du -sh ~/aosp/out 2>/dev/null
df -h ~ | tail -1
echo
echo "=== progress signal — ninja % ==="
grep -oE '\[ *[0-9]+% [0-9]+/[0-9]+\]' ~/aosp/build.log 2>/dev/null | tail -3
echo
echo "=== outputs produced so far ==="
ls ~/aosp/out/target/product/aether_arm64/ 2>/dev/null | head -20
