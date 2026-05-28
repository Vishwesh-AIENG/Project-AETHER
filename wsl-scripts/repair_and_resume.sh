#!/bin/bash
# Repair after a hard-kill (power outage etc.) of an AOSP `m` build, then resume.
#
# Strategy:
#   1. Kill any leftover processes (paranoia — they shouldn't survive the host
#      reboot but if WSL2 was suspended/resumed weirdly, check).
#   2. Remove stale lock files (.ninja_lock, soong/.bootstrap.lock).
#   3. Detect zero-length / truncated intermediates that ninja would
#      mistakenly trust as "built". Common signatures: empty .o files, empty
#      .so files, partially-written .jar files.
#   4. Remove any obviously-broken outputs so ninja re-builds them.
#   5. Resume `m -j8`. Ninja's mtime tracking handles the rest.
echo "=== 1. kill leftover processes ==="
for proc in phase5_build.sh soong_ui ninja kati ckati clang clang++ javac d8 r8 zip aapt2; do
    pkill -9 -x "$proc" 2>/dev/null && echo "  killed $proc"
done
sleep 1

echo
echo "=== 2. remove stale lock files ==="
removed=0
for lock in \
    /root/aosp/out/.ninja_lock \
    /root/aosp/out/soong/.bootstrap.lock \
    /root/aosp/out/soong/.bootstrap/.ninja_lock \
    /root/aosp/.repo/repo/.repopickle_config.lock \
    /root/aosp/out/build_date.txt.lock
do
    if [ -e "$lock" ]; then
        rm -f "$lock" && echo "  removed $lock" && removed=$((removed+1))
    fi
done
[ $removed -eq 0 ] && echo "  (no stale locks)"

echo
echo "=== 3. zero-length intermediate sweep (ALL file types) ==="
# ANY zero-byte file under out/ that ninja or kati produced is suspect.
# The narrow filter (.o/.so/.a/.jar/.dex) missed XML/TOC/RES/RSP files
# that also lethally cached as 0 bytes after a power cut and made later
# build runs fail with cryptic parser errors. Sweep everything.
# Locks and intentional 0-byte markers will simply be recreated on demand.
zero_count=$(find /root/aosp/out -type f -size 0 2>/dev/null | wc -l)
echo "  zero-length files (all types): $zero_count"
if [ "$zero_count" -gt 0 ]; then
    echo "  removing them..."
    find /root/aosp/out -type f -size 0 -delete 2>/dev/null
fi

echo
echo "=== 4. check ninja state files for truncation ==="
for f in /root/aosp/out/.ninja_log /root/aosp/out/.ninja_deps; do
    if [ -f "$f" ]; then
        size=$(stat -c%s "$f")
        printf "  %s: %d bytes\n" "$f" "$size"
        # .ninja_log has a "# ninja log v5" header. If file is non-empty but
        # missing that header, it's truncated — better to remove (ninja
        # rebuilds it).
        if [ "$size" -gt 0 ] && ! head -1 "$f" 2>/dev/null | grep -q "^# ninja log"; then
            if [ "$(basename "$f")" = ".ninja_log" ]; then
                echo "    .ninja_log truncated — removing (ninja rebuilds)"
                rm -f "$f"
            fi
        fi
    fi
done

echo
echo "=== 5. disk + memory state ==="
df -h /root | tail -1
free -h | head -2
du -sh /root/aosp/out 2>/dev/null

echo
echo "=== 6. resume m -j8 ==="
setsid nohup bash /mnt/d/AETHER/wsl-scripts/phase5_build.sh > /dev/null 2>&1 < /dev/null &
disown
sleep 6
echo "  processes:"
ps -eo pid,etime,stat,cmd | grep -E "soong_ui|phase5_build|kati|ninja" | grep -v grep | head -6
echo
echo "  build.log tail:"
tail -8 /root/aosp/build.log
