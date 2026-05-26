#!/bin/bash
echo "=== process ==="
pgrep -fa "repo.*sync" 2>/dev/null | head -3 || echo "(no repo sync process — first pass exited)"

echo
echo "=== aosp footprint ==="
du -sh ~/aosp 2>/dev/null
df -h ~ | tail -1

echo
echo "=== smoke checks ==="
for p in build/make device frameworks/base packages/apps/Settings external/avb art bionic libcore prebuilts/clang/host/linux-x86; do
    if [ -d ~/aosp/$p ]; then
        echo "  OK    ~/aosp/$p"
    else
        echo "  MISS  ~/aosp/$p"
    fi
done

echo
echo "=== error counts ==="
echo "  work-tree errors:  $(grep -c 'Cannot initialize work tree' ~/aosp/sync.log)"
echo "  checkout errors:   $(grep -c 'Cannot checkout' ~/aosp/sync.log)"
echo "  Connection reset:  $(grep -c 'Connection reset' ~/aosp/sync.log)"
echo "  GitCommandError:   $(grep -c 'GitCommandError' ~/aosp/sync.log)"

echo
echo "=== final summary lines ==="
grep -E "additional errors|Syncing|complete" ~/aosp/sync.log | tail -5

echo
echo "=== project count actually checked out ==="
ls ~/aosp/.repo/projects/ 2>/dev/null | wc -l
echo "      (vs. expected manifest project count — check via:"
echo "       cd ~/aosp && repo list 2>/dev/null | wc -l)"
