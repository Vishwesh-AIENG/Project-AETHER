#!/bin/bash
export PATH=~/.bin:$PATH
cd ~/aosp
echo "=== mop-up process state ==="
pgrep -fa "sync_mopup\|repo.*sync" 2>/dev/null | head -3 || echo "(no sync running)"
echo
echo "=== sync2.log tail ==="
tail -15 ~/aosp/sync2.log 2>/dev/null || echo "(no sync2.log)"
echo
echo "=== sync2.log error counts ==="
if [ -f ~/aosp/sync2.log ]; then
    echo "  Cannot initialize work tree:  $(grep -c 'Cannot initialize work tree' ~/aosp/sync2.log)"
    echo "  Cannot checkout:              $(grep -c 'Cannot checkout' ~/aosp/sync2.log)"
    echo "  Connection reset:             $(grep -c 'Connection reset' ~/aosp/sync2.log)"
fi
echo
echo "=== disk + project sanity ==="
du -sh ~/aosp 2>/dev/null
df -h ~ | tail -1
echo "  projects: $(repo list 2>/dev/null | wc -l)"
echo "  workdirs: $(repo list -p 2>/dev/null | while read p; do [ -e "$p/.git" ] && echo 1; done | wc -l)"
echo
echo "=== required-for-build paths ==="
for p in build/make build/soong frameworks/base packages/apps/Settings external/avb art bionic libcore system/core prebuilts/clang/host/linux-x86 prebuilts/build-tools; do
    if [ -d ~/aosp/$p ]; then echo "  OK    $p"; else echo "  MISS  $p"; fi
done
