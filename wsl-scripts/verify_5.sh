#!/bin/bash
export PATH=~/.bin:$PATH
echo "=== compare HEAD vs tag-target commit (not tag-object SHA) ==="
for p in bionic art bootable/recovery bootable/libbootloader; do
    cd ~/aosp/$p
    head=$(git rev-parse HEAD)
    # Dereference the tag to the commit it points to (^{})
    tag_commit=$(git rev-parse 'refs/tags/android-14.0.0_r74^{}' 2>/dev/null)
    if [ "$head" = "$tag_commit" ]; then
        echo "  $p:  HEAD == tag commit  ✓"
    else
        echo "  $p:  HEAD != tag commit  ✗"
        echo "         HEAD:       $head"
        echo "         tag commit: $tag_commit"
    fi
done
echo
echo "=== final repo status — anything dirty or unsynced? ==="
cd ~/aosp
repo status -j16 2>&1 | grep -v "^$" | head -20
echo
echo "=== ready-to-build paths still present ==="
for p in build/make build/soong frameworks/base packages/apps/Settings external/avb art bionic libcore system/core prebuilts/clang/host/linux-x86 prebuilts/build-tools device/aether/aether_arm64 vendor/microg/GmsCore; do
    if [ -d ~/aosp/$p ]; then echo "  OK    $p"; else echo "  MISS  $p"; fi
done
