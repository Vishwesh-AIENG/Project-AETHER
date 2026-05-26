#!/bin/bash
export PATH=~/.bin:$PATH
cd ~/aosp
echo "=== state of each problem project ==="
for p in bionic art bootable/recovery bootable/libbootloader; do
    echo "--- $p ---"
    if [ ! -d "$p" ]; then
        echo "  MISSING DIR"
        continue
    fi
    pushd "$p" >/dev/null
    echo "  HEAD:           $(git rev-parse --short HEAD 2>&1)"
    echo "  current branch: $(git symbolic-ref --short HEAD 2>&1 || echo detached)"
    echo "  status:         $(git status --porcelain 2>&1 | wc -l) lines"
    # First 5 lines if anything is dirty
    git status --porcelain 2>&1 | head -3 | sed 's/^/    /'
    echo "  manifest wants: $(cd ~/aosp && repo forall $p -c 'echo $REPO_RREV' 2>&1 | head -1)"
    popd >/dev/null
done
echo
echo "=== try targeted repo sync for these 4 only ==="
repo sync -c -j1 --force-sync --no-clone-bundle --no-tags \
    bionic art bootable/recovery bootable/libbootloader 2>&1 | tail -20
echo
echo "=== verify after ==="
for p in bionic art bootable/recovery bootable/libbootloader; do
    pushd ~/aosp/$p >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  $p: HEAD=$(git rev-parse --short HEAD)"
        popd >/dev/null
    fi
done
