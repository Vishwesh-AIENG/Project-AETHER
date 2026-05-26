#!/bin/bash
export PATH=~/.bin:$PATH
cd ~/aosp
echo "=== verify HEAD matches manifest tag for the 4 problem projects ==="
for p in bionic art bootable/recovery bootable/libbootloader; do
    echo "--- $p ---"
    cd ~/aosp/$p
    head_sha=$(git rev-parse HEAD)
    # The manifest revision is android-14.0.0_r74. Check what that tag points to.
    tag_sha=$(git rev-parse refs/tags/android-14.0.0_r74 2>/dev/null \
              || git rev-parse android-14.0.0_r74 2>/dev/null \
              || echo "TAG_NOT_LOCAL")
    echo "  HEAD:       $head_sha"
    echo "  tag points: $tag_sha"
    if [ "$head_sha" = "$tag_sha" ]; then
        echo "  RESULT:     OK ✓"
    else
        # Maybe tag isn't fetched. Check via remote.
        echo "  RESULT:     MISMATCH (or tag not locally fetched)"
        # Show whether current HEAD is on the tag line
        if git merge-base --is-ancestor "$head_sha" "$tag_sha" 2>/dev/null; then
            echo "             HEAD is ancestor of tag → behind by:"
            git rev-list --count "$head_sha..$tag_sha" 2>&1
        elif git merge-base --is-ancestor "$tag_sha" "$head_sha" 2>/dev/null; then
            echo "             HEAD is descendant of tag → ahead by:"
            git rev-list --count "$tag_sha..$head_sha" 2>&1
        fi
    fi
done
echo
echo "=== overall repo verify ==="
cd ~/aosp
# repo status shows which projects have local changes / unsynced commits
repo status -j16 2>&1 | tail -10
