#!/bin/bash
# Second-pass repo sync: mop up the 90+ projects that failed work-tree init
# during the first pass. Lower -j to avoid the parallel-checkout race that
# caused the initial failures. Objects are already in .repo/projects/ for
# most projects, so this is fast.
export PATH=~/.bin:$PATH
cd ~/aosp
exec > ~/aosp/sync2.log 2>&1
echo "=== mop-up repo sync started $(date) ==="
echo "=== nproc: $(nproc) — using -j4 to avoid the work-tree race ==="
df -h ~ | tail -1
echo
repo sync -c -j4 --no-clone-bundle --no-tags --force-sync
SYNC_EXIT=$?
echo
echo "=== mop-up finished $(date) with exit=$SYNC_EXIT ==="
df -h ~ | tail -1
echo
echo "=== remaining workdir gaps ==="
repo list -p 2>/dev/null | while read -r p; do
    [ ! -e "$p/.git" ] && echo "MISS $p"
done | wc -l
exit $SYNC_EXIT
