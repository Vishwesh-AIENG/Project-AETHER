#!/bin/bash
# Phase 2.2 — repo sync. Long-running (4-12 hours). Logged to ~/aosp/sync.log.
set -e
export PATH=~/.bin:$PATH
cd ~/aosp
exec > ~/aosp/sync.log 2>&1
echo "=== repo sync started $(date) ==="
echo "=== nproc: $(nproc) ==="
echo "=== df before ==="; df -h ~
repo sync -c -j$(nproc) --no-clone-bundle --no-tags --force-sync
SYNC_EXIT=$?
echo
echo "=== repo sync finished $(date) with exit=$SYNC_EXIT ==="
echo "=== df after ==="; df -h ~
echo
echo "=== smoke checks (the 4 paths the original script verifies) ==="
ls -d build/make device frameworks/base packages/apps/Settings external/avb 2>&1
exit $SYNC_EXIT
