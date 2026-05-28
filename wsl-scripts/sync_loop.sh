#!/usr/bin/env bash
# Continuous sync loop — flushes WSL2's ext4 page cache to the vhdx every
# SYNC_INTERVAL seconds. Reduces the amount of corrupt-mid-write data when
# the host loses power without warning.
#
# Run as: setsid nohup bash sync_loop.sh < /dev/null > /tmp/sync_loop.log 2>&1 & disown
SYNC_INTERVAL=${SYNC_INTERVAL:-30}
echo "[sync-loop] started pid=$$ interval=${SYNC_INTERVAL}s"
while true; do
  sync
  echo "[sync-loop] $(date -u +%T) flush done"
  sleep "$SYNC_INTERVAL"
done
