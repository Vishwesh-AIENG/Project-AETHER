#!/usr/bin/env bash
# Delete EVERY zero-byte file under out/. Power-outage debris that's not an
# archive (so missed by sweep_corrupt_jars.sh) also wedges ninja because
# ninja sees a valid mtime and treats the file as built-and-up-to-date,
# even though the file is empty.
#
# We unconditionally delete every zero-byte file — ninja will detect them
# missing and re-run the producing rule.
set -u
echo "=== scanning out/ for zero-byte files ==="
COUNT=0
TMP=/tmp/zero_files.list
: > "$TMP"
find /root/aosp/out -type f -size 0 2>/dev/null > "$TMP"
COUNT=$(wc -l < "$TMP")
echo "found $COUNT zero-byte files"
if [ "$COUNT" -gt 0 ]; then
  echo "--- sample (first 20) ---"
  head -20 "$TMP"
  echo "--- deleting ---"
  xargs -d '\n' -a "$TMP" rm -f 2>&1 | head -10
  echo "done"
fi
echo "log: $TMP"
