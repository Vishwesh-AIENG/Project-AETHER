#!/usr/bin/env bash
# Find and delete jar files corrupted by the power outage.
# A valid zip has a known magic / valid central directory. Java's turbine
# bails on the first invalid zip it touches, so we have to scan exhaustively.
set -u
cd /root/aosp

echo "=== scanning out/soong/.intermediates for corrupt .jar/.apk/.zip ==="
echo "(this may take 2-5 minutes — there are tens of thousands of jars)"
echo

CORRUPT_LOG=/tmp/corrupt_archives.log
: > "$CORRUPT_LOG"

# unzip -t exits non-zero on corrupt zips. Suppress -t verbose output.
# Limit to files modified before the resume (mtime older than build.log)
# to avoid racing the current build — but the build has already failed,
# so we just scan everything.
TOTAL=0
BAD=0
while IFS= read -r f; do
  TOTAL=$((TOTAL+1))
  if ! unzip -t "$f" >/dev/null 2>&1; then
    BAD=$((BAD+1))
    sz=$(stat -c '%s' "$f" 2>/dev/null)
    echo "CORRUPT  size=$sz  $f" | tee -a "$CORRUPT_LOG"
  fi
  if [ $((TOTAL % 5000)) -eq 0 ]; then
    echo "  ... scanned $TOTAL files, $BAD corrupt so far"
  fi
done < <(find /root/aosp/out -type f \( -name '*.jar' -o -name '*.apk' -o -name '*.zip' -o -name '*.srcjar' -o -name '*.aar' -o -name '*.ziplist' \) 2>/dev/null)

echo
echo "=== summary ==="
echo "scanned: $TOTAL archives"
echo "corrupt: $BAD"
echo "log:     $CORRUPT_LOG"

if [ "$BAD" -gt 0 ]; then
  echo
  echo "=== deleting corrupt archives ==="
  while read line; do
    f=$(echo "$line" | awk -F'  ' '{print $NF}')
    if [ -f "$f" ]; then
      rm -f "$f" && echo "  rm  $f"
    fi
  done < "$CORRUPT_LOG"
  echo "deleted $BAD corrupt archives — ninja will rebuild them"
else
  echo "no corruption found"
fi
