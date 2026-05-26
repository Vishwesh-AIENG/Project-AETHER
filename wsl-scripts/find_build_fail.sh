#!/bin/bash
echo "=== lines BEFORE the Go panic — the real error is usually here ==="
grep -n -B1 -E "panic|fatal error|runtime error|Errors:|error:|FAILED" ~/aosp/build.log | head -60
echo
echo "=== explicit 'Errors:' block ==="
awk '/Errors:/,/Failed/' ~/aosp/build.log | head -40
echo
echo "=== first lines of any goroutine panic ==="
grep -n -E "^panic:|panic\(0x|fatal: " ~/aosp/build.log | head
echo
echo "=== look for any Android.bp reference in last 80 lines before panic ==="
sed -n '7600,7716p' ~/aosp/build.log | head -100
