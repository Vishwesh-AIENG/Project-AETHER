#!/usr/bin/env bash
# Force-kill anything related to the AOSP build. Idempotent.
for pat in phase5_build soong_ui ckati ninja turbine javac kotlinc d8 r8 aapt2 metalava ; do
  pkill -9 -f "$pat" 2>/dev/null
done
sleep 2
left=$(ps -ef | grep -Ec '(phase5|soong|ninja|ckati|turbine|javac|kotlinc|metalava|aapt2)' || true)
left=$((left - 1)) # subtract the grep itself
echo "stale procs after hammer: $left"
ps -ef | grep -E '(phase5|soong|ninja|ckati|turbine|javac|kotlinc|metalava|aapt2)' | grep -v grep || echo "(none)"
