#!/bin/bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /mnt/d/AETHER
out=$(cargo +nightly test -p aether-translator 2>&1)
total_pass=$(echo "$out" | grep -oE '^test result: ok\. [0-9]+' | awk '{ s += $4 } END { print s }')
fail_count=$(echo "$out" | grep -cE '^test .* FAILED$')
echo "translator: total_passed=$total_pass FAILED_count=$fail_count"
