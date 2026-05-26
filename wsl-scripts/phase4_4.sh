#!/bin/bash
set -e
export PATH="$HOME/.cargo/bin:$PATH"
cd /mnt/d/AETHER

echo "=== 4.4 hypervisor lib tests ==="
cargo +nightly test --lib -p hypervisor 2>&1 | grep -E "^test result:|FAILED" | tail -5

echo
echo "=== 4.4 translator tests ==="
cargo +nightly test -p aether-translator 2>&1 | grep -E "^test result:|FAILED" | tail -3
echo
echo "=== summary ==="
echo "If any line above says FAILED, something regressed; otherwise all green."
