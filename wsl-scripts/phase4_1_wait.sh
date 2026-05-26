#!/bin/bash
until ! pgrep -x rustup >/dev/null 2>&1; do
    sleep 5
done
echo "rustup done"
export PATH="$HOME/.cargo/bin:$PATH"
echo
echo "=== verify ==="
rustc --version
cargo --version
echo "=== installed targets ==="
rustup target list --installed
