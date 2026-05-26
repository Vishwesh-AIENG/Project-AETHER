#!/bin/bash
set -e
echo "=== 4.1 Rust nightly + UEFI targets ==="
if [ ! -d "$HOME/.cargo" ]; then
    echo "  installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain nightly --component rust-src
else
    echo "  ~/.cargo exists; ensuring nightly + rust-src"
fi
. "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src 2>&1 | tail -3
rustup component add rust-src --toolchain nightly 2>&1 | tail -3
rustup target add aarch64-unknown-uefi --toolchain nightly 2>&1 | tail -3
rustup target add x86_64-unknown-uefi --toolchain nightly 2>&1 | tail -3
echo
echo "=== verify ==="
rustc +nightly --version
cargo +nightly --version
rustup +nightly target list --installed | head -10
