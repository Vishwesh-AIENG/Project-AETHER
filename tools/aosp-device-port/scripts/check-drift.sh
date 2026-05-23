#!/usr/bin/env bash
#
# check-drift.sh — confirm every CONFIG_ entry in
# hypervisor/src/kernel_defconfig.rs::AETHER_GKI_DEFCONFIG and
# hypervisor/src/adreno_render.rs::ADRENO_RENDER_DEFCONFIG appears in
# tools/aosp-device-port/device/aether/arm64/kernel/aether_gki_defconfig
# with the correct y / n / m value.
#
# Run from the repo root:
#   bash tools/aosp-device-port/scripts/check-drift.sh
#
# Exit codes:
#   0  no drift
#   1  drift detected
#   2  script error / files missing
#
# This is a structural gate; the runtime gate is AetherDefconfigGate in
# hypervisor/src/kernel_defconfig.rs (validates a parsed GkiConfig).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DEFCONFIG="$REPO_ROOT/tools/aosp-device-port/device/aether/arm64/kernel/aether_gki_defconfig"
RUST_SRC_GKI="$REPO_ROOT/hypervisor/src/kernel_defconfig.rs"
RUST_SRC_ADRENO="$REPO_ROOT/hypervisor/src/adreno_render.rs"

if [[ ! -r "$DEFCONFIG" ]]; then
    echo "error: defconfig template missing: $DEFCONFIG" >&2
    exit 2
fi
if [[ ! -r "$RUST_SRC_GKI" ]]; then
    echo "error: kernel_defconfig.rs missing: $RUST_SRC_GKI" >&2
    exit 2
fi
if [[ ! -r "$RUST_SRC_ADRENO" ]]; then
    echo "error: adreno_render.rs missing: $RUST_SRC_ADRENO" >&2
    exit 2
fi

drift=0

check_required() {
    local name="$1"
    if ! grep -qE "^${name}=[ym]\$" "$DEFCONFIG"; then
        echo "drift: ${name} required but not enabled (=y or =m) in $DEFCONFIG"
        drift=$((drift + 1))
    fi
}

check_disabled() {
    local name="$1"
    # Either commented "# CONFIG_X is not set" or explicitly =n.
    if ! grep -qE "^# ${name} is not set\$|^${name}=n\$" "$DEFCONFIG"; then
        echo "drift: ${name} must be disabled in $DEFCONFIG"
        drift=$((drift + 1))
    fi
}

# Extract must_enable("CONFIG_*") names from kernel_defconfig.rs.
while IFS= read -r name; do
    check_required "$name"
done < <(grep -oE 'must_enable\(b"(CONFIG_[A-Z0-9_]+)"\)' "$RUST_SRC_GKI" \
         | sed -E 's/must_enable\(b"(CONFIG_[A-Z0-9_]+)"\)/\1/' \
         | sort -u)

# Extract must_disable("CONFIG_*") names from kernel_defconfig.rs.
while IFS= read -r name; do
    check_disabled "$name"
done < <(grep -oE 'must_disable\(b"(CONFIG_[A-Z0-9_]+)"\)' "$RUST_SRC_GKI" \
         | sed -E 's/must_disable\(b"(CONFIG_[A-Z0-9_]+)"\)/\1/' \
         | sort -u)

# Extract AdrenoKernelEntry::required(b"CONFIG_*") from adreno_render.rs.
while IFS= read -r name; do
    check_required "$name"
done < <(grep -oE 'required\(\s*b"(CONFIG_[A-Z0-9_]+)"' "$RUST_SRC_ADRENO" \
         | sed -E 's/.*b"(CONFIG_[A-Z0-9_]+)".*/\1/' \
         | sort -u)

# Extract AdrenoKernelEntry::forbidden(b"CONFIG_*") from adreno_render.rs.
while IFS= read -r name; do
    check_disabled "$name"
done < <(grep -oE 'forbidden\(\s*b"(CONFIG_[A-Z0-9_]+)"' "$RUST_SRC_ADRENO" \
         | sed -E 's/.*b"(CONFIG_[A-Z0-9_]+)".*/\1/' \
         | sort -u)

if (( drift > 0 )); then
    echo
    echo "FAIL: ${drift} drift entries between AETHER_GKI_DEFCONFIG / ADRENO_RENDER_DEFCONFIG and template defconfig."
    echo "Reconcile by editing $DEFCONFIG to match the Rust constants, or"
    echo "update the Rust constants if the spec genuinely changed."
    exit 1
fi

echo "OK: defconfig template matches AETHER_GKI_DEFCONFIG + ADRENO_RENDER_DEFCONFIG."
exit 0
