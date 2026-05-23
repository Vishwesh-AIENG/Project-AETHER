#!/usr/bin/env bash
# Fetch and extract a pinned Android GSI ARM64 system.img for the AT-5
# decoder coverage audit.
#
# Usage:
#   ./scripts/fetch_gsi.sh
#
# After running, the 21 AOT default libraries are placed under
# `corpus/system_img/` and `cargo test -p aether-translator --test at5_system_img`
# can be run.
#
# This is a developer convenience; the corpus is gitignored.

set -euo pipefail

# ---- Pin (update when refreshing) ----
# Android 14 GSI build id; use ci.android.com to refresh.
GSI_BUILD_ID="${GSI_BUILD_ID:-11580240}"
GSI_TARGET="${GSI_TARGET:-aosp_arm64-img-${GSI_BUILD_ID}.zip}"
GSI_URL="https://ci.android.com/builds/submitted/${GSI_BUILD_ID}/aosp_arm64/latest/raw/${GSI_TARGET}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${HERE}/corpus/system_img"
WORK="${HERE}/corpus/.gsi-work"

mkdir -p "${CORPUS}" "${WORK}"

if [[ ! -f "${WORK}/${GSI_TARGET}" ]]; then
    echo "Downloading ${GSI_TARGET} ..."
    curl -L --fail -o "${WORK}/${GSI_TARGET}" "${GSI_URL}"
fi

echo "Unpacking GSI ..."
(cd "${WORK}" && 7z x -y "${GSI_TARGET}" >/dev/null)

if [[ ! -f "${WORK}/system.img" ]]; then
    echo "ERROR: system.img not found inside ${GSI_TARGET}" >&2
    exit 1
fi

# Convert sparse to raw.
if command -v simg2img >/dev/null; then
    simg2img "${WORK}/system.img" "${WORK}/system.raw.img"
else
    echo "WARNING: simg2img not installed; assuming system.img is already raw."
    cp "${WORK}/system.img" "${WORK}/system.raw.img"
fi

# Extract the 21 AOT default .so files. Loopback mount on Linux; on WSL/macOS
# a 7z extraction works for ext4 images via the e2fsprogs build of 7z. The
# directory walk below is intentionally simple — refine in AT-5 fill if it
# proves fragile across GSI versions.
AOT_LIBS=(
    libc.so libm.so libdl.so libart.so libartbase.so libartpalette.so
    libhwui.so libgui.so libsurfaceflinger.so libui.so libbinder.so
    libbinder_ndk.so libutils.so libcutils.so libandroid_runtime.so
    libvulkan.so libEGL.so libGLESv2.so libsqlite.so libssl.so libcrypto.so
)

MOUNTPOINT="${WORK}/mnt"
mkdir -p "${MOUNTPOINT}"

if command -v mount >/dev/null && [[ "$(uname -s)" == "Linux" ]] && [[ "${EUID:-0}" -eq 0 ]]; then
    mount -o ro,loop "${WORK}/system.raw.img" "${MOUNTPOINT}"
    trap 'umount "${MOUNTPOINT}"' EXIT
    for lib in "${AOT_LIBS[@]}"; do
        path="$(find "${MOUNTPOINT}" -name "${lib}" -type f -print -quit || true)"
        if [[ -n "${path}" ]]; then
            cp "${path}" "${CORPUS}/${lib}"
        else
            echo "MISSING IN GSI: ${lib}" >&2
        fi
    done
else
    echo "Loopback mount unavailable; falling back to 7z extraction."
    (cd "${WORK}" && 7z x -y -o"system_extract" "system.raw.img" >/dev/null || true)
    for lib in "${AOT_LIBS[@]}"; do
        path="$(find "${WORK}/system_extract" -name "${lib}" -type f -print -quit || true)"
        if [[ -n "${path}" ]]; then
            cp "${path}" "${CORPUS}/${lib}"
        else
            echo "MISSING IN GSI: ${lib}" >&2
        fi
    done
fi

# Record what we have.
(cd "${CORPUS}" && sha256sum *.so > SHA256SUMS || true)

echo "Done. AT-5 corpus at ${CORPUS}"
