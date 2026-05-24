#!/usr/bin/env bash
# Fetch and extract a pinned Android GSI ARM64 system.img for the AT-5
# decoder coverage audit (full 21-library sweep).
#
# Usage:
#   ./scripts/fetch_gsi.sh
#   GSI_BUILD_ID=<latest> ./scripts/fetch_gsi.sh   # override pinned build
#
# After running, the 21 AOT default libraries are placed under
# `corpus/system_img/` and `cargo test -p aether-translator --test at5_system_img`
# can be run.
#
# Tooling requirements (script verifies and reports cleanly if missing):
#   - curl              (universally available)
#   - 7z OR unzip       (for the AOSP zip wrapper)
#   - simg2img          (Android sparse → raw image — part of android-sdk-platform-tools)
#   - 7z OR Linux mount (for ext4 extraction; 7z 21+ with `Ext` plugin works)
#
# Windows fallback (no admin):
#   Download `7-Zip 25.00 x64 standalone` from https://www.7-zip.org/a/7z2500-x64.exe
#   and place `7z.exe` somewhere in PATH (e.g., %USERPROFILE%/portable).
#   Download `simg2img` from Android platform-tools:
#     https://dl.google.com/android/repository/platform-tools-latest-windows.zip
#   Extract simg2img.exe to your PATH.
#
# WSL/Linux preferred path:
#   apt install simg2img p7zip-full
#
# See https://github.com/Vishwesh-AIENG/Project-AETHER/blob/sandbox/aether-translator/aether-translator/README.md
# for the full corpus workflow.

set -euo pipefail

# ---- Pinned build (refresh as GSI builds rotate; ci.android.com retains ~30 days) ----
# To find a current build:
#   1. Visit https://ci.android.com/builds/branches/aosp-main/grid
#   2. Click a green "aosp_arm64" cell
#   3. Copy the build number into GSI_BUILD_ID below or via env var
GSI_BUILD_ID="${GSI_BUILD_ID:-12678901}"
GSI_TARGET="${GSI_TARGET:-aosp_arm64-img-${GSI_BUILD_ID}.zip}"
GSI_URL="https://ci.android.com/builds/submitted/${GSI_BUILD_ID}/aosp_arm64/latest/raw/${GSI_TARGET}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${HERE}/corpus/system_img"
WORK="${HERE}/corpus/.gsi-work"

# Tool discovery — be explicit about what's missing.
need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "MISSING TOOL: $1" >&2
        echo "  See header comment in this script for install hints." >&2
        return 1
    fi
}
need_tool curl

EXTRACTOR=""
if command -v 7z >/dev/null 2>&1; then
    EXTRACTOR="7z"
elif command -v unzip >/dev/null 2>&1; then
    EXTRACTOR="unzip"
else
    echo "MISSING TOOL: 7z or unzip (need one)" >&2
    exit 1
fi

mkdir -p "${CORPUS}" "${WORK}"

if [[ ! -f "${WORK}/${GSI_TARGET}" ]]; then
    echo "Downloading ${GSI_TARGET} from ${GSI_URL} ..."
    if ! curl -L --fail -o "${WORK}/${GSI_TARGET}" "${GSI_URL}"; then
        echo "ERROR: download failed. The build ID ${GSI_BUILD_ID} may have rotated." >&2
        echo "       Visit https://ci.android.com/builds/branches/aosp-main/grid to find a current build." >&2
        exit 1
    fi
fi

# Sanity-check the download isn't a tiny error page.
size=$(stat -c%s "${WORK}/${GSI_TARGET}" 2>/dev/null || stat -f%z "${WORK}/${GSI_TARGET}")
if [[ "${size}" -lt 100000 ]]; then
    echo "ERROR: download is ${size} bytes — likely an error response, not the real GSI." >&2
    echo "       Re-check GSI_BUILD_ID; current builds are listed at ci.android.com." >&2
    exit 1
fi

echo "Unpacking GSI wrapper zip ..."
if [[ "${EXTRACTOR}" == "7z" ]]; then
    (cd "${WORK}" && 7z x -y "${GSI_TARGET}" >/dev/null)
else
    (cd "${WORK}" && unzip -o "${GSI_TARGET}" >/dev/null)
fi

if [[ ! -f "${WORK}/system.img" ]]; then
    echo "ERROR: system.img not found inside ${GSI_TARGET}" >&2
    exit 1
fi

echo "Converting sparse → raw ..."
if command -v simg2img >/dev/null 2>&1; then
    simg2img "${WORK}/system.img" "${WORK}/system.raw.img"
else
    echo "WARNING: simg2img not installed; treating system.img as raw."
    echo "         If extraction below fails, install android-platform-tools."
    cp "${WORK}/system.img" "${WORK}/system.raw.img"
fi

AOT_LIBS=(
    libc.so libm.so libdl.so libart.so libartbase.so libartpalette.so
    libhwui.so libgui.so libsurfaceflinger.so libui.so libbinder.so
    libbinder_ndk.so libutils.so libcutils.so libandroid_runtime.so
    libvulkan.so libEGL.so libGLESv2.so libsqlite.so libssl.so libcrypto.so
)

# Preferred extraction: Linux loopback mount as root.
if [[ "$(uname -s)" == "Linux" ]] && [[ "${EUID:-0}" -eq 0 ]]; then
    MOUNTPOINT="${WORK}/mnt"
    mkdir -p "${MOUNTPOINT}"
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
    # Fallback: 7-Zip 21+ can read ext4 with the Ext plugin (Windows + macOS).
    echo "Trying 7-Zip ext4 extraction (Windows/macOS path) ..."
    if [[ "${EXTRACTOR}" == "7z" ]]; then
        (cd "${WORK}" && 7z x -y -o"system_extract" "system.raw.img" >/dev/null || true)
        for lib in "${AOT_LIBS[@]}"; do
            path="$(find "${WORK}/system_extract" -name "${lib}" -type f -print -quit 2>/dev/null || true)"
            if [[ -n "${path}" ]]; then
                cp "${path}" "${CORPUS}/${lib}"
            else
                echo "MISSING IN GSI: ${lib}" >&2
            fi
        done
    else
        echo "ERROR: only Linux loopback mount or 7-Zip 21+ Ext plugin can read ext4." >&2
        echo "       On Windows: install 7-Zip 21+ (https://www.7-zip.org/)." >&2
        echo "       On WSL/Linux: run this script as root." >&2
        exit 1
    fi
fi

# Record what we have.
(cd "${CORPUS}" && sha256sum *.so 2>/dev/null > SHA256SUMS || true)

count=$(ls -1 "${CORPUS}"/*.so 2>/dev/null | wc -l)
echo "Done. ${count}/${#AOT_LIBS[@]} AOT libraries extracted to ${CORPUS}"
