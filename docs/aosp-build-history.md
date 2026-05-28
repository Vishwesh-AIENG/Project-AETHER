# AOSP Build History — AETHER `aether_arm64`

Chronological ledger of every `m -j8` build attempt from initial bring-up
through the first successful image production. Each section documents one
build run: how far it got, what failed, and what fix went into the next
attempt.

Build environment: WSL2 Ubuntu-24.04 on Windows 11, AMD Ryzen, 8 cores,
AOSP `android-14.0.0_r74`, target `aether_arm64-ap2a-user`.


## Run 1

**Phase**: process spawn
**Outcome**: died at 3 s on SIGHUP — bash terminated when WSL invocation closed
**Fix for run 2**: wrap launcher with `setsid nohup ... </dev/null >/dev/null 2>&1 & disown`. No repo change; pattern adopted in `wsl-scripts/phase5_build.sh` later.

## Run 2

**Phase**: Kati legacy parse
**Outcome**: 31 s — `TARGET_CPU_VARIANT := cortex-a510` rejected
**Fix for run 3**: `BoardConfig.mk` TARGET_CPU_VARIANT switched to `cortex-a76` (modern but supported).

## Run 3

**Phase**: Soong analysis
**Outcome**: 18 s — `Android.bp:44` declared a non-existent module shape
**Fix for run 4**: rewrote HAL service modules with `cc_defaults` (aether_hal_defaults_hidl / aether_hal_defaults_aidl) and `cc_binary` consumers.

## Run 4

**Phase**: Kati legacy parse
**Outcome**: 6 min — `external/mesa3d/Android.mk:13: error: must be in PRODUCT_SOONG_NAMESPACES`
**Fix for run 5**: added `PRODUCT_SOONG_NAMESPACES += external/mesa3d` to `device.mk` (required by `BOARD_GPU_DRIVERS := freedreno`).

## Run 5

**Phase**: ninja early
**Outcome**: 12 min — wall power cut, host PC lost. Build state intact on vhdx but no in-flight syncs.
**Fix for run 6**: none required; restarted via `phase5_build.sh`.

## Run 6

**Phase**: Kati late
**Outcome**: 1:30 — AOSP 14 rejects `PRODUCT_COPY_FILES += .../vintf/manifest.xml:vendor/etc/vintf/manifest.xml`
**Fix for run 7**: moved manifest declaration to `BoardConfig.mk` `DEVICE_MANIFEST_FILE := device/aether/aether_arm64/manifest.xml`.
