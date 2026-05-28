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

## Run 7

**Phase**: Kati late
**Outcome**: 1:30 — `vbmeta_system` + `vbmeta_vendor` chain partitions need explicit rollback index locations
**Fix for run 8**: `BoardConfig.mk` set `BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX_LOCATION := 1` and `BOARD_AVB_VBMETA_VENDOR_ROLLBACK_INDEX_LOCATION := 2`.

## Run 8

**Phase**: Kati 100% / writing module rules
**Outcome**: 1:45 — `build/make/core/base_rules.mk:497: error: overriding commands for target out/.../vendor/etc/vintf/manifest.xml`. Soong's `prebuilt_etc { name: "aether_vendor_manifest" }` collided with Make's `DEVICE_MANIFEST_FILE`.
**Fix for run 9**: removed the `aether_vendor_manifest` `prebuilt_etc` block from `Android.bp`; `DEVICE_MANIFEST_FILE` is the canonical Treble path because it triggers `assemble_vintf` to merge with per-HAL fragments.

## Run 9

**Phase**: Soong bootstrap
**Outcome**: 6:20 — kernel OOM killer fired; `soong_build` total-vm 37 GB, anon-rss 15 GB inside a 15 GiB WSL allocation
**Fix for run 10**: `C:\Users\<user>\.wslconfig` with `memory=26GB swap=24GB processors=8`; `wsl --shutdown`. No repo change. Free RAM went from 0 → ~24 GiB.

## Run 10

**Phase**: Kati 100%
**Outcome**: 4:50 — `vendor/microg/GmsCore/Android.mk:29: error: writing to readonly directory "vendor/microg/GmsCore/play-services-core/build/.../release-unsigned.apk"`. Upstream microG uses Gradle which targets paths under the source tree; AOSP `--werror_writable` forbids that.
**Fix for run 11**: commented out `GmsCore/FakeStore/GsfProxy/UnifiedNlp` from `device.mk` `PRODUCT_PACKAGES` AND renamed `vendor/microg/GmsCore/Android.mk` -> `.disabled` so Kati's recursive walk doesn't even parse it. microG defers until proper `Android.bp` shims exist.

## Run 11

**Phase**: ninja early
**Outcome**: 3:33 — `ninja: 'out/target/product/aether_arm64/kernel', needed by 'boot.img', missing and no known rule`. Tried `TARGET_PREBUILT_KERNEL` in BoardConfig.mk first but grep showed AOSP 14 build/make/core/Makefile no longer consumes that variable.
**Fix for run 12**: switched to `PRODUCT_COPY_FILES += device/linaro/dragonboard-kernel/android-6.1/Image.gz:kernel` in `device.mk`. AOSP 14's mechanism is to require the kernel to already exist at `$(PRODUCT_OUT)/kernel`, populated by the device tree via `PRODUCT_COPY_FILES`.

## Run 12

**Phase**: ninja (real compile)
**Outcome**: ran clean for the first time. Compile phase begun.
**Fix for run 13**: none; this run was healthy.

## Run 13

**Phase**: ninja mid-compile
**Outcome**: cut at ~1.5 hours, 36% absolute. Recovery sweep deleted 82 zero-length intermediates from in-flight writes.
**Fix for run 14**: `wsl-scripts/repair_and_resume.sh` (zero-length + lock sweep) + restart. `.ninja_log` (22 MB) survived.

## Run 14

**Phase**: ninja mid-compile
**Outcome**: 7:38 — kapt step on ManagedProvisioningLib hit `java.util.zip.ZipException: invalid zip archive`. The 82 zero-length files swept in run 13 were the obvious casualties; the `wsl --shutdown` forced post-hang also left several hundred non-zero-length but partially-written jars across the JAVA_LIBRARIES tree.
**Fix for run 15**: `wsl-scripts/sweep_corrupt_jars.sh` scans every `.jar/.apk/.zip` under `out/` via `unzip -t`, deletes the corrupt ones, lets ninja rebuild. 513 archives deleted including `metalava.jar`, `turbine.jar`, `r8.jar`, `signapk.jar`.

## Run 15

**Phase**: ninja early
**Outcome**: second outage; sweep deleted another 411 corrupt jars.
**Fix for run 16**: hardware-watchdog protections installed — `sync_loop.sh` (every 30s `sync` of WSL ext4 page cache) and a Windows Ctrl+Alt+S hotkey running `emergency_shutdown.ps1` which pauses build procs (SIGSTOP) + sync x3 + `wsl --shutdown` for a clean unmount. Caps outage damage from ~5 min of in-flight writes to ~30 s.

## Run 16

**Phase**: re-spawn check
**Outcome**: sanity-restart confirmed sync_loop + hotkey wiring before further iteration.
**Fix for run 17**: none.

## Run 17

**Phase**: ninja early (kapt fail again)
**Outcome**: extended sweep across `.srcjar/.aar/.ziplist` (originally only `.jar/.apk/.zip`) found 526 corrupt host-side tool jars under `out/host/linux-x86/framework/`. These came from the forced `wsl --shutdown` during an earlier VM hang — Hyper-V abandoned mid-write to the vhdx.
**Fix for run 18**: `wsl-scripts/sweep_corrupt_jars.sh` widened to cover those archive extensions.

## Run 18

**Phase**: pre-flight
**Outcome**: round-4 sweep scanned 8,521 archives, found 0 corrupt. Tree confirmed clean before run 19.
**Fix for run 19**: none.
