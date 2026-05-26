# `device/aether/aether_arm64/` — AOSP device tree for the AETHER ARM64 Android partition

Mechanically derived from `hypervisor/src/aosp_build.rs`. Drop this directory
into a synced AOSP tree at `device/aether/aether_arm64/` and `lunch
aether_arm64-user` becomes a valid build target.

## Files in this drop

| File | Source of truth | What it does |
|---|---|---|
| `AndroidProducts.mk` | `AETHER_LUNCH_TARGET` | Registers `aether_arm64-user` in the lunch menu |
| `aether_arm64.mk` | `AospBuildConfig::default_aether()` | Product makefile — composes AOSP base + AETHER device.mk + product identity |
| `BoardConfig.mk` | `BoardConfigMk::AETHER_DEFAULT` + `BoardPartitionSizes::AETHER_DEFAULT` | TARGET_ARCH, partition sizes, AVB keys, SELinux mode, dynamic-partitions, A/B |
| `device.mk` | `AETHER_PRODUCT_PACKAGES` + `AETHER_COPY_FILES` + `AETHER_PROPERTY_OVERRIDES` | The packages / files / properties that ship in the image |
| `Android.bp` | `AETHER_SOONG_MODULES` | The 5 virtual HAL services + Gralloc + 2 prebuilts |
| `vendorsetup.sh` | (convenience) | Sources the lunch combo + adds `aether_build` / `aether_quickboot` / `aether_clean` aliases |
| `fstab.aether` | `PartitionLayout` (ch21) | First-stage mount fstab — system / vendor / product / userdata |
| `manifest.xml` | `TrebleManifest` (ch21) | VINTF manifest declaring the 8 HALs |
| `configs/audio_policy_configuration.xml` | Minimum stub | Single primary speaker output — satisfies build |
| `configs/media_codecs.xml` | Minimum stub | Software H.264 + AAC encode/decode |
| `configs/media_profiles.xml` | Minimum stub | 720p + 480p MediaRecorder profiles |
| `configs/handheld_core_hardware.xml` | `DeviceProperties` (ch21) | Declared hardware features (touchscreen / WiFi / sensors / GPU) |
| `configs/network_security_config.xml` | Production-safe default | Cleartext disabled except for RFC1918 + localhost |
| `sepolicy/file_contexts` | AETHER HAL binary list | SELinux file labels for HAL binaries + `/dev/aether/*` |
| `sepolicy/device.te` | — | Declares the `aether_device` SELinux type used in file_contexts |

## How to use it

```bash
# Inside WSL2 (or a Linux machine), after `repo sync`:
cd $AOSP_ROOT
cp -r /mnt/d/AETHER/aosp/device/aether device/aether
# or, from inside this repo:
# cp -r ~/AETHER/aosp/device/aether device/aether

# Build
source build/envsetup.sh
lunch aether_arm64-user
m -j$(nproc)

# Outputs at out/target/product/aether_arm64/:
#   boot.img, system.img, vendor.img, vbmeta.img, userdata.img,
#   super.img (dynamic partitions), dtbo.img
```

## What's NOT yet in this drop — known stubs / placeholders

The device tree is structurally complete: `lunch` will resolve, `m` will start
the build, partition images will be produced. But the following are minimum
stubs and will need real implementations before the resulting image actually
boots a polished user experience:

1. **HAL service C++ sources.** `Android.bp` references
   `hal/sensors/SensorsService.cpp`, `hal/radio/RadioService.cpp`, etc. These
   source files don't exist in this drop yet — implementing them is the
   ch47 / ch48 work that talks to the hypervisor's paravirt pages via HVC.
   Until those land, the build will fail with "file not found" on every
   `cc_binary` rule.

   **Workaround for a first dry-run build:** comment out the five `cc_binary`
   blocks in `Android.bp` and the `aether.*-service` lines in `device.mk`
   PRODUCT_PACKAGES. The image will boot to a Linux userspace but Android's
   service manager will report missing HALs and the home screen won't render.

2. **microG prebuilts.** `device.mk` lists `GmsCore` / `FakeStore` / `GsfProxy`
   / `UnifiedNlp` as PRODUCT_PACKAGES but doesn't ship them. Procedure:
   ```bash
   cd $AOSP_ROOT
   mkdir -p vendor/microg
   # GmsCore — clone from github.com/microg/GmsCore and follow upstream
   # build instructions; place the built APK + Android.bp under
   # vendor/microg/GmsCore/.
   # FakeStore + GsfProxy + UnifiedNlp follow the same pattern.
   ```

3. **Signature spoofing patch.** microG requires a `frameworks/base` patch
   that lets apps declare `<faked-signature>` in their manifest. AOSP doesn't
   ship this; pull it from LineageOS's `android_frameworks_base` (search for
   "signature spoofing" in their patch series) and apply via
   `repo` overlays.

4. **Kernel.** `BoardConfig.mk` has a commented-out `TARGET_PREBUILT_KERNEL`
   pointing at `kernel/aether-gki/Image`. AETHER's kernel needs to be built
   separately (Android GKI defconfig from `hypervisor/src/kernel_defconfig.rs`)
   and the resulting `arch/arm64/boot/Image` dropped at that path before
   `m bootimage` produces a bootable `boot.img`.

5. **AVB production keys.** Currently using AOSP's test keys
   (`external/avb/test/data/testkey_rsa4096.pem`). Fine for development;
   replace with real keys via `avbtool` before any public release.

## Validator alignment

This tree is the AOSP-side counterpart of `hypervisor/src/aosp_build.rs`. The
Rust-side `AospBuildConfig::default_aether().validate()` check passes when the
constants here exactly match the constants there. If you change one side,
re-run the hypervisor `cargo test --lib -p hypervisor` to catch drift
(`device_mk_*`, `board_config_*`, `android_bp_*`, `microg_integration_*`,
`aosp_build_config_*` tests).
