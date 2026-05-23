# AETHER AOSP Device Port

Templates for the AETHER Android device tree, copied into an external AOSP
checkout at `device/aether/arm64/` and `vendor/aether/` to produce
`boot.img` / `system.img` / `vendor.img` / `vbmeta.img` / `userdata.img`
for the `aether_arm64-user` lunch target.

The AOSP tree itself (≈300 GB) lives outside this repo. AETHER ships only
the device-specific contributions; everything else is upstream AOSP.

## Source of truth

The Rust constants in `hypervisor/src/aosp_build.rs`,
`hypervisor/src/kernel_defconfig.rs`, `hypervisor/src/userspace_boot.rs`,
`hypervisor/src/adreno_render.rs`, etc. are the authoritative spec. Every
template file here mirrors a constant in those modules. When the Rust
constant changes, the template file changes in the same commit.

`AospBuildGate` (`hypervisor/src/aosp_build.rs`) and the other phase gates
check at runtime that the produced images really do match — if a template
diverges from the spec, the gate fails the boot.

## Integration procedure

Pinned AOSP version: see `AOSP_VERSION` in this directory.

```sh
mkdir ~/aosp && cd ~/aosp
repo init -u https://android.googlesource.com/platform/manifest -b $(cat /path/to/AETHER/tools/aosp-device-port/AOSP_VERSION)
repo sync -c -j8                                           # ~300 GB, ~4 hours

aether-install --prepare-aosp-tree=$PWD                    # copies templates
# (under the hood: recursive copy of tools/aosp-device-port/device/...
#  and tools/aosp-device-port/vendor/... into the AOSP checkout)

source build/envsetup.sh
lunch aether_arm64-user                                    # must register without error
m -j$(nproc)                                               # ~2-4 hours first build

ls -lh out/target/product/aether/{boot,system,vendor,vbmeta,userdata}.img
```

All five image files exist, > 0 bytes, sizes within `BoardPartitionSizes::AETHER_DEFAULT`.

## Layout

```
tools/aosp-device-port/
├── README.md
├── AOSP_VERSION
├── scripts/
│   └── check-drift.sh                    # ensures defconfig matches AETHER_GKI_DEFCONFIG
├── device/aether/arm64/
│   ├── AndroidProducts.mk                # registers aether_arm64-user
│   ├── aether_arm64.mk                   # product makefile
│   ├── BoardConfig.mk                    # mirrors BoardConfigMk::AETHER_DEFAULT
│   ├── device.mk                         # PRODUCT_PACKAGES + PRODUCT_PROPERTY_OVERRIDES
│   ├── vendor.mk
│   ├── Android.bp                        # AETHER_SOONG_MODULES (8 entries)
│   ├── init.aether.rc
│   ├── fstab.aether
│   ├── ueventd.aether.rc
│   ├── manifest.xml                      # 21 HALs from AETHER_HAL_MANIFEST
│   ├── compatibility_matrix.xml
│   ├── sepolicy/                         # AETHER_SEPOLICY_FIXES + ADRENO_SELINUX_RULES
│   └── kernel/                           # AETHER_GKI_DEFCONFIG + device tree source
└── vendor/aether/
    └── hal/                              # skeleton HAL implementations
        ├── sensors/  radio/  camera/  power/  health/  gralloc/
```

## Constraints

- `ro.build.type=user` — mandatory; the userspace boot gate fails any other value.
- AVB test-keys until Phase 7 production release.
- microG signature spoofing must be enabled (`sys.microg.signature_spoofing=1`).
- Kernel: GKI 6.1 (Android 14 baseline), 4 KiB pages, little-endian.
