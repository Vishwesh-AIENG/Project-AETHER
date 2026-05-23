# vendor.mk — vendor partition properties (vendor/build.prop).
#
# Mirrors hypervisor/src/aosp_build.rs::AETHER_PROPERTY_OVERRIDES entries
# that semantically belong on the vendor side (hardware identity, ABI).

PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.build.fingerprint=AETHER/aether_x1/aether_x1:14/UP1A/eng.aether:user/release-keys \
    ro.vendor.product.cpu.abilist=arm64-v8a \
    ro.vendor.product.cpu.abilist64=arm64-v8a \
    ro.vendor.product.cpu.abilist32= \
    ro.hardware.egl=adreno \
    ro.hardware.vulkan=adreno \
    ro.hardware.gralloc=aether
