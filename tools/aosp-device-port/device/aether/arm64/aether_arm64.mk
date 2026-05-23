# aether_arm64.mk — top-level product makefile for the AETHER device.
#
# Inherits the generic phone product and layers AETHER-specific packages,
# properties, and copy files on top. Matches AETHER_LUNCH_TARGET in
# hypervisor/src/aosp_build.rs (product name = aether_arm64, variant = user).

$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system.mk)

$(call inherit-product, $(LOCAL_DIR)/device.mk)
$(call inherit-product, $(LOCAL_DIR)/vendor.mk)

# microG (frameworks/base signature-spoofing patch must be applied upstream).
$(call inherit-product-if-exists, vendor/microg/microg.mk)

PRODUCT_NAME         := aether_arm64
PRODUCT_DEVICE       := aether_x1
PRODUCT_BRAND        := AETHER
PRODUCT_MODEL        := AETHER X1
PRODUCT_MANUFACTURER := AETHER

# Force release-keys signing in user builds.
PRODUCT_DEFAULT_DEV_CERTIFICATE := build/target/product/security/testkey

# ABI: arm64-v8a only (no 32-bit). Mirrors AETHER_PROPERTY_OVERRIDES.
TARGET_USES_64_BIT_BINDER := true
