# aether_arm64.mk — the product makefile for the AETHER ARM64 Android partition.
#
# This is the file pointed to by AndroidProducts.mk and resolved when the user
# runs `lunch aether_arm64-user`. It composes:
#
#   1. AOSP base inheritances — generic handheld + treble + ARM64 + Phone APIs.
#   2. AETHER device.mk — PRODUCT_PACKAGES, PRODUCT_COPY_FILES, properties.
#   3. Product identity — PRODUCT_NAME, PRODUCT_DEVICE, PRODUCT_BRAND, etc.
#
# Mechanically derived from hypervisor/src/aosp_build.rs.
#
# Build gate (ch42):
#   lunch aether_arm64-user && m
# Produces: out/target/product/aether_arm64/{boot,system,vendor,vbmeta,userdata}.img

# ── AOSP base inheritances ────────────────────────────────────────────────────
# Generic handheld base — pulls in Settings, SystemUI, Launcher3, etc.
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_product.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)

# Treble VNDK + full vendor partition split (mandatory for ch21 Treble manifest).
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base.mk)

# AVB (Android Verified Boot 2). Pulls in the vbmeta target and signing rules.
$(call inherit-product, build/make/target/product/aosp_arm64.mk)

# ── AETHER device-specific configuration ──────────────────────────────────────
$(call inherit-product, device/aether/aether_arm64/device.mk)

# ── Product identity ──────────────────────────────────────────────────────────
# Must match the lunch target name in AndroidProducts.mk. The build system uses
# PRODUCT_NAME as the directory under out/target/product/<PRODUCT_NAME>/.
PRODUCT_NAME            := aether_arm64
PRODUCT_DEVICE          := aether_arm64
PRODUCT_BRAND           := AETHER
PRODUCT_MODEL           := AETHER X1
PRODUCT_MANUFACTURER    := AETHER
PRODUCT_RELEASE_NAME    := AETHER_X1

# Required by the AOSP build for non-Google products to compile cleanly.
PRODUCT_RESTRICT_VENDOR_FILES := false

# ── Locales ───────────────────────────────────────────────────────────────────
# Minimal default set; locales are not in scope for the ch42 gate.
PRODUCT_LOCALES := en_US

# ── Default DPI ───────────────────────────────────────────────────────────────
# 440dpi matches a typical 6-inch phone-class display. Adjusted at runtime.
PRODUCT_AAPT_CONFIG     := normal large xlarge hdpi xhdpi xxhdpi xxxhdpi
PRODUCT_AAPT_PREF_CONFIG := xxxhdpi
