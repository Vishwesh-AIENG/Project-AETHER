# AndroidProducts.mk — registers AETHER's lunch target with the AOSP build.
#
# When `lunch` runs, it sources every device/*/AndroidProducts.mk and aggregates
# their COMMON_LUNCH_CHOICES into the lunch menu. This file exports exactly one
# target: aether_arm64-user. See hypervisor/src/aosp_build.rs::AETHER_LUNCH_TARGET.
#
# Reference: source.android.com/setup/create/new-device#set-up-the-product-definition

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/aether_arm64.mk

# The lunch menu entry. AETHER ships only the `user` variant — `userdebug` and
# `eng` are rejected at the build-system level by AospBuildConfig::validate().
# Hardware Authenticity (CLAUDE.md §Hardware Authenticity): ro.build.type=user.
#
# AOSP 14 changed combo format from <product>-<variant> to
# <product>-<release>-<variant>. The release for android-14.0.0_r74 is `ap2a`.
COMMON_LUNCH_CHOICES := \
    aether_arm64-ap2a-user
