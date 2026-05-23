# AndroidProducts.mk — registers AETHER's lunch combos.
#
# Mirrors hypervisor/src/aosp_build.rs::AETHER_LUNCH_TARGET
# (product = aether_arm64, variant = User).

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/aether_arm64.mk

COMMON_LUNCH_CHOICES := \
    aether_arm64-user
