# vendorsetup.sh — adds AETHER's lunch combo to the menu shown by `lunch`.
#
# Sourced by build/envsetup.sh when the user runs `source build/envsetup.sh`.
# Without this file the `lunch aether_arm64-user` invocation still works
# (AndroidProducts.mk registers it) but the combo will not appear in the
# numbered menu produced by a bare `lunch` call.
#
# This file is shell, not make; keep it portable to bash.

# AOSP 14+ — combos are registered via COMMON_LUNCH_CHOICES in
# AndroidProducts.mk. `add_lunch_combo` is obsolete and emits a warning, but
# is kept here for compatibility with earlier branches in case AETHER is ever
# back-ported. The Android 14 release name is `ap2a`.
# add_lunch_combo aether_arm64-ap2a-user

# Convenience aliases — invoke from any directory in the AOSP tree.
#
#   aether_build              full build (boot + system + vendor + vbmeta + userdata)
#   aether_quickboot          incremental boot.img rebuild only
#   aether_clean              clean everything except the kernel cache

function aether_build() {
    if [ -z "$ANDROID_BUILD_TOP" ]; then
        echo "ERROR: source build/envsetup.sh + lunch first."
        return 1
    fi
    ( cd "$ANDROID_BUILD_TOP" && \
      lunch aether_arm64-user && \
      m -j"$(nproc)" )
}

function aether_quickboot() {
    if [ -z "$ANDROID_BUILD_TOP" ]; then
        echo "ERROR: source build/envsetup.sh + lunch first."
        return 1
    fi
    ( cd "$ANDROID_BUILD_TOP" && m -j"$(nproc)" bootimage )
}

function aether_clean() {
    if [ -z "$ANDROID_BUILD_TOP" ]; then
        echo "ERROR: source build/envsetup.sh + lunch first."
        return 1
    fi
    ( cd "$ANDROID_BUILD_TOP" && m clean )
}
