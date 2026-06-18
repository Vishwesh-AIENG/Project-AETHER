#!/bin/bash
# Resilient AOSP build/resume for aether_arm64-ap2a-user.
# - trap '' HUP : ignore SIGHUP so a detached console hangup can't kill ninja
# - own session via setsid at launch; logs appended to build.log
# - recreates the vendor_ramdisk dirs that installclean removes (Run-22 fix)
trap '' HUP
cd /root/aosp || exit 1

mkdir -p out/target/product/aether_arm64/vendor_ramdisk \
         out/target/product/aether_arm64/vendor_debug_ramdisk \
         out/target/product/aether_arm64/debug_ramdisk

# periodic sync guard (child; ends when this script exits)
( while true; do sync; sleep 30; done ) &
SYNC_PID=$!

source build/envsetup.sh >/dev/null 2>&1
lunch aether_arm64-ap2a-user >/dev/null

echo "=== BUILD_RESUME $(date -u) ===" >> /root/aosp/build.log
m -j8 >> /root/aosp/build.log 2>&1
RC=$?
echo "BUILD_RC=$RC" >> /root/aosp/build.log

kill "$SYNC_PID" 2>/dev/null
exit $RC
