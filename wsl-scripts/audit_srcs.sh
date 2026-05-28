#!/usr/bin/env bash
set -u
cd /root/aosp
DT=device/aether/aether_arm64

echo "=== Android.bp srcs: array entries ==="
awk '/srcs:[[:space:]]*\[/,/\]/' "$DT/Android.bp" | grep -oE '"[^"]+\.(cpp|h|c|cc|aidl|hal)"' | tr -d '"' \
  | while read s; do
      if [ -f "$DT/$s" ]; then echo "  OK    $s"
      elif [ -f "$s" ]; then echo "  OK_abs $s"
      else echo "  MISS  $s"
      fi
    done

echo
echo "=== BoardConfig.mk SEPOLICY / AVB key ==="
grep -nE 'SEPOLICY|AVB_.*KEY|FSTAB' "$DT/BoardConfig.mk"

echo
echo "=== sepolicy/device.te (first 20 lines) ==="
head -20 "$DT/sepolicy/device.te"

echo
echo "=== sepolicy/file_contexts (first 20 lines) ==="
head -20 "$DT/sepolicy/file_contexts"

echo
echo "=== fstab.aether ==="
cat "$DT/fstab.aether"

echo
echo "=== aether_arm64.mk inherits ==="
grep -E 'inherit-product|PRODUCT_NAME|PRODUCT_DEVICE|PRODUCT_BRAND|PRODUCT_MODEL' "$DT/aether_arm64.mk"

echo
echo "=== AndroidProducts.mk ==="
cat "$DT/AndroidProducts.mk"
