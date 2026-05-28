#!/usr/bin/env bash
# Audit AETHER device tree references before they bite us at build time.
set -u
cd /root/aosp
DT=device/aether/aether_arm64

echo "=== PRODUCT_COPY_FILES src audit ==="
# Extract entries (src:dest) from PRODUCT_COPY_FILES blocks
awk '/PRODUCT_COPY_FILES[[:space:]]*\+?=/{inblock=1} inblock{print; if (!/\\$/) inblock=0}' "$DT/device.mk" \
  | grep -oE '[a-zA-Z0-9_/.-]+:[a-zA-Z0-9_/.-]+' \
  | while read line; do
      src=$(echo "$line" | cut -d: -f1)
      if [ -f "$src" ]; then echo "  OK    $src"
      else echo "  MISS  $src"
      fi
    done

echo
echo "=== BoardConfig.mk file/dir refs ==="
grep -E 'MANIFEST_FILE|SEPOLICY_DIRS|FSTAB|AVB_.*KEY|RAMDISK_FSTAB|RECOVERY_FSTAB|KERNEL_CMDLINE_FILE|BOOTIMAGE_PARTITION' "$DT/BoardConfig.mk" \
  | grep -v '^[[:space:]]*#' \
  | while IFS= read -r line; do
      for p in $(echo "$line" | grep -oE '(device|out|external|kernel|system|hardware)/[a-zA-Z0-9_/.-]+'); do
        if [ -e "$p" ]; then echo "  OK    $p"
        else echo "  MISS  $p"
        fi
      done
    done

echo
echo "=== Top-level device tree files ==="
for f in manifest.xml fstab.aether AndroidProducts.mk aether_arm64.mk BoardConfig.mk device.mk Android.bp vendorsetup.sh; do
  if [ -f "$DT/$f" ]; then echo "  OK    $f"
  else echo "  MISS  $f"
  fi
done

echo
echo "=== sepolicy contents ==="
ls "$DT/sepolicy/" 2>&1 | sed 's/^/  /'

echo
echo "=== HAL service.cpp files ==="
find "$DT/hal" -name "service.cpp" 2>/dev/null | sed 's/^/  /'

echo
echo "=== init RC files ==="
ls "$DT/init/" 2>&1 | sed 's/^/  /'

echo
echo "=== vintf fragments referenced in Android.bp ==="
grep -E 'vintf_fragments|src:|filename:' "$DT/Android.bp" | sed 's/^/  /'

echo
echo "=== vintf/ directory contents ==="
ls "$DT/vintf/" 2>&1 | sed 's/^/  /'

echo
echo "=== Android.bp module srcs existence check ==="
# Extract each src: "path" entry
grep -oE 'src:[[:space:]]*"[^"]+"' "$DT/Android.bp" \
  | sed 's/src:[[:space:]]*"\(.*\)"/\1/' \
  | while read src; do
      full="$DT/$src"
      if [ -e "$full" ]; then echo "  OK    $src"
      else echo "  MISS  $src   (looking at $full)"
      fi
    done

echo
echo "=== Android.bp init_rc existence check ==="
grep -oE 'init_rc:[[:space:]]*\["[^"]+"' "$DT/Android.bp" \
  | sed 's/init_rc:[[:space:]]*\["\(.*\)"/\1/' \
  | while read rc; do
      full="$DT/$rc"
      if [ -e "$full" ]; then echo "  OK    $rc"
      else echo "  MISS  $rc"
      fi
    done

echo
echo "=== Android.bp vintf_fragments existence check ==="
grep -oE 'vintf_fragments:[[:space:]]*\["[^"]+"' "$DT/Android.bp" \
  | sed 's/vintf_fragments:[[:space:]]*\["\(.*\)"/\1/' \
  | while read vf; do
      full="$DT/$vf"
      if [ -e "$full" ]; then echo "  OK    $vf"
      else echo "  MISS  $vf"
      fi
    done

echo
echo "=== PRODUCT_PACKAGES resolvability (sample first 20) ==="
awk '/PRODUCT_PACKAGES[[:space:]]*\+?=/{inblock=1} inblock{print; if (!/\\$/) inblock=0}' "$DT/device.mk" \
  | grep -vE '^[[:space:]]*(#|PRODUCT_PACKAGES)' \
  | grep -oE '[A-Za-z][A-Za-z0-9._@-]+' \
  | grep -v '^_' \
  | sort -u \
  | head -30 \
  | while read pkg; do
      # Check if package is defined anywhere as a Soong module name
      hit=$(grep -rlE "name:[[:space:]]*\"$pkg\"" --include="Android.bp" /root/aosp 2>/dev/null | head -1)
      if [ -n "$hit" ]; then echo "  OK    $pkg  -> $hit"
      else
        # Check Make-style modules too
        mkhit=$(grep -rlE "LOCAL_MODULE[[:space:]]*:=[[:space:]]*$pkg[[:space:]]*$" --include="Android.mk" /root/aosp 2>/dev/null | head -1)
        if [ -n "$mkhit" ]; then echo "  OK    $pkg  -> $mkhit (mk)"
        else echo "  UNKNOWN $pkg"
        fi
      fi
    done

echo
echo "=== Done ==="
