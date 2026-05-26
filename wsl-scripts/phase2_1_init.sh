#!/bin/bash
set -e
export PATH=~/.bin:$PATH
echo "=== 2.1 repo init ==="
mkdir -p ~/aosp
cd ~/aosp
repo init -u https://android.googlesource.com/platform/manifest \
          -b android-14.0.0_r74 \
          --partial-clone --no-clone-bundle --no-tags 2>&1 | tail -20
echo
echo "=== status after init ==="
ls -la .repo | head
