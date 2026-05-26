#!/bin/bash
set -e
echo "=== 3.3 microG clones ==="
mkdir -p ~/aosp/vendor/microg
cd ~/aosp/vendor/microg
for repo_pair in \
    "GmsCore=https://github.com/microg/GmsCore" \
    "FakeStore=https://github.com/microg/FakeStore" \
    "GsfProxy=https://github.com/microg/android_packages_apps_GsfProxy" \
    "UnifiedNlp=https://github.com/microg/UnifiedNlp"; do
    name="${repo_pair%=*}"
    url="${repo_pair#*=}"
    if [ -d "$name/.git" ]; then
        echo "  $name: already cloned"
    else
        echo "  cloning $name from $url"
        git clone --depth=1 "$url" "$name" 2>&1 | tail -3 || echo "    (clone failed — repo may be private or moved)"
    fi
done
echo
echo "=== what we have ==="
ls -la ~/aosp/vendor/microg/
