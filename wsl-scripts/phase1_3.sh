#!/bin/bash
set -e
echo "=== 1.3 repo tool ==="
mkdir -p ~/.bin
curl -sL https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
chmod +x ~/.bin/repo
if ! grep -q "/.bin:" ~/.bashrc 2>/dev/null; then
    echo 'export PATH=~/.bin:$PATH' >> ~/.bashrc
fi
export PATH=~/.bin:$PATH
which repo
echo
echo "=== 1.4 git identity ==="
git config --global user.name  "AETHER builder"
git config --global user.email "aether@localhost"
git config --global color.ui   true
git config --global --get user.name
git config --global --get user.email
