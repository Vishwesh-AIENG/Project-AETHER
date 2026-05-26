#!/bin/bash
export PATH=~/.bin:$PATH
cd ~/aosp
echo "=== total manifest projects ==="
repo list 2>/dev/null | wc -l
echo
echo "=== projects actually populated (have .git/HEAD) ==="
find . -name HEAD -path '*/\.git/*' 2>/dev/null | wc -l
echo
echo "=== unique failed project names from log ==="
grep -E "Cannot initialize work tree for|Cannot checkout" ~/aosp/sync.log | awk '{print $NF}' | sort -u | wc -l
echo
echo "=== first 15 failed projects ==="
grep -E "Cannot initialize work tree for|Cannot checkout" ~/aosp/sync.log | awk '{print $NF}' | sort -u | head -15
