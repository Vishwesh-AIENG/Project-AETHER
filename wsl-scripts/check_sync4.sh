#!/bin/bash
export PATH=~/.bin:$PATH
cd ~/aosp

echo "=== full project inventory (repo's view) ==="
total=$(repo list 2>/dev/null | wc -l)
echo "  manifest total: $total"

# Each project has a .git symlink/dir in its working tree.
# Count those that exist (= projects with at least workdir initialized).
workdirs=$(repo list -p 2>/dev/null | while read -r p; do
    [ -e "$p/.git" ] && echo 1
done | wc -l)
echo "  workdirs with .git: $workdirs"

# Count those that actually have a HEAD (= checkout completed).
heads=$(repo list -p 2>/dev/null | while read -r p; do
    [ -f "$p/.git" ] && head_path="$(cat "$p/.git" 2>/dev/null | sed 's|gitdir: ||')/HEAD"
    [ -d "$p/.git" ] && head_path="$p/.git/HEAD"
    [ -n "$head_path" ] && [ -f "$head_path" ] && echo 1
done | wc -l)
echo "  with valid HEAD:    $heads"

echo
echo "=== failed-projects breakdown by top-level dir ==="
grep -E "Cannot initialize work tree for|Cannot checkout" ~/aosp/sync.log \
    | awk '{print $NF}' | sort -u \
    | awk -F/ '{print $1"/"$2}' | sort | uniq -c | sort -rn | head
