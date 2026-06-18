#!/bin/bash
# grind_boot.sh — run ONE AETHER x86 boot under run-x86-auto.py with an independent
# stuck-detector watchdog, then print a self-contained report (verdict + next gap).
#
# The watchdog exists because run-x86-auto.py's SETTLE_S only fires when the serial
# log goes QUIET. An INFINITE LOOP (e.g. the vmap-stack nested-fault storm) keeps the
# serial flowing with [dbt] iter markers forever, so SETTLE never triggers and the run
# would burn the full HARD_TIMEOUT (or, if the runner/QMP itself wedges, hang past it).
# The watchdog kills QEMU early on a clear stuck state, which makes run-x86-auto.py
# exit, which re-invokes the autonomous grind loop with a clear verdict.
#
# Env knobs (all seconds): HARD_WALL (default 1800), FROZE_SECS (150), LOOP_SECS (360),
# plus HARD_TIMEOUT / SETTLE_S passed through to run-x86-auto.py.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="$HERE/com1.log"
VERDICT="$HERE/_boot_verdict.txt"
RUNLOG="$HERE/_runlog_grind.txt"
HARD_WALL=${HARD_WALL:-1800}
FROZE_SECS=${FROZE_SECS:-150}
LOOP_SECS=${LOOP_SECS:-360}
LOOP_MIN_ITERS=$((0x2000000))   # 33M dispatches advanced w/ no new output => loop

kill_qemu() { taskkill //F //IM qemu-system-x86_64.exe >/dev/null 2>&1; }

rm -f "$VERDICT"
# Clean any stray QEMU that could hold com1.log open (breaks stage_binary's remove).
kill_qemu; sleep 1

# ---- watchdog (background, shared logic) ----
HARD_WALL=$HARD_WALL FROZE_SECS=$FROZE_SECS LOOP_SECS=$LOOP_SECS bash "$HERE/boot_watchdog.sh" &
WD=$!

# ---- the boot ----
( cd "$HERE" && python run-x86-auto.py ) >"$RUNLOG" 2>&1
RC=$?
kill $WD >/dev/null 2>&1

echo "=== GRIND BOOT DONE rc=$RC ==="
echo "--- watchdog verdict ---"; cat "$VERDICT" 2>/dev/null || echo "(clean exit — no watchdog intervention)"
echo "--- next gap (UD2 / TranslateFail) ---"; grep -E 'inject undef at pc=|TranslateFail pc=' "$LOG" 2>/dev/null | tail -2
echo "--- init / panic / mount ---"; grep -nE '\] init:|Run /init|Kernel panic|exitcode|VFS: Mounted|second stage|EXT4-fs' "$LOG" 2>/dev/null | grep -vE '\[dbt\]|\[mmu\]' | tail -8
echo "--- last iter ---"; grep -oE '\[dbt\] #0x[0-9a-f]+' "$LOG" 2>/dev/null | tail -1
