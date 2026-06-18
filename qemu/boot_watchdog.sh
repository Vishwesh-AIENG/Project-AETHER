#!/bin/bash
# boot_watchdog.sh — independent stuck-detector for a live AETHER boot. Kills QEMU
# (so run-x86-auto.py exits and the grind loop is re-invoked) on a clear stuck state,
# writing a one-line verdict to _boot_verdict.txt. Safe to run alongside any boot.
#
# Stuck states:
#   FROZEN        — dispatch iter marker unchanged for FROZE_SECS (hung, no progress)
#   INFINITE_LOOP — iter raced +LOOP_MIN_ITERS but ZERO new kernel/init lines for LOOP_SECS
#                   (e.g. the vmap-stack nested-fault storm: serial flows so SETTLE_S
#                    never fires, but no real forward progress)
#   WALL_TIMEOUT  — total wall exceeded HARD_WALL (covers the runner/QMP itself wedging)
# TERMINAL (UD2/TranslateFail/panic/halt) is left to the runner's own exit path.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="$HERE/com1.log"
VERDICT="$HERE/_boot_verdict.txt"
HARD_WALL=${HARD_WALL:-1800}
FROZE_SECS=${FROZE_SECS:-150}
LOOP_SECS=${LOOP_SECS:-360}
LOOP_MIN_ITERS=$((0x2000000))
kill_qemu() { taskkill //F //IM qemu-system-x86_64.exe >/dev/null 2>&1; }

start=$(date +%s)
last_iter=""; iter_t=$start
last_prog="-1"; prog_t=$start; prog_iter_base=""
while true; do
  sleep 15
  now=$(date +%s); el=$((now-start))
  if [ ! -f "$LOG" ]; then [ $el -ge $HARD_WALL ] && { echo "WALL_TIMEOUT @${el}s (no log)" >"$VERDICT"; kill_qemu; exit 0; }; continue; fi
  if grep -qE 'inject undef at pc=|TranslateFail pc=|Kernel panic|dispatch loop exited' "$LOG" 2>/dev/null; then
    echo "TERMINAL @${el}s (runner exits on its own)" >"$VERDICT"; exit 0
  fi
  if [ $el -ge $HARD_WALL ]; then echo "WALL_TIMEOUT @${el}s — killed qemu" >"$VERDICT"; kill_qemu; exit 0; fi
  cur_iter=$(grep -oE '\[dbt\] #0x[0-9a-f]+' "$LOG" | tail -1)
  cur_prog=$(grep -cvE '\[dbt\]|\[mmu\]|\[uflt\]' "$LOG" 2>/dev/null)
  if [ -n "$cur_iter" ] && [ "$cur_iter" = "$last_iter" ]; then
    if [ $((now-iter_t)) -ge $FROZE_SECS ]; then echo "FROZEN iter=$cur_iter @${el}s — killed qemu" >"$VERDICT"; kill_qemu; exit 0; fi
  else last_iter="$cur_iter"; iter_t=$now; fi
  if [ "$cur_prog" = "$last_prog" ]; then
    iv=$((16#$(echo "${cur_iter:-0x0}" | grep -oE '[0-9a-f]+$')))
    bv=$((16#$(echo "${prog_iter_base:-${cur_iter:-0x0}}" | grep -oE '[0-9a-f]+$')))
    if [ $((now-prog_t)) -ge $LOOP_SECS ] && [ $((iv-bv)) -ge $LOOP_MIN_ITERS ]; then
      echo "INFINITE_LOOP iter=$cur_iter (+$((iv-bv)) dispatches, no kernel/init output ${LOOP_SECS}s) @${el}s — killed qemu" >"$VERDICT"; kill_qemu; exit 0
    fi
  else last_prog="$cur_prog"; prog_t=$now; prog_iter_base="$cur_iter"; fi
done
