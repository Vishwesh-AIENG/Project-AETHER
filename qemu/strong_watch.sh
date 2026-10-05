#!/bin/bash
# Strong boot watcher — exits (wakes the agent) FAST on success, hard-stop, OR
# any "wasted-cycle" state: crash-loop, frozen guest-clock-while-spinning,
# no-forward-progress, or repetitive output. Never sits idle for hours.
#
# Usage:  bash strong_watch.sh [extra_success_regex]
# Prints a single RESULT=<KIND> line + context, then exits.
LOG=/d/AETHER/qemu/com1.log
POLL=25                 # seconds between polls
STALL_POLLS=10          # frozen clock + TIGHT-LOOP (few distinct PCs) this many polls (~4min) => STUCK
DISTINCT_MAX=6          # <=6 distinct block PCs in the recent [dbt] ring => a real loop (not a slow op)
NOPROG_POLLS="${NOPROG_POLLS:-32}"  # no clock advance AND no new service => NOPROGRESS. Raise via env for
                                    # long zygote-preload/dex2oat stretches that pause logging for many minutes.
SIG11_MAX="${SIG11_MAX:-2}"   # >=N SIGSEGV (signal 11) => CRASHLOOP. Raise via env when a
EXIT1_MAX="${EXIT1_MAX:-12}"  # known service crash-loops NON-FATALLY but the boot still progresses
                              # (e.g. keystore2 once keymint is up) — then NOPROGRESS guards the real stall.
EXTRA="${1:-}"          # optional caller-supplied early-success regex
# NOTE: a slow-but-healthy op (apexd loop-mount, dex2oat, zygote preload) pauses
# printk for minutes while executing VARIED code (many distinct PCs). STUCK now
# requires BOTH a frozen clock AND a tiny repeating PC set, so it no longer
# false-fires on those. On a STUCK/NOPROGRESS fire, re-check the clock advanced
# before treating it as a real hang.

prev_t=""; prev_sz=0; stall=0
prev_prog=""; noprog=0

emit() { echo "RESULT=$1"; shift; for p in "$@"; do grep -aE "$p" "$LOG" 2>/dev/null | tail -3 | cut -c1-110; done; }

for i in $(seq 1 720); do
  # ---------- terminal GOOD ----------
  # Precise RUNTIME markers only — init's "... started service 'X' has pid N"
  # and SF's "Boot is finished". These never appear in "Parsing file .rc" lines.
  if grep -aqE "started service '(zygote|zygote_secondary|surfaceflinger|system_server|bootanim|launcher)'|Boot is finished" "$LOG" 2>/dev/null; then
    emit SUCCESS "started service '(zygote|surfaceflinger|system_server|bootanim)'|Boot is finished"; exit 0; fi
  if [ -n "$EXTRA" ] && grep -aqE "$EXTRA" "$LOG" 2>/dev/null; then emit SUCCESS_EXTRA "$EXTRA"; exit 0; fi
  # ---------- terminal BAD / stop ----------
  if grep -aqE "Kernel panic|reboot,|Attempted to kill init|dispatch loop exited|Halting" "$LOG" 2>/dev/null; then
    emit HARDSTOP "Kernel panic|reboot, reason|Attempted to kill|dispatch loop exited"; exit 0; fi
  if grep -aqE "\[dbt-arm\]|TranslateFail" "$LOG" 2>/dev/null; then emit DBTWALL "\[dbt-arm\] pc=|TranslateFail"; exit 0; fi
  # qemu vanished
  UP=$(powershell.exe -NoProfile -Command "(Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue|Measure-Object).Count" 2>/dev/null | tr -d '\r ')
  if [ "$UP" = "0" ]; then emit QEMU_DOWN "panic|reboot|Halting|signal 11|exited with status"; exit 0; fi
  # ---------- WASTED-CYCLE detectors (the critical part) ----------
  SIG11=$(grep -acE "received signal 11" "$LOG" 2>/dev/null)
  if [ "${SIG11:-0}" -ge "$SIG11_MAX" ]; then emit CRASHLOOP_SIGSEGV "received signal 11"; exit 0; fi
  EXIT1=$(grep -acE "exited with status" "$LOG" 2>/dev/null)
  if [ "${EXIT1:-0}" -ge "$EXIT1_MAX" ]; then emit CRASHLOOP_EXIT "exited with status|received signal"; exit 0; fi
  cur_t=$(grep -aoE '\[ *[0-9]+\.[0-9]+\]' "$LOG" 2>/dev/null | tail -1)
  cur_sz=$(wc -c < "$LOG" 2>/dev/null | tr -d ' ')
  # distinct block PCs in the recent [dbt] ring: FEW => tight loop (true hang);
  # MANY => executing varied code (slow-but-progressing op like apexd/dex2oat).
  distinct=$(grep -aoE '\[dbt\] #0x[0-9a-f]+ pc=0x[0-9a-f]+' "$LOG" 2>/dev/null | tail -40 | grep -oE 'pc=0x[0-9a-f]+' | sort -u | wc -l | tr -d ' ')
  if [ "$cur_t" != "$prev_t" ]; then stall=0; prev_t="$cur_t";          # clock advanced => progressing
  elif [ "${cur_sz:-0}" -gt "${prev_sz:-0}" ] && [ "${distinct:-99}" -le "$DISTINCT_MAX" ]; then stall=$((stall+1));  # frozen + tight loop
  else stall=0; fi                                                       # frozen but varied PCs (slow op) => not a hang
  prev_sz="$cur_sz"
  if [ "$stall" -ge "$STALL_POLLS" ]; then emit STUCK_SPINNING "$cur_t"; echo "  (clock frozen at $cur_t ~$((STALL_POLLS*POLL))s, only $distinct distinct block PCs — TRUE loop)"; tail -4 "$LOG"|cut -c1-100; exit 0; fi
  # no forward progress: guest-clock, service count, AND the [dbt] dispatch
  # counter all frozen. The dispatch counter advancing means the DBT is still
  # executing guest code (e.g. a kernel-busy phase that emits no printk) — that
  # is NOT a stall, so include it so NOPROGRESS only fires on a TOTAL freeze.
  prog="${cur_t}|$(grep -acE "started service '|Start proc " "$LOG" 2>/dev/null)|$(grep -aoE '\[dbt\] #0x[0-9a-f]+' "$LOG" 2>/dev/null | tail -1)"
  if [ "$prog" = "$prev_prog" ]; then noprog=$((noprog+1)); else noprog=0; prev_prog="$prog"; fi
  if [ "$noprog" -ge "$NOPROG_POLLS" ]; then emit NOPROGRESS "$cur_t"; echo "  (no guest-clock/service advance ~$((NOPROG_POLLS*POLL))s at $cur_t)"; tail -4 "$LOG"|cut -c1-100; exit 0; fi
  sleep "$POLL"
done
echo "RESULT=TIMEOUT t=$(grep -aoE '\[ *[0-9.]+\]' "$LOG"|tail -1)"
