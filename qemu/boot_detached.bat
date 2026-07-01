@echo off
setlocal enableextensions
REM ============================================================================
REM boot_detached.bat -- TEARDOWN-IMMUNE AETHER x86-DBT boot launcher (Windows).
REM
REM Runs run-x86-auto.py via WINDOWS PYTHON directly (NO Git-Bash / cygwin fork).
REM Designed to be launched by Windows Task Scheduler (schtasks) so the qemu
REM process tree is a child of the scheduler service (svchost/taskeng), NOT of
REM Claude's Bash/PowerShell tool shell. That is what makes it survive a full
REM Claude-process context-teardown that kills Claude's descendant tree.
REM
REM Why NOT grind_boot.sh under the scheduler: grind_boot.sh is bash, and a
REM bash-under-scheduler run hits the cygwin `fork` failure
REM (`child_copy: cygheap read copy failed`). Python has no such problem.
REM
REM Staging replicated here (mirrors grind_boot.sh + run-x86-auto.stage_binary):
REM   1. Kill any stray qemu holding com1.log open (native taskkill, no bash).
REM   2. run-x86-auto.py's own stage_binary() copies hypervisor.efi ->
REM      efi-x86\EFI\BOOT\BOOTX64.EFI and truncates com1.log, so no extra copy
REM      is needed here -- Python does it.
REM
REM Env knobs (override before calling, or edit the defaults below):
REM   WHPX=1          -- Windows Hypervisor Platform accel (required for a real boot)
REM   HARD_TIMEOUT    -- run-x86-auto absolute cap (s). Big => let the boot run.
REM   SETTLE_S        -- serial-quiet-before-exit (s). Big => don't exit on a pause.
REM   MEM             -- guest RAM (default 16G inside run-x86-auto.py)
REM
REM The strong stuck-detector is NOT run here (it is bash). Watch the boot from
REM the agent side with:  bash qemu/strong_watch.sh
REM ============================================================================

cd /d "%~dp0"

REM --- pick Windows Python (py launcher preferred, then python on PATH) ---
set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>&1 && set "PYEXE=python"
)
if not defined PYEXE set "PYEXE=C:\Program Files\Python313\python.exe"

REM --- default boot env (only set if caller did not already) ---
if not defined WHPX          set "WHPX=1"
if not defined HARD_TIMEOUT  set "HARD_TIMEOUT=300000"
if not defined SETTLE_S      set "SETTLE_S=4000"

set "STAMP=%DATE% %TIME%"
echo ==== boot_detached start %STAMP% ==== > boot_detached.log
echo PYEXE=%PYEXE%  WHPX=%WHPX%  HARD_TIMEOUT=%HARD_TIMEOUT%  SETTLE_S=%SETTLE_S% >> boot_detached.log

REM --- staging step 1: kill stray qemu (frees com1.log so Python can truncate) ---
taskkill /F /IM qemu-system-x86_64.exe >> boot_detached.log 2>&1
REM small settle so the OS releases the file handle
ping -n 2 127.0.0.1 >nul

REM --- launch the Python runner (this blocks until the boot finishes/settles) ---
echo ==== launching run-x86-auto.py ==== >> boot_detached.log
%PYEXE% run-x86-auto.py >> boot_detached.log 2>&1
set "RC=%ERRORLEVEL%"

echo ==== boot_detached done rc=%RC% ==== >> boot_detached.log
endlocal
exit /b %RC%
