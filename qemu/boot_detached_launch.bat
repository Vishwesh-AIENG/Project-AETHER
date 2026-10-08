@echo off
setlocal enableextensions
REM ============================================================================
REM boot_detached_launch.bat -- register boot_detached.bat as a Windows scheduled
REM task and fire it immediately. The task runs under the Task Scheduler service
REM (svchost -> taskeng), so the qemu process it spawns is NOT a descendant of
REM Claude's Bash/PowerShell shell and survives a Claude context-teardown.
REM
REM Usage (from anywhere):   D:\AETHER\qemu\boot_detached_launch.bat
REM Task name:               AETHER_DBT_Boot
REM
REM To stop/clean up later:
REM   taskkill /F /IM qemu-system-x86_64.exe
REM   schtasks /delete /tn AETHER_DBT_Boot /f
REM ============================================================================

set "TN=AETHER_DBT_Boot"
set "BAT=%~dp0boot_detached.bat"

echo [launch] deleting any prior task %TN% ...
schtasks /delete /tn "%TN%" /f >nul 2>&1

echo [launch] creating task %TN% for %BAT%
REM /sc ONCE + a far-future start time; we fire it with /run immediately.
REM /RL HIGHEST => run elevated (qemu/WHPX + taskkill need it).
REM /IT keeps it interactive-visible when the current user is logged on, but it
REM still runs under the scheduler service tree (detached from Claude).
schtasks /create /tn "%TN%" /tr "\"%BAT%\"" /sc ONCE /st 23:59 /rl HIGHEST /f
if errorlevel 1 (
  echo [launch] ERROR: schtasks /create failed. Are you elevated?
  exit /b 1
)

echo [launch] firing task %TN% now ...
schtasks /run /tn "%TN%"
if errorlevel 1 (
  echo [launch] ERROR: schtasks /run failed.
  exit /b 1
)

echo [launch] started. Watch with:  bash /d/AETHER/qemu/strong_watch.sh
echo [launch] boot stdout/stderr: D:\AETHER\qemu\boot_detached.log
echo [launch] kernel serial:      D:\AETHER\qemu\com1.log
endlocal
exit /b 0
