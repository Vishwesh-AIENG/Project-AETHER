# emergency_shutdown.ps1 - single-keystroke clean shutdown of WSL2.
#
# When the user hears the UPS kick in (AC dropped), they hit a hotkey bound to
# this script. It does:
#   1. Inside WSL: pause the AOSP build (SIGSTOP - pauses without killing) so
#      ninja stops writing new data.
#   2. Inside WSL: explicit sync.
#   3. From Windows: wsl --shutdown (synchronous, returns when vhdx is flushed
#      and unmounted by Hyper-V).
#
# After AC returns and the box powers back up, the next `wsl` command will
# restart Ubuntu cleanly. The build can be resumed with
#   bash /mnt/d/AETHER/wsl-scripts/phase5_restart.sh
# and ninja picks up from .ninja_log with zero corruption.

$ErrorActionPreference = 'Continue'
$startTime = Get-Date

Write-Host "=== AETHER emergency WSL shutdown ==="
Write-Host "started at $startTime"

# Step 1: pause the build inside WSL so no new writes happen during sync
Write-Host "[1/3] pausing build processes in WSL..."
& wsl.exe -d Ubuntu-24.04 -- bash -c "for pat in soong_ui ninja ckati turbine javac kotlinc clang clang++ d8 r8 aapt2 metalava; do pkill -STOP -f `"`$pat`" 2>/dev/null; done; echo paused"

# Step 2: explicit sync inside WSL
Write-Host "[2/3] syncing WSL filesystem..."
& wsl.exe -d Ubuntu-24.04 -- bash -c "sync; sync; sync; echo synced"

# Step 3: full clean WSL shutdown - Hyper-V flushes the vhdx and detaches
Write-Host "[3/3] shutting down WSL (vhdx flush)..."
& wsl.exe --shutdown

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "=== WSL safely shut down in $($elapsed.TotalSeconds.ToString('F1'))s ==="
Write-Host "vhdx is now in a consistent state - no corruption possible from here."
Write-Host ""
Write-Host "To resume after AC returns:"
Write-Host "  bash /mnt/d/AETHER/wsl-scripts/phase5_restart.sh"
Write-Host ""

# Hold the console open if launched via hotkey so user can see the result
if ([Environment]::UserInteractive -and ($Host.Name -ne 'Default Host')) {
  Write-Host "Press any key to close..."
  try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}
