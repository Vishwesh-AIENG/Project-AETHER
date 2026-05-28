# install_outage_hotkey.ps1 - creates a Windows shortcut on the Desktop with
# a global hotkey bound to emergency_shutdown.ps1.
#
# Default hotkey: Ctrl+Alt+S (S = Shutdown)
#
# Once installed, pressing Ctrl+Alt+S from ANY application will fire the
# emergency shutdown. The shortcut MUST live in Desktop, Start Menu, or
# Quick Launch for the hotkey to be global - that is a Windows requirement.

$ErrorActionPreference = 'Stop'

$ScriptPath = 'D:\AETHER\wsl-scripts\emergency_shutdown.ps1'
$ShortcutDir = [Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $ShortcutDir 'AETHER Emergency Shutdown.lnk'
$Hotkey = 'Ctrl+Alt+S'

Write-Host "creating shortcut at: $ShortcutPath"

$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($ShortcutPath)
$lnk.TargetPath = (Get-Command powershell.exe).Source
$lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
$lnk.WorkingDirectory = (Split-Path $ScriptPath)
$lnk.WindowStyle = 1
$lnk.Hotkey = $Hotkey
$lnk.Description = 'Cleanly shut down WSL2 to flush the vhdx before UPS dies (AETHER)'
$lnk.IconLocation = 'powershell.exe,0'
$lnk.Save()

Write-Host ""
Write-Host "=== INSTALLED ==="
Write-Host "  Shortcut: $ShortcutPath"
Write-Host "  Hotkey:   $Hotkey  (works from anywhere)"
Write-Host ""
Write-Host "When the UPS clicks in:"
Write-Host "  1. Hit Ctrl+Alt+S - that is it."
Write-Host "  2. Within ~5 seconds, WSL is cleanly shut down."
Write-Host "  3. UPS now only needs to keep the PC powered until it dies."
Write-Host "  4. When AC returns, boot the PC and run:"
Write-Host "       bash /mnt/d/AETHER/wsl-scripts/phase5_restart.sh"
Write-Host "     (phase5_restart syncs the device tree and spawns ninja again)"
Write-Host ""
Write-Host "Pre-test (recommended, but DOES shut WSL down):"
Write-Host "  Press Ctrl+Alt+S now to confirm the hotkey is wired correctly."
Write-Host "  Skip this if mid-build (you would need to restart it)."
