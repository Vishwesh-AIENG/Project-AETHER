# Identify USB-style removable drives and inspect their ESP layout.
$drives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -or $_.FileSystem -eq 'FAT32' }
if (-not $drives) {
    Write-Host "No removable/FAT32 drives detected."
    exit 1
}

Write-Host "=== Detected drives ==="
$drives | ForEach-Object {
    $sz = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
    $free = if ($_.SizeRemaining) { [math]::Round($_.SizeRemaining / 1GB, 2) } else { 0 }
    Write-Host ("  {0}: label='{1}' fs={2} size={3}GB free={4}GB" -f $_.DriveLetter, $_.FileSystemLabel, $_.FileSystem, $sz, $free)
}

Write-Host ""
foreach ($d in $drives) {
    if (-not $d.DriveLetter) { continue }
    $root = "$($d.DriveLetter):\"
    Write-Host "=== Contents of $root ==="
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime |
            Format-Table -AutoSize
    }
}
