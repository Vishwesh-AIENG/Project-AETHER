Get-Volume | Sort-Object DriveLetter | Format-Table -AutoSize DriveLetter, FileSystemLabel, FileSystem, DriveType, @{Name='SizeGB';Expression={if ($_.Size) {[math]::Round($_.Size/1GB,2)} else {0}}}
Write-Host ""
Write-Host "=== Physical disks ==="
Get-Disk | Format-Table -AutoSize Number, FriendlyName, BusType, @{Name='SizeGB';Expression={[math]::Round($_.Size/1GB,2)}}, PartitionStyle
