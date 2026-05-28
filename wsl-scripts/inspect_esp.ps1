$drive = 'E:\'
if (-not (Test-Path $drive)) { Write-Host "E not accessible"; exit 1 }

Write-Host "Tree under $drive"
Get-ChildItem -Path $drive -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object FullName | ForEach-Object {
    if ($_.PSIsContainer) {
        Write-Host ("DIR  " + $_.FullName)
    } else {
        $kb = [math]::Round($_.Length / 1KB, 1)
        Write-Host ("FILE " + $kb.ToString("F1") + " KB  " + $_.FullName)
    }
}

Write-Host ""
Write-Host "Required files"
$required = @('EFI\BOOT\BOOTX64.EFI','EFI\AETHER\hypervisor.efi','EFI\AETHER\boot.img','EFI\AETHER\vbmeta.img')
$missing = 0
foreach ($r in $required) {
    $full = Join-Path $drive $r
    if (Test-Path $full) {
        $sz = (Get-Item $full).Length
        Write-Host ("OK   " + $r + "  " + $sz + " bytes")
    } else {
        Write-Host ("MISS " + $r)
        $missing++
    }
}

Write-Host ""
if ($missing -eq 0) { Write-Host "ESP looks bootable" } else { Write-Host ($missing.ToString() + " required file(s) missing") }

Write-Host ""
Write-Host "Compare to staging"
$staging = 'D:\AETHER\esp-staging'
Get-ChildItem -Path $staging -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($staging.Length + 1)
    $espFile = Join-Path $drive $rel
    if (Test-Path $espFile) {
        $esp = Get-Item $espFile
        if ($esp.Length -eq $_.Length) {
            Write-Host ("OK             " + $rel)
        } else {
            Write-Host ("SIZE-MISMATCH  " + $rel + "  staging=" + $_.Length + "  esp=" + $esp.Length)
        }
    } else {
        Write-Host ("NOT-COPIED     " + $rel)
    }
}
