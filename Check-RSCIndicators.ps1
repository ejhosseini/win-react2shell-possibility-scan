Write-Host "=== Node.js Detection Test ===" -ForegroundColor Cyan

# 1. PATH lookup
$nodePath = Get-Command node -ErrorAction SilentlyContinue
if ($nodePath) {
    Write-Host "[PATH] Node found:" $nodePath.Source -ForegroundColor Green
} else {
    Write-Host "[PATH] Node not found in PATH." -ForegroundColor Yellow
}

# 2. Registry lookup (Apps & Features)
$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$foundReg = foreach ($p in $regPaths) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Node.js*' }
}

if ($foundReg) {
    Write-Host "`n[REGISTRY] Node installation(s) detected:" -ForegroundColor Green
    $foundReg | Select-Object DisplayName, DisplayVersion, InstallLocation | Format-Table -AutoSize
} else {
    Write-Host "`n[REGISTRY] No Node installation found." -ForegroundColor Yellow
}
