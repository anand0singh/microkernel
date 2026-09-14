# Automated QEMU Virtualization Runner for Bare-Metal Microkernel
param (
    [string]$EspDir = "target/esp",
    [int]$MemoryMB = 512,
    [int]$Cpus = 2
)

# 1. Ensure build and ESP layout are up to date
& "$PSScriptRoot/build_disk.ps1" -TargetDir $EspDir

# 2. Locate QEMU executable
$qemuPath = (Get-Command "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue).Source
if (-not $qemuPath) {
    $commonPaths = @(
        "C:\Program Files\qemu\qemu-system-x86_64.exe",
        "C:\Program Files (x86)\qemu\qemu-system-x86_64.exe",
        "$env:LOCALAPPDATA\Programs\qemu\qemu-system-x86_64.exe"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) {
            $qemuPath = $p
            break
        }
    }
}

if (-not $qemuPath) {
    Write-Warning "QEMU executable (qemu-system-x86_64.exe) not found on PATH or standard directories."
    Write-Host "Install QEMU using: winget install SoftwareFreedomConservancy.QEMU" -ForegroundColor Yellow
    Write-Host "Manual command once installed:" -ForegroundColor Cyan
    Write-Host "  qemu-system-x86_64 -drive file=fat:rw:$EspDir,format=raw -serial stdio -m ${MemoryMB}M -smp $Cpus" -ForegroundColor Gray
    exit 0
}

Write-Host "==> Launching Microkernel in QEMU ($qemuPath)..." -ForegroundColor Green
& $qemuPath -drive "file=fat:rw:$EspDir,format=raw" -serial stdio -m "${MemoryMB}M" -smp $Cpus
