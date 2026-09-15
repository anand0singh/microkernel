# Bare-Metal UEFI Boot Disk Image Builder
# Packages EFI/BOOT/BOOTX64.EFI, KERNEL.ELF, and Ring 3 service binaries into a FAT32 ESP directory/disk

param (
    [string]$TargetDir = "target/esp"
)

$ErrorActionPreference = "Stop"

Write-Host "==> [1/3] Building entire microkernel workspace..." -ForegroundColor Cyan
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --workspace

Write-Host "==> [2/3] Creating UEFI ESP directory layout at $TargetDir..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$TargetDir/EFI/BOOT" | Out-Null
New-Item -ItemType Directory -Force -Path "$TargetDir/SERVICES" | Out-Null

# Copy UEFI Bootloader as default fallback bootloader
Copy-Item -Force "target/x86_64-unknown-uefi/debug/boot.efi" "$TargetDir/EFI/BOOT/BOOTX64.EFI"

# Copy Microkernel ELF payload
Copy-Item -Force "target/x86_64-unknown-none/debug/kernel" "$TargetDir/KERNEL.ELF"

# Copy Ring 3 User Space Service Binaries
$services = @("vfs", "net", "crypto", "audit", "driver-virtio", "driver-net", "keystore", "init", "vault", "shell")
foreach ($srv in $services) {
    $srcPath = "target/x86_64-unknown-none/debug/$srv"
    if (Test-Path $srcPath) {
        Copy-Item -Force $srcPath "$TargetDir/SERVICES/$srv.elf"
        Write-Host "  -> Packaged service: $srv.elf" -ForegroundColor Green
    }
}

Write-Host "==> [3/3] UEFI Bootable ESP structure ready!" -ForegroundColor Green
Get-ChildItem -Recurse $TargetDir | Select-Object FullName, Length
