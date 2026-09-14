# Automated Security Suite & Syzkaller-style Fuzzer Runner
$ErrorActionPreference = "Stop"

Write-Host "==> Running Microkernel Security Verification & Fuzzing Suite..." -ForegroundColor Cyan
& "$env:USERPROFILE\.cargo\bin\cargo.exe" run --manifest-path "$PSScriptRoot/security_suite/Cargo.toml" --target x86_64-pc-windows-gnu
