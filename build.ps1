#Requires -Version 5.1
<#
.SYNOPSIS
    Build a distributable Windows executable for the Software Security Auditor.
.NOTES
    Run from the project root:  .\build.ps1
    Prerequisites: Python venv at .venv\ with dependencies installed.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# Ensure assets\ folder exists (required by spec datas entry)
if (-not (Test-Path "$root\assets")) {
    New-Item -ItemType Directory "$root\assets" | Out-Null
    Write-Host "Created assets\ folder." -ForegroundColor Yellow
}

# Install PyInstaller into venv if not already present
$pyinstaller = "$root\.venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $pyinstaller)) {
    Write-Host "Installing PyInstaller..." -ForegroundColor Yellow
    uv pip install --python "$root\.venv\Scripts\python.exe" "pyinstaller>=6.14"
}
$ver = & $pyinstaller --version 2>&1
Write-Host "PyInstaller $ver" -ForegroundColor Cyan

# Vendor all dependencies as wheels for offline server install
Write-Host "Downloading vendor wheels..." -ForegroundColor Cyan
if (-not (Test-Path "$root\vendor")) { New-Item -ItemType Directory "$root\vendor" | Out-Null }
uv pip download --python "$root\.venv\Scripts\python.exe" -r "$root\requirements.txt" -d "$root\vendor"
Write-Host "Vendor wheels saved to vendor\" -ForegroundColor Green

# Run PyInstaller
Write-Host ""
Write-Host "Building executable..." -ForegroundColor Cyan
& $pyinstaller --clean --noconfirm "$root\SoftwareSecurityAuditor.spec"

# Report result
$exe = "$root\dist\SoftwareSecurityAuditor\SoftwareSecurityAuditor.exe"
if (Test-Path $exe) {
    Write-Host ""
    Write-Host "Build succeeded." -ForegroundColor Green
    Write-Host "Output : $root\dist\SoftwareSecurityAuditor\" -ForegroundColor Green
    Write-Host ""
    Write-Host "Deployment:" -ForegroundColor White
    Write-Host "  Zip dist\SoftwareSecurityAuditor\ and copy to the server." -ForegroundColor White
    Write-Host ""
    Write-Host "Offline server install (no internet required):" -ForegroundColor White
    Write-Host "  uv pip install --no-index --find-links=vendor\ -r requirements.txt" -ForegroundColor White
} else {
    Write-Error "Build failed — executable not found at: $exe"
}
