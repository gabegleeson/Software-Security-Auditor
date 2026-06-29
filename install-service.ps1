#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Software Security Auditor as a Windows Service using NSSM.

.DESCRIPTION
    Requires NSSM (Non-Sucking Service Manager) to be on PATH.
    Download from https://nssm.cc/download

    Run once from an elevated PowerShell prompt in the project directory:
        .\install-service.ps1

    After installation:
    1. Ensure IIS ARR proxy is enabled (IIS Manager > server > ARR Cache > Server Proxy Settings).
    2. Place web.config in your IIS site root (or point the site at this directory).
    3. Grant the service account write access to the data\ folder:
           icacls data /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F"
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$serviceName = "SoftwareSecurityAuditor"
$root        = $PSScriptRoot
$python      = Join-Path $root ".venv\Scripts\python.exe"
$script      = Join-Path $root "app.py"
$logFile     = Join-Path $root "data\service.log"

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "nssm not found on PATH. Download from https://nssm.cc/download and add to PATH."
}

if (-not (Test-Path $python)) {
    Write-Error "Virtual environment not found at $python. Run: uv sync"
}

Write-Host "Installing service '$serviceName'..." -ForegroundColor Cyan

nssm install $serviceName $python "`"$script`""
nssm set $serviceName AppDirectory $root
nssm set $serviceName DisplayName  "Software Security Auditor"
nssm set $serviceName Description  "Flask web application for software security auditing."
nssm set $serviceName Start        SERVICE_AUTO_START
nssm set $serviceName AppStdout    $logFile
nssm set $serviceName AppStderr    $logFile
nssm set $serviceName AppRotateFiles 1
nssm set $serviceName AppRotateSeconds 86400

Write-Host "Starting service..." -ForegroundColor Cyan
nssm start $serviceName

Write-Host ""
Write-Host "Service '$serviceName' installed and started." -ForegroundColor Green
Write-Host "Logs: $logFile" -ForegroundColor White
Write-Host "Stop:    nssm stop $serviceName" -ForegroundColor White
Write-Host "Remove:  .\uninstall-service.ps1" -ForegroundColor White
