#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$serviceName = "SoftwareSecurityAuditor"

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "nssm not found on PATH."
}

Write-Host "Stopping and removing service '$serviceName'..." -ForegroundColor Yellow
nssm stop   $serviceName
nssm remove $serviceName confirm

Write-Host "Service removed." -ForegroundColor Green
