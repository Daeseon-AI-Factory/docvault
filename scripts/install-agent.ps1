# DocVault clipboard agent installer — single Windows PC.
#
# Run in an ELEVATED PowerShell (Run as Administrator) ON THE TARGET PC:
#   .\install-agent.ps1 -ServerURL "https://docvault.example.com" -AgentPSK "<the DOCVAULT_OSQUERY_PSK from gen-env.sh>"
#
# This is the right script for the "friend's PC over the internet" scenario.
# (deploy-agents.ps1 is for pushing to many PCs from a domain-admin box.)

param(
    [Parameter(Mandatory = $true)][string]$ServerURL,
    [Parameter(Mandatory = $true)][string]$AgentPSK,
    [string]$AgentExe = ".\docvault-clip.exe",
    [string]$InstallDir = "C:\Program Files\DocVault"
)

$ErrorActionPreference = "Stop"

# Require elevation — installing a service and setting machine env vars needs it.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run this in an elevated PowerShell (Run as Administrator)."
    exit 1
}

if ($ServerURL -notmatch '^https://') {
    Write-Warning "ServerURL is not https:// — over the internet you should use HTTPS with a valid certificate."
}

if (-not (Test-Path $AgentExe)) {
    Write-Error "Agent binary not found: $AgentExe`nBuild it with:  GOOS=windows GOARCH=amd64 go build -o docvault-clip.exe ./cmd/clipagent"
    exit 1
}

Write-Host "=== Installing DocVault clipboard agent ==="
Write-Host "Server : $ServerURL"
Write-Host "Target : $InstallDir"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path $AgentExe -Destination "$InstallDir\docvault-clip.exe" -Force

# Machine-level env vars so the Windows service process picks them up at start.
[Environment]::SetEnvironmentVariable("DOCVAULT_SERVER_URL", $ServerURL, "Machine")
[Environment]::SetEnvironmentVariable("DOCVAULT_AGENT_PSK", $AgentPSK, "Machine")
# Also set for the current process so a foreground test run works immediately.
$env:DOCVAULT_SERVER_URL = $ServerURL
$env:DOCVAULT_AGENT_PSK = $AgentPSK

# Install and start the service (implemented in service_windows.go).
& "$InstallDir\docvault-clip.exe" install
Start-Service DocVaultClipAgent -ErrorAction SilentlyContinue

$svc = Get-Service DocVaultClipAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "OK — DocVault agent is installed and running, reporting to $ServerURL" -ForegroundColor Green
    Write-Host "Verify on the server dashboard that '$env:COMPUTERNAME' appears under Agents." -ForegroundColor Green
}
else {
    Write-Host "Installed, but the service is not running yet." -ForegroundColor Yellow
    Write-Host "Check:  Get-Service DocVaultClipAgent   and   Get-EventLog -LogName Application -Source DocVaultClipAgent -Newest 20" -ForegroundColor Yellow
}
