# DocVault Agent Deployment Script
# Run as Domain Admin on a management PC
# Usage: .\deploy-agents.ps1 -ServerURL "http://docvault:8080" -AgentPath "\\fileserver\share\docvault-clip.exe"

param(
    [string]$ServerURL = "http://docvault:8080",
    [string]$AgentPath = ".\docvault-clip.exe",
    [string]$PCListFile = ".\pc-list.txt",     # One hostname per line
    [string]$InstallDir = "C:\Program Files\DocVault"
)

# Read PC list
if (Test-Path $PCListFile) {
    $PCs = Get-Content $PCListFile | Where-Object { $_ -ne "" }
} else {
    Write-Host "Create $PCListFile with one PC hostname per line:"
    Write-Host "  PC-ENG-001"
    Write-Host "  PC-ENG-002"
    Write-Host "  ..."
    exit 1
}

Write-Host "=== DocVault Agent Deployment ==="
Write-Host "Server: $ServerURL"
Write-Host "Agent:  $AgentPath"
Write-Host "PCs:    $($PCs.Count)"
Write-Host ""

$success = 0
$failed = 0

foreach ($pc in $PCs) {
    Write-Host -NoNewline "[$pc] "
    try {
        # Test connectivity
        if (!(Test-Connection -ComputerName $pc -Count 1 -Quiet)) {
            Write-Host "OFFLINE" -ForegroundColor Yellow
            $failed++
            continue
        }

        # Create install directory
        $remotePath = "\\$pc\C$\Program Files\DocVault"
        if (!(Test-Path $remotePath)) {
            New-Item -Path $remotePath -ItemType Directory -Force | Out-Null
        }

        # Copy agent binary
        Copy-Item -Path $AgentPath -Destination "$remotePath\docvault-clip.exe" -Force

        # Install and start service remotely
        Invoke-Command -ComputerName $pc -ScriptBlock {
            param($serverURL, $installDir)

            # Set environment variables (machine-level)
            [Environment]::SetEnvironmentVariable("DOCVAULT_SERVER_URL", $serverURL, "Machine")

            # Install service
            & "$installDir\docvault-clip.exe" install 2>&1 | Out-Null

            # Start service
            Start-Service DocVaultClipAgent -ErrorAction SilentlyContinue

            # Verify
            $svc = Get-Service DocVaultClipAgent -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                return "OK"
            } else {
                return "FAILED"
            }
        } -ArgumentList $ServerURL, $InstallDir

        Write-Host "OK" -ForegroundColor Green
        $success++
    }
    catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "=== Deployment Complete ==="
Write-Host "Success: $success / $($PCs.Count)"
Write-Host "Failed:  $failed / $($PCs.Count)"
