# Verifying the Windows agent without a Windows PC (UTM VM on a Mac)

CI (`.github/workflows/ci.yml`, `windows` job) already proves the agent **builds
on Windows and registers as a service**. What CI can't prove is the GUI-only
part — actually capturing the clipboard. To verify that on an Apple-Silicon Mac,
run a free Windows VM.

## 1. Install a Windows VM (free)

- Install **UTM** — https://mac.getutm.app (free).
- Get **Windows 11 ARM**: UTM's "Gallery" has a guided Windows 11 download, or
  use Microsoft's Windows 11 Arm64 VHDX / ISO.
- Create the VM and finish Windows setup.

## 2. Build the agent for Windows on ARM

On the Mac (host), build an ARM64 Windows binary so it runs natively in the VM:

```bash
GOOS=windows GOARCH=arm64 go build -o docvault-clip.exe ./cmd/clipagent
```

(The existing `amd64` build also works via Windows 11 ARM's x64 emulation, but
`arm64` is fastest.)

Copy `docvault-clip.exe` and `scripts/install-agent.ps1` into the VM (UTM shared
folder, or just drag-and-drop).

## 3. Point the agent at your server

The server runs on the Mac host (e.g. `docker compose up`, port 8080). From the
VM, the host is reachable at the host's LAN IP (find it on the Mac with
`ipconfig getifaddr en0`), **not** `localhost`.

In the VM, open **PowerShell as Administrator** and run (replace the IP and PSK):

```powershell
.\install-agent.ps1 -ServerURL "http://192.168.x.x:8080" -AgentPSK "<DOCVAULT_OSQUERY_PSK from the server .env>"
```

This installs `DocVaultClipAgent` as a service and starts it.

## 4. Verify clipboard capture

1. In the VM, copy any file or text (Ctrl+C).
2. On the server dashboard (`http://localhost:8080` on the Mac → **Endpoint
   Events**), the clipboard event should appear within a few seconds.
3. Also check the agent is healthy: `Get-Service DocVaultClipAgent` (should be
   `Running`).

If events don't appear, check:
- Windows Firewall isn't blocking outbound to the server IP/port.
- The PSK matches the server's `DOCVAULT_OSQUERY_PSK`.
- The service env vars: `DOCVAULT_SERVER_URL` / `DOCVAULT_AGENT_PSK` were set
  machine-wide by the installer (a service reads machine env at start).

## 5. Clean up

```powershell
Stop-Service DocVaultClipAgent
.\docvault-clip.exe uninstall
```

> osquery (file/USB/process monitoring) is a separate install on the same VM —
> see `docs/DEPLOY.md` Part 3. Its node enrollment can be verified the same way.
