# Verifying the Windows agent without a Windows PC (UTM VM on a Mac)

CI (`.github/workflows/win-install-test.yml`) proves the current Windows model:
the installer removes old LocalSystem service-mode installs, creates a per-user
Scheduled Task, runs in the interactive user session, posts enroll/heartbeat/
self-test, and captures a real `Set-Clipboard` event. Use this VM procedure to
repeat the same check on your own machine or a real customer PC.

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

Copy `docvault-clip.exe` into the VM only if you are testing the binary directly.
For the product flow, use `/admin/install` and generate a one-time employee link.

## 3. Use the product install flow

The server runs on the Mac host (e.g. `docker compose up`, port 8080). From the
VM, the host is reachable at the host's LAN IP (find it on the Mac with
`ipconfig getifaddr en0`), **not** `localhost`.

1. Log in to DocVault as admin.
2. Open `/admin/install`.
3. Select the employee and create a one-time Windows install link.
4. Open that link inside the Windows VM.
5. Download and run `docvault-install.bat`.

The `.bat` contains the server URL, PSK, and install token. The employee page
does not show those values. The installed agent runs through a per-user Scheduled
Task, not a Windows service, because clipboard APIs are scoped to the interactive
desktop session.

## 4. Verify clipboard capture

1. In the VM, copy any file or text (Ctrl+C).
2. On the server dashboard (`http://localhost:8080` on the Mac), the Windows
   onboarding queue should eventually show the PC as no longer "캡처 미검증".
3. Open `/admin/agents` and confirm:
   - `보고중`
   - `interactive_user`
   - `캡처 검증됨`
   - the selected employee is already assigned

If events don't appear, check:
- Windows Firewall isn't blocking outbound to the server IP/port.
- The one-time link was not already used or expired.
- The Scheduled Task exists: `schtasks /Query /TN DocVaultClipAgent /V /FO LIST`.
- `C:\DocVault\run-docvault-agent.cmd` contains `DOCVAULT_SERVER_URL`,
  `DOCVAULT_AGENT_PSK`, and `DOCVAULT_INSTALL_TOKEN`.

## 5. Clean up

```powershell
schtasks /Delete /TN "DocVaultClipAgent" /F
C:\DocVault\dvclip.exe uninstall
```

> osquery (file/USB/process monitoring) is a separate install on the same VM —
> see `docs/DEPLOY.md` Part 3. Its node enrollment can be verified the same way.
