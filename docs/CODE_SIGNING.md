# Code-signing the Windows agent (remove the SmartScreen warning)

## Why
The agent (`dvclip.exe`) is currently **unsigned**, so Windows SmartScreen shows
"Windows의 PC를 보호했습니다 / Windows protected your PC" on first run, and the
employee must click **"추가 정보 → 실행" (More info → Run anyway)**. The install still
works — signing just removes that scary screen so it's truly double-click-only.

## Honest reality (the one step only you can do)
Removing SmartScreen requires a **real Authenticode code-signing certificate**, which
costs money and requires identity verification. **This cannot be faked or self-signed**
(a self-signed cert is untrusted → SmartScreen still warns). The signing pipeline below
is ready; you just need to obtain a cert and point the build at it.

### Which certificate to buy
| Option | Cost | SmartScreen | Notes |
|---|---|---|---|
| **Azure Trusted Signing** | ~$10/mo | reputation builds, fast | Modern, cheapest, CI-friendly; needs Azure account + identity verification (individual or org). **Recommended for a solo founder.** |
| **OV cert** (Sectigo/DigiCert via reseller) | ~$200–400/yr | builds over time (early installs still warned) | Standard `.pfx`; works with the Makefile target below. |
| **EV cert** | ~$300–600/yr + token/HSM | **instant** (no warning from day one) | Best UX, priciest; needs a hardware token or cloud HSM. |

For "the friend should never see SmartScreen from day one" → **EV**. For "cheap and it
clears up after some installs" → OV or Azure Trusted Signing.

## How to sign (once you have a `.pfx`)
On the Mac (cross-platform via `osslsigncode`):
```bash
brew install osslsigncode
export DOCVAULT_WINDOWS_CERT_PATH=/path/to/cert.pfx
export DOCVAULT_WINDOWS_CERT_PASSWORD='...'      # do NOT commit; keep in ~/.secrets
make sign-windows
# -> bin/dvclip-windows-amd64-signed.exe  (timestamped, verified)
```

## How to publish the signed binary
The download endpoint serves `/download/dvclip-windows-amd64.exe` from the box's
`/vault/agents/` directory. Replace it with the **signed** binary:
```bash
scp bin/dvclip-windows-amd64-signed.exe \
    root@<box>:/data/docvault/agents/dvclip-windows-amd64.exe
```
(`/data/docvault` is mounted as `/vault` in the container.) New installs then download
the signed agent; SmartScreen reputation applies from that point.

## Verify
- Mac: `osslsigncode verify bin/dvclip-windows-amd64-signed.exe`
- Windows: right-click the `.exe` → Properties → **Digital Signatures** tab → should list your cert.

## Until you sign
The friend can still install today — the visual guide (`/admin/install` and
`/download/install-windows.ko.html`) walks them through the one SmartScreen click
("추가 정보 → 실행"). Or do the first install remotely (AnyDesk/TeamViewer) yourself.
