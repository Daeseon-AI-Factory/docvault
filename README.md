# DocVault

**On-premise document security & endpoint monitoring system** for 40-user manufacturing/engineering teams.

Replaces expensive Korean DRM solutions (Fasoo, Softcamp) with a lightweight **detection-based** approach — monitors everything, blocks nothing, zero impact on employee productivity.

## Why DocVault?

| Traditional DRM | DocVault |
|---|---|
| Kernel-mode drivers, DLL injection | User-mode detection only |
| ~400MB RAM (JVM), slow startup | ~50MB RAM, single binary |
| $50K+/year license | Open source, self-hosted |
| Blocks file access, breaks workflows | Never blocks — detect & alert |
| Complex deployment, agent conflicts | Single binary + osquery |

## Key Features

### Endpoint Monitoring (Zero interference)
- **File operations**: create, modify, delete, rename, copy — all tracked via osquery
- **Messenger detection**: KakaoTalk, Telegram, Slack, Discord, Teams accessing documents
- **Email attachment tracking**: Outlook, Thunderbird opening sensitive files
- **USB copy detection**: files written to removable drives (E:, F:, G:, H:)
- **Network share copy**: files written to UNC paths (\\\\server\\share)
- **Clipboard monitoring**: copy events with source app detection (Windows + macOS)
- **Screen capture detection**: SnippingTool, ShareX, Lightshot, Greenshot, PicPick
- **Print job tracking**: spooler activity monitoring
- **Extension disguise detection**: `.dwg` renamed to `.jpg` detected via hash comparison
- **Cloud upload detection**: browser processes accessing document files

### File Tracking (SHA-256 Hash-based)
- Register any file → SHA-256 hash computed automatically
- Tracked across all endpoints regardless of rename/move/extension change
- Detection log with hostname, path, process, timestamp
- Sensitivity levels: Restricted, Confidential, Top Secret

### User & Entity Behavior Analytics (UEBA)
- Per-user behavioral baselines (30-day rolling window)
- 10 anomaly types with weighted risk scoring (0-100):
  - Extension disguise (30), Messenger file leak (25), Bulk download (20)
  - Bulk clipboard (15), Rapid access (12), After-hours (10)
  - Weekend access (8), Unusual file type (8), New IP/hostname (5)
- Daily baseline recalculation (automatic at 2:00 AM)
- Dashboard widget: Top 5 risky users with color-coded severity

### Security
- **AES-256 streaming encryption** — files never fully buffered in memory
- **Envelope encryption** — per-file keys encrypted by master key
- **Two-factor authentication (TOTP)** — Google Authenticator compatible, 8 recovery codes
- **CSRF protection** — HMAC-signed tokens on all POST forms
- **Login rate limiting** — 5 failures → 15-minute IP lockout
- **JWT auto-refresh** — transparent cookie renewal within 5 minutes of expiry
- **Audit middleware** — every authenticated request auto-logged with tamper-evident hash chain

### Real-time Dashboard (SSE)
- Server-Sent Events push endpoint/alert/audit events to connected browsers
- Auto-reconnect with visual status indicator
- New events flash-highlighted and prepended to tables

### DB-driven Configuration
- Monitored processes, file extensions, paths, disguise rules — all managed via Admin UI
- No code changes needed to add new messenger apps or file types
- 5-minute cache with auto-refresh

## Architecture

```
Browser ──→ Nginx (TLS) ──→ DocVault Server ──→ PostgreSQL
                                    ↑
          osquery agents ───────────┘  POST /api/events/osquery
          clipboard agents ─────────┘  POST /api/events/clipboard
                                    ↓
                              Alert Engine ──→ Slack / Email
                              UEBA Analyzer ──→ Risk Scores
                              File Tracker ──→ Hash Matching
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Go 1.22+ |
| Database | PostgreSQL 16 |
| Router | chi |
| Auth | JWT + bcrypt + TOTP (RFC 6238) |
| Encryption | AES-256-CTR streaming + GCM envelope |
| Frontend | htmx + Go html/template |
| Endpoint Agent | osquery 5.x |
| Clipboard Agent | Custom Go binary (Win32 API / macOS pbpaste) |
| Real-time | Server-Sent Events (SSE) |

## Project Stats

- **12,200+ lines** of Go code
- **66 source files**, 12 SQL migrations
- **97 test functions** across 9 packages
- **Cross-platform**: Windows (exe + service), macOS (Intel + Apple Silicon)
- Single binary: **~21MB server**, **~9MB agent**

## Quick Start

```bash
# Build
make build                    # Server
make clipagent-all            # Clipboard agents (Windows + macOS)

# Database
psql -U postgres -c "CREATE DATABASE docvault;"
./bin/docvault migrate        # Apply 12 migrations
./bin/docvault seed           # Create admin user + default alert rules

# Run
./bin/docvault serve          # http://localhost:8080
                              # Login: admin / admin1234!
```

## Agent Deployment

### Clipboard Agent — Windows
```powershell
docvault-clip.exe install     # Register as Windows service (auto-start, auto-recovery)
net start DocVaultClipAgent   # Start service
```

### Clipboard Agent — macOS
```bash
cp docvault-clip-mac /usr/local/bin/docvault-clip
launchctl load ~/Library/LaunchAgents/com.docvault.clipagent.plist
```

### osquery
```bash
# Copy configs to C:\ProgramData\osquery\
cp deploy/osquery/osquery.conf deploy/osquery/osquery.flags
# osquery service auto-enrolls with DocVault server
```

## Project Structure

```
cmd/
  server/                 Entry point (serve, migrate, seed)
  clipagent/              Cross-platform clipboard agent
    agent.go              Shared logic (enroll, send, monitor loop)
    clipboard_windows.go  Win32 API clipboard monitoring
    clipboard_darwin.go   macOS pbpaste monitoring
    service_windows.go    Windows SCM service management
    service_darwin.go     macOS launchd support

internal/
  auth/                   JWT + bcrypt + TOTP + middleware
  vault/                  AES-256 streaming encryption + storage
  folder/                 Folder CRUD + permission hierarchy
  audit/                  Auto-logging middleware + CSV export
  endpoint/               osquery/clipboard ingestion + unified timeline
  alert/                  Rule engine + Slack webhook notifications
  monitoring/             DB-driven config (processes, extensions, paths)
  tracking/               SHA-256 hash-based file tracking
  ueba/                   User behavior analytics + risk scoring
  web/                    Router + SSE + CSRF + rate limiting + templates
  config/                 Environment-based configuration
  database/               Connection pool + embedded migrations (12)

deploy/
  osquery/                osquery.conf + osquery.flags
  nginx/                  Reverse proxy with TLS
  systemd/                Linux service unit
  launchd/                macOS agent plist
  backup/                 Daily pg_dump + rsync script
```

## Testing

```bash
make test-all     # Build + vet + 97 tests across 9 packages
make ci           # Same as test-all (CI pipeline target)
```

Pre-commit hook runs automatically on every commit:
```
build → vet → test (all 9 packages) → commit allowed
```

## Web Pages

| URL | Description |
|---|---|
| `/dashboard` | Real-time stats, alerts, SSE events, risk users |
| `/files` | Encrypted file vault with folder navigation |
| `/audit/search` | Audit log search + CSV export |
| `/events/search` | Endpoint event search + CSV export |
| `/admin/users` | User management (create, edit, reset password) |
| `/admin/alerts` | Alert rules (11 pre-configured) |
| `/admin/monitoring` | Monitored processes, extensions, paths (DB-driven) |
| `/admin/tracking` | Hash-based file tracking (register, detect, history) |
| `/admin/agents` | Endpoint agent status |
| `/account/2fa` | Two-factor authentication setup |

## Design Decisions

1. **Detection over Prevention** — No kernel drivers, no DLL injection, no OS hooks. Zero performance impact on employee PCs.
2. **Go over Java/Spring** — Single 21MB binary, ~50MB RAM. No JVM, no container required.
3. **PostgreSQL only** — 40 users, ~50K events/day. No Elasticsearch, no Redis, no Kafka needed.
4. **htmx over React** — Server-rendered HTML, no build step, no node_modules.
5. **On-premise** — Document security product. Files stay on company network.

## License

MIT
