# DocVault

On-premise document security & audit system for 40-user manufacturing/engineering teams.
Replaces expensive DRM solutions (Fasoo/Softcamp) with a lightweight detection-based approach.

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 16
- (Optional) osquery 5.x on endpoint PCs

### 1. Configure

```bash
cp .env.example .env
# Edit .env with your database credentials and a 32-byte hex master key
```

### 2. Build

```bash
make build       # Server binary -> bin/docvault
make clipagent   # Clipboard agent -> bin/docvault-clip.exe
```

### 3. Database Setup

```bash
# Create database and user
psql -U postgres -c "CREATE USER docvault_app WITH PASSWORD 'yourpassword';"
psql -U postgres -c "CREATE DATABASE docvault OWNER docvault_app;"

# Run migrations
./bin/docvault migrate

# Create initial admin user (admin / admin1234!)
./bin/docvault seed
```

### 4. Run

```bash
./bin/docvault serve
# Server starts at http://localhost:8080
# Login: admin / admin1234!
```

## Architecture

```
Browser ──→ Nginx (TLS) ──→ DocVault Server ──→ PostgreSQL
                                    ↑
          osquery agents ───────────┘ (POST /api/events/osquery)
          clipboard agents ─────────┘ (POST /api/events/clipboard)
```

- **AES-256 streaming encryption** — files never fully buffered in memory
- **Envelope encryption** — each file key encrypted by master key
- **Audit middleware** — every authenticated request auto-logged
- **Detection over prevention** — osquery monitors, server alerts

## Agent Deployment

### Clipboard Agent (Windows)

```powershell
# Set environment variables
setx DOCVAULT_SERVER_URL "https://docvault.company.local"
setx DOCVAULT_AGENT_PSK "your-pre-shared-key"

# Install as Windows service (run as Administrator)
docvault-clip.exe install
net start DocVaultClipAgent

# Or run in console mode for testing
docvault-clip.exe
```

### osquery

1. Install osquery from https://osquery.io
2. Copy `deploy/osquery/osquery.conf` and `osquery.flags` to `C:\ProgramData\osquery\`
3. Set enrollment secret in `C:\ProgramData\osquery\enroll_secret`
4. Start osquery service

## Pre-Deployment Verification

```bash
make precheck
```

Runs build, vet, 47 unit tests (180 subtests), binary compilation, and file integrity checks.
**If any step fails, do not deploy.**

## Project Structure

```
cmd/server/          Server entry point (serve, migrate, seed)
cmd/clipagent/       Windows clipboard monitoring agent
internal/
  auth/              JWT + bcrypt + middleware
  vault/             AES-256 streaming encrypt/decrypt + storage
  folder/            Folder CRUD + permission hierarchy
  audit/             Auto-logging middleware + search + dashboard
  endpoint/          osquery/clipboard event ingestion + unified timeline
  alert/             Rule engine + Slack notifications
  web/               chi router + htmx templates + form handlers
  config/            Environment-based configuration
  database/          PostgreSQL connection pool + embedded migrations
deploy/              nginx, systemd, osquery, backup configs
scripts/precheck.sh  Pre-deployment verification script
```

## Commands

| Command | Description |
|---------|-------------|
| `make build` | Build server binary |
| `make clipagent` | Build clipboard agent (Windows) |
| `make run` | Build and run server |
| `make migrate` | Apply database migrations |
| `make seed` | Create initial admin user |
| `make test` | Run all tests |
| `make precheck` | Full pre-deployment verification |

## License

Proprietary. Internal use only.
