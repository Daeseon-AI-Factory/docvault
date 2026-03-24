# DocVault - Document Security & Audit System

## Project Overview
On-premise document vault with endpoint monitoring for 40-user manufacturing/engineering teams.
Replaces expensive DRM solutions (Fasoo/Softcamp) with a lightweight detection-based system.

## Architecture Decision Records

### ADR-001: Go over Spring/Kotlin
- File I/O streaming (io.Reader/Writer) is native and efficient for large CAD files
- Single 15MB binary deployment, no JVM overhead
- ~50MB RAM runtime vs ~400MB JVM idle
- Better fit for Toronto AI startup job market

### ADR-002: PostgreSQL only, no Elasticsearch/Redis/Kafka
- 40 users, ~50K events/day — PostgreSQL handles everything
- Full-text search via tsvector is sufficient
- Adding more services triples ops complexity for zero benefit

### ADR-003: Detection over Prevention
- osquery (user-mode) detects and logs file operations
- No kernel-mode drivers, no DLL injection, no OS hooks
- Near-zero performance impact on employee PCs (~50MB RAM, ~1% CPU)
- Tradeoff: cannot block actions in real-time, only detect after the fact

### ADR-004: htmx over React for frontend
- Server-rendered HTML with htmx for interactivity
- No build step, no node_modules, no webpack
- Go templates handle all rendering
- Faster to build, simpler to maintain

### ADR-005: On-premise over cloud
- Document security product — files should stay on company network
- Single server, all services on one box
- Lower TCO than cloud for 40 users

## Tech Stack
- **Language**: Go 1.22+
- **Database**: PostgreSQL 16
- **Router**: chi (github.com/go-chi/chi/v5)
- **DB Driver**: pgx (github.com/jackc/pgx/v5)
- **SQL**: sqlc for type-safe query generation
- **Auth**: JWT (github.com/golang-jwt/jwt/v5)
- **Crypto**: stdlib crypto/aes, crypto/cipher (AES-256-GCM)
- **Hashing**: stdlib crypto/sha256 (file integrity), golang.org/x/crypto/bcrypt (passwords)
- **Frontend**: htmx + Go html/template
- **Endpoint Agent**: osquery 5.x (pre-built, we only configure)
- **Clipboard Agent**: Custom Go binary using golang.org/x/sys/windows
- **Reverse Proxy**: Nginx
- **Migration**: golang-migrate
- **Logging**: stdlib log/slog (structured JSON logging)
- **UUID**: github.com/google/uuid

## Project Structure
```
docvault/
├── CLAUDE.md                    # This file
├── DIRECTION_GUARD.md           # Scope guard — what NOT to build
├── go.mod
├── go.sum
├── cmd/
│   ├── server/
│   │   └── main.go              # Entry point, wire dependencies
│   └── clipagent/
│       └── main.go              # Windows clipboard monitoring agent
├── internal/
│   ├── config/
│   │   └── config.go            # Env/file-based configuration
│   ├── database/
│   │   ├── db.go                # PostgreSQL connection pool
│   │   └── migrations/          # SQL migration files
│   │       ├── 001_users.up.sql
│   │       ├── 001_users.down.sql
│   │       ├── 002_folders_files.up.sql
│   │       ├── 002_folders_files.down.sql
│   │       ├── 003_audit_logs.up.sql
│   │       ├── 003_audit_logs.down.sql
│   │       ├── 004_endpoint_events.up.sql
│   │       ├── 004_endpoint_events.down.sql
│   │       ├── 005_alerts.up.sql
│   │       ├── 005_alerts.down.sql
│   │       ├── 006_encryption_keys.up.sql
│   │       ├── 006_encryption_keys.down.sql
│   │       ├── 007_agent_registry.up.sql
│   │       ├── 007_agent_registry.down.sql
│   │       └── 008_hostname_mapping.up.sql
│   ├── auth/
│   │   ├── jwt.go               # JWT generation, validation, refresh
│   │   ├── jwt_test.go          # JWT round-trip, expiry, invalid sig tests
│   │   ├── middleware.go        # Auth middleware (extract user from JWT)
│   │   └── handler.go           # Login, logout, refresh endpoints
│   ├── user/
│   │   ├── model.go             # User struct, roles enum
│   │   ├── repository.go        # DB queries (CRUD)
│   │   └── handler.go           # Admin user management endpoints
│   ├── vault/
│   │   ├── encryption.go        # AES-256-GCM encrypt/decrypt streaming
│   │   ├── encryption_test.go   # Round-trip, wrong key, tamper detection
│   │   ├── storage.go           # Disk storage (write/read encrypted blobs)
│   │   ├── storage_test.go      # Store/retrieve, concurrent uploads
│   │   ├── keymanager.go        # Envelope encryption, master key handling
│   │   ├── model.go             # File, FileVersion, Folder structs
│   │   ├── repository.go        # DB queries for files, folders, versions
│   │   └── handler.go           # Upload, download, checkout, checkin, delete
│   ├── folder/
│   │   ├── model.go             # Folder, FolderPermission structs
│   │   ├── repository.go        # DB queries
│   │   └── handler.go           # Folder CRUD, permission management
│   ├── audit/
│   │   ├── model.go             # AuditLog struct, action enum
│   │   ├── middleware.go        # Auto-logging middleware (cross-cutting)
│   │   ├── repository.go        # DB queries (insert, search, aggregate)
│   │   ├── repository_test.go   # Unified timeline, search tests
│   │   └── handler.go           # User audit view, file audit view, search, dashboard stats
│   ├── endpoint/
│   │   ├── model.go             # EndpointEvent struct, event type enum
│   │   ├── osquery.go           # osquery event receiver, normalizer
│   │   ├── osquery_test.go      # Event normalization, drive detection tests
│   │   ├── clipboard.go         # Clipboard event receiver
│   │   ├── repository.go        # DB queries for endpoint events
│   │   └── handler.go           # POST /api/events/osquery, /api/events/clipboard
│   ├── alert/
│   │   ├── model.go             # Alert, AlertRule structs
│   │   ├── engine.go            # Rule evaluation engine
│   │   ├── engine_test.go       # All rule type tests
│   │   ├── notifier.go          # Slack webhook, email notifications
│   │   ├── repository.go        # DB queries
│   │   └── handler.go           # Alert list, acknowledge endpoints
│   ├── agent/
│   │   ├── model.go             # AgentRegistration, HostnameMapping structs
│   │   ├── registry.go          # Agent enrollment, heartbeat, status
│   │   ├── repository.go        # DB queries
│   │   └── handler.go           # POST /api/agents/enroll, GET /api/admin/agents
│   ├── retention/
│   │   ├── cleaner.go           # Data retention: partition mgmt + archival
│   │   └── cleaner_test.go
│   ├── apierror/
│   │   └── error.go             # Standardized API error response
│   └── web/
│       ├── router.go            # chi router setup, middleware chain
│       ├── templates/           # Go html/template files
│       │   ├── layout.html      # Base layout with nav
│       │   ├── login.html
│       │   ├── dashboard.html
│       │   ├── files.html       # File browser
│       │   ├── file_detail.html # File detail + versions
│       │   ├── audit_user.html  # User timeline
│       │   ├── audit_file.html  # File timeline
│       │   ├── audit_search.html
│       │   ├── admin_users.html
│       │   ├── admin_alerts.html
│       │   └── admin_agents.html
│       └── static/
│           ├── htmx.min.js
│           └── style.css
├── deploy/
│   ├── osquery/
│   │   ├── osquery.conf         # osquery configuration
│   │   ├── osquery.flags        # osquery daemon flags
│   │   └── enrollment.ps1       # PowerShell: install + enroll agent
│   ├── clipagent/
│   │   └── install.ps1          # PowerShell: install clipboard agent
│   ├── nginx/
│   │   └── docvault.conf        # Nginx reverse proxy config
│   ├── systemd/
│   │   └── docvault.service     # systemd service file
│   └── backup/
│       └── backup.sh            # Daily pg_dump + rsync script
└── docs/
    ├── DocVault_Architecture.docx
    └── DocVault_UserFlows.docx
```

## Development Workflow

### Build & Run
```bash
# Build server
go build -o bin/docvault ./cmd/server

# Run with config
DOCVAULT_DB_URL="postgres://docvault_app:pass@localhost:5432/docvault" \
DOCVAULT_MASTER_KEY="your-32-byte-hex-key" \
DOCVAULT_VAULT_PATH="/vault" \
./bin/docvault serve

# Run migrations
./bin/docvault migrate up

# Build clipboard agent (cross-compile for Windows)
GOOS=windows GOARCH=amd64 go build -o bin/docvault-clip.exe ./cmd/clipagent
```

### Testing
```bash
go test ./...
go test -race ./...              # Race detector
go test -count=1 ./internal/vault/...  # No cache
```

---

## Database Schema Addendum: Indexes

CRITICAL: Without these indexes, audit/event queries will table-scan and become unusable within weeks.

### Migration 003: audit_logs indexes
```sql
-- Primary query pattern: "show me all actions by user X in time range"
CREATE INDEX idx_audit_logs_user_created ON audit_logs (user_id, created_at DESC);

-- Secondary: "show me all actions on file X"
CREATE INDEX idx_audit_logs_target ON audit_logs (target_type, target_id, created_at DESC);

-- Dashboard: "count events today"
CREATE INDEX idx_audit_logs_created ON audit_logs (created_at DESC);

-- Full-text search on target_name and detail
CREATE INDEX idx_audit_logs_search ON audit_logs USING gin (
    to_tsvector('simple', coalesce(target_name, '') || ' ' || coalesce(detail::text, ''))
);
```

### Migration 004: endpoint_events indexes
```sql
-- Primary: "show me all events from user X's PC"
CREATE INDEX idx_endpoint_events_user_time ON endpoint_events (user_id, event_time DESC);

-- Secondary: "show me all events for filename X"
CREATE INDEX idx_endpoint_events_filename ON endpoint_events (file_name, event_time DESC);

-- Alert engine: "find USB events in last N minutes"
CREATE INDEX idx_endpoint_events_type_time ON endpoint_events (event_type, event_time DESC);

-- Agent health: "last event from hostname X"
CREATE INDEX idx_endpoint_events_hostname ON endpoint_events (hostname, event_time DESC);

-- File extension filtering
CREATE INDEX idx_endpoint_events_ext ON endpoint_events (file_extension) WHERE file_extension IS NOT NULL;
```

### Migration 005: alerts indexes
```sql
CREATE INDEX idx_alerts_unacked ON alerts (acknowledged, created_at DESC) WHERE acknowledged = false;
CREATE INDEX idx_alerts_severity ON alerts (severity, created_at DESC);
```

### Migration 002: files/folders indexes
```sql
CREATE INDEX idx_files_folder ON files (folder_id, is_deleted);
CREATE INDEX idx_files_created_by ON files (created_by);
CREATE INDEX idx_file_versions_file ON file_versions (file_id, version DESC);
CREATE INDEX idx_folders_parent ON folders (parent_id);
```

### Estimated table sizes (1 year, 40 users)
```
audit_logs:       ~2M rows (50K/day x 365 / weekends)
endpoint_events:  ~30M rows (40 PCs x events every 30s x 8 hours x 250 days)
files:            ~10K rows
file_versions:    ~30K rows
alerts:           ~5K rows
```

At 30M rows, endpoint_events NEEDS partitioning. See Data Retention section below.

---

## Standardized API Error Response

ALL error responses MUST use this format. Never return plain text errors or inconsistent JSON shapes.

```go
// internal/apierror/error.go
package apierror

import (
    "encoding/json"
    "net/http"
)

type APIError struct {
    Status  int    `json:"-"`
    Code    string `json:"code"`              // machine-readable: "AUTH_FAILED", "NOT_FOUND", "FORBIDDEN"
    Message string `json:"message"`           // human-readable: "Invalid email or password"
    Detail  any    `json:"detail,omitempty"`   // optional: validation errors, context
}

func (e *APIError) Write(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(e.Status)
    json.NewEncoder(w).Encode(e)
}

// Predefined errors
var (
    ErrUnauthorized    = &APIError{Status: 401, Code: "AUTH_REQUIRED",     Message: "Authentication required"}
    ErrInvalidLogin    = &APIError{Status: 401, Code: "AUTH_FAILED",       Message: "Invalid email or password"}
    ErrForbidden       = &APIError{Status: 403, Code: "FORBIDDEN",        Message: "You do not have permission to perform this action"}
    ErrNotFound        = &APIError{Status: 404, Code: "NOT_FOUND",        Message: "Resource not found"}
    ErrConflict        = &APIError{Status: 409, Code: "CONFLICT",         Message: "Resource already exists or is locked"}
    ErrCheckedOut      = &APIError{Status: 409, Code: "CHECKED_OUT",      Message: "File is checked out by another user"}
    ErrValidation      = &APIError{Status: 422, Code: "VALIDATION_FAILED",Message: "Request validation failed"}
    ErrTooLarge        = &APIError{Status: 413, Code: "FILE_TOO_LARGE",   Message: "File exceeds maximum upload size"}
    ErrRateLimit       = &APIError{Status: 429, Code: "RATE_LIMITED",      Message: "Too many requests, please try again later"}
    ErrInternal        = &APIError{Status: 500, Code: "INTERNAL_ERROR",    Message: "An internal error occurred"}
)

// WithDetail returns a copy with additional context
func (e *APIError) WithDetail(detail any) *APIError {
    return &APIError{Status: e.Status, Code: e.Code, Message: e.Message, Detail: detail}
}
```

### Usage in handlers
```go
// CORRECT
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
    file, err := h.repo.GetByID(r.Context(), fileID)
    if err != nil {
        apierror.ErrNotFound.Write(w)
        return
    }
    if !h.canDownload(user, file.FolderID) {
        apierror.ErrForbidden.Write(w)
        return
    }
}

// WRONG — never do this
w.WriteHeader(403)
w.Write([]byte("forbidden"))
```

---

## Hostname-to-User Mapping

### Migration 008: hostname_mapping
```sql
CREATE TABLE hostname_mappings (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname   VARCHAR(100) NOT NULL UNIQUE,  -- PC hostname e.g. "PC-KIM"
    user_id    UUID NOT NULL REFERENCES users(id),
    ip_address INET,                          -- optional: last known IP
    notes      TEXT,                          -- e.g. "Engineering dept, desk 3A"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_hostname_mapping_user ON hostname_mappings (user_id);
CREATE INDEX idx_hostname_mapping_hostname ON hostname_mappings (hostname);
```

### How it works
When osquery sends events, each event includes the PC hostname. The endpoint event receiver looks up the hostname in this table to attach a user_id:

```go
func (h *Handler) ReceiveOsqueryEvents(w http.ResponseWriter, r *http.Request) {
    var batch OsqueryBatch
    json.NewDecoder(r.Body).Decode(&batch)

    // Look up user from hostname
    mapping, err := h.agentRepo.GetByHostname(r.Context(), batch.Hostname)
    if err != nil {
        slog.Warn("unknown hostname", "hostname", batch.Hostname)
        // Still store event with user_id = NULL, don't drop it
    }

    for _, event := range batch.Events {
        event.Hostname = batch.Hostname
        if mapping != nil {
            event.UserID = &mapping.UserID
        }
        h.repo.Insert(r.Context(), event)
    }
}
```

### Admin configures this during user setup
When admin creates a new user, they also register the user's PC hostname:
```
POST /api/admin/hostname-mapping
{
    "hostname": "PC-KIM",
    "user_id": "abc-123-...",
    "notes": "Engineering dept, desk 3A"
}
```

One user can have multiple hostnames (laptop + desktop). One hostname maps to exactly one user.

---

## Agent Authentication Protocol

### osquery -> Server authentication

osquery uses a **pre-shared key (PSK)** model. Each agent includes the PSK in the HTTP header:

```
POST /api/events/osquery
Headers:
    Content-Type: application/json
    X-Agent-PSK: <pre-shared-key>
    X-Agent-Hostname: PC-KIM
```

The Go server validates:
```go
func AgentAuthMiddleware(psk string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Header.Get("X-Agent-PSK") != psk {
                apierror.ErrUnauthorized.Write(w)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

### Agent enrollment flow
```
1. Admin installs osquery on PC-KIM
2. Admin runs enrollment script:
   deploy/osquery/enrollment.ps1 -Server "https://docvault.internal" -PSK "shared-key" -Hostname "PC-KIM"
3. Script writes osquery.conf with server URL and PSK
4. Script registers agent with server: POST /api/agents/enroll
5. Server creates agent_registry entry
6. osqueryd service starts, begins sending events
```

### Migration 007: agent_registry
```sql
CREATE TABLE agent_registry (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname      VARCHAR(100) NOT NULL UNIQUE,
    agent_type    VARCHAR(20) NOT NULL,          -- 'osquery' or 'clipboard'
    agent_version VARCHAR(20),
    os_version    VARCHAR(100),
    last_seen_at  TIMESTAMPTZ,
    enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    active        BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_agent_registry_lastseen ON agent_registry (last_seen_at DESC);
```

### Agent heartbeat
Every batch event POST also counts as a heartbeat. The server updates `last_seen_at` on every successful event ingestion. If an agent hasn't been seen in 10+ minutes, alert fires (Agent Offline rule).

---

## osquery Configuration Spec

### deploy/osquery/osquery.conf
```json
{
  "options": {
    "logger_plugin": "tls",
    "logger_tls_endpoint": "/api/events/osquery",
    "logger_tls_period": 30,
    "config_plugin": "tls",
    "enroll_secret_path": "C:\\Program Files\\osquery\\enroll_secret",
    "host_identifier": "hostname",
    "tls_hostname": "docvault.internal",
    "tls_server_certs": "C:\\Program Files\\osquery\\server.pem",
    "disable_events": false,
    "enable_file_events": true,
    "enable_ntfs_event_publisher": true
  },
  "schedule": {
    "file_events": {
      "query": "SELECT target_path, action, md5, sha256, time, eid FROM file_events;",
      "interval": 30,
      "removed": false
    },
    "usb_devices": {
      "query": "SELECT vendor, model, serial, removable FROM usb_devices WHERE removable = 1;",
      "interval": 10
    },
    "process_open_files": {
      "query": "SELECT p.name AS process_name, p.path AS process_path, pof.path AS file_path FROM processes p JOIN process_open_files pof ON p.pid = pof.pid WHERE pof.path LIKE 'C:\\Users\\%' OR pof.path LIKE 'D:\\%';",
      "interval": 60
    },
    "print_events": {
      "query": "SELECT datetime, source, data FROM windows_eventlog WHERE source = 'Microsoft-Windows-PrintService' AND eventid = 307 AND datetime > (SELECT CAST(strftime('%s','now','-60 seconds') AS INTEGER));",
      "interval": 60
    }
  },
  "file_paths": {
    "documents": [
      "C:\\Users\\%\\Documents\\%%",
      "C:\\Users\\%\\Desktop\\%%",
      "C:\\Users\\%\\Downloads\\%%"
    ],
    "projects": [
      "D:\\Projects\\%%",
      "D:\\Drawings\\%%"
    ],
    "removable": [
      "E:\\%%",
      "F:\\%%",
      "G:\\%%"
    ]
  },
  "file_accesses": ["documents", "projects", "removable"]
}
```

### deploy/osquery/osquery.flags
```
--tls_hostname=docvault.internal
--tls_server_certs=C:\Program Files\osquery\server.pem
--enroll_secret_path=C:\Program Files\osquery\enroll_secret
--host_identifier=hostname
--enable_ntfs_event_publisher=true
--disable_events=false
--logger_plugin=tls
--logger_tls_endpoint=/api/events/osquery
--logger_tls_period=30
--config_plugin=tls
--config_tls_endpoint=/api/config/osquery
--config_refresh=300
--watchdog_memory_limit=100
--watchdog_utilization_limit=10
```

### osquery event format (what the server receives)
```json
{
  "node_key": "PC-KIM",
  "log_type": "result",
  "data": [
    {
      "name": "file_events",
      "hostIdentifier": "PC-KIM",
      "calendarTime": "Tue Mar 23 14:22:31 2026 UTC",
      "unixTime": 1774548151,
      "columns": {
        "target_path": "C:\\Users\\Kim\\Documents\\plan_v3.dwg",
        "action": "CREATED",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "time": "1774548151"
      }
    }
  ]
}
```

### Event normalization (osquery -> endpoint_events table)
```go
func NormalizeOsqueryEvent(raw OsqueryResult) EndpointEvent {
    return EndpointEvent{
        Hostname:      raw.HostIdentifier,
        EventType:     mapAction(raw.Columns["action"]),  // CREATED->FILE_CREATE, UPDATED->FILE_MODIFY, etc.
        FilePath:      raw.Columns["target_path"],
        FileName:      filepath.Base(raw.Columns["target_path"]),
        FileExtension: filepath.Ext(raw.Columns["target_path"]),
        DriveType:     detectDriveType(raw.Columns["target_path"]),  // "local", "removable", "network"
        ProcessName:   raw.Columns["process_name"],
        EventTime:     time.Unix(raw.UnixTime, 0),
        ReceivedAt:    time.Now(),
    }
}

func detectDriveType(path string) string {
    drive := strings.ToUpper(path[:2])
    switch {
    case drive == "C:" || drive == "D:":
        return "local"
    case drive == "E:" || drive == "F:" || drive == "G:":
        return "removable"    // Configurable: which drive letters are removable
    case strings.HasPrefix(path, "\\\\"):
        return "network"
    default:
        return "unknown"
    }
}
```

---

## Windows Clipboard Agent Spec

### cmd/clipagent/main.go requirements

The clipboard agent is a small Go binary that runs on each Windows PC alongside osquery. It monitors clipboard content changes and sends events to the server.

### Win32 API calls needed
```go
import "golang.org/x/sys/windows"

// Functions to call:
// 1. user32.dll -> AddClipboardFormatListener(hwnd) — register for clipboard change notifications
// 2. user32.dll -> GetClipboardData(format) — read clipboard content metadata
// 3. user32.dll -> OpenClipboard(hwnd) / CloseClipboard()
// 4. kernel32.dll -> GlobalLock / GlobalUnlock — access clipboard memory
// 5. user32.dll -> GetForegroundWindow + GetWindowText — identify source application

// Message loop:
// WM_CLIPBOARDUPDATE (0x031D) fires when clipboard content changes
```

### What to capture (NOT the content itself — privacy)
```go
type ClipboardEvent struct {
    Hostname          string    `json:"hostname"`
    Timestamp         time.Time `json:"timestamp"`
    SourceApp         string    `json:"source_app"`        // "AUTOCAD.EXE", "EXCEL.EXE"
    SourceWindowTitle string    `json:"source_window"`     // "plan_v3.dwg - AutoCAD"
    ContentType       string    `json:"content_type"`      // "text", "image", "files", "rich_text"
    ContentLength     int       `json:"content_length"`    // size in bytes (NOT the actual content)
    HasFiles          bool      `json:"has_files"`         // true if clipboard contains file references
    FileNames         []string  `json:"file_names"`        // if HasFiles, list the filenames
}
```

IMPORTANT: Do NOT capture actual clipboard text content. Only capture metadata (source app, content type, size). Capturing actual text is a privacy violation and would create massive storage. The point is to log "Kim copied something from AutoCAD at 14:30" not "Kim copied this specific text."

### Sending events to server
```go
// Buffer events and send in batch every 10 seconds
// POST /api/events/clipboard
// Headers: X-Agent-PSK, X-Agent-Hostname
// Body: JSON array of ClipboardEvent
```

### Installation as Windows service
```powershell
# deploy/clipagent/install.ps1
param(
    [string]$Server = "https://docvault.internal",
    [string]$PSK,
    [string]$Hostname = $env:COMPUTERNAME
)

$installDir = "C:\Program Files\DocVault"
New-Item -ItemType Directory -Path $installDir -Force

# Copy binary
Copy-Item "docvault-clip.exe" "$installDir\docvault-clip.exe"

# Write config
@{
    server_url = $Server
    psk = $PSK
    hostname = $Hostname
    send_interval_seconds = 10
} | ConvertTo-Json | Set-Content "$installDir\clipagent.json"

# Register as Windows service
New-Service -Name "DocVaultClip" -BinaryPathName "$installDir\docvault-clip.exe" `
    -DisplayName "DocVault Clipboard Monitor" -StartupType Automatic
Start-Service "DocVaultClip"
```

---

## Data Retention Policy

### The problem
endpoint_events grows fast: ~120K rows/day (40 PCs x ~3000 events/day each). That's ~30M rows/year. Without retention, queries slow down and disk fills up.

### Strategy: table partitioning + archival

#### Step 1: Partition endpoint_events by month
```sql
-- In migration 004, create as partitioned table:
CREATE TABLE endpoint_events (
    id           BIGSERIAL,
    hostname     VARCHAR(100) NOT NULL,
    user_id      UUID,
    event_type   VARCHAR(50) NOT NULL,
    file_path    VARCHAR(1000),
    file_name    VARCHAR(500),
    file_extension VARCHAR(20),
    process_name VARCHAR(255),
    drive_type   VARCHAR(20),
    device_info  JSONB,
    detail       JSONB,
    event_time   TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, event_time)
) PARTITION BY RANGE (event_time);

-- Create partitions for current + next 3 months
CREATE TABLE endpoint_events_2026_03 PARTITION OF endpoint_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE endpoint_events_2026_04 PARTITION OF endpoint_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
-- etc.
```

#### Step 2: Auto-create partitions
```go
// internal/retention/cleaner.go
// Run monthly: create next month's partition, archive partitions older than retention period

func (c *Cleaner) CreateNextPartition(ctx context.Context) error {
    next := time.Now().AddDate(0, 2, 0) // 2 months ahead
    partName := fmt.Sprintf("endpoint_events_%s", next.Format("2006_01"))
    startDate := time.Date(next.Year(), next.Month(), 1, 0, 0, 0, 0, time.UTC)
    endDate := startDate.AddDate(0, 1, 0)

    query := fmt.Sprintf(
        `CREATE TABLE IF NOT EXISTS %s PARTITION OF endpoint_events FOR VALUES FROM ('%s') TO ('%s')`,
        partName, startDate.Format("2006-01-02"), endDate.Format("2006-01-02"),
    )
    _, err := c.db.Exec(ctx, query)
    return err
}
```

#### Step 3: Retention rules
```
endpoint_events:  Keep 6 months online, archive older to CSV + compressed storage
audit_logs:       Keep 2 years online (smaller, legally important)
alerts:           Keep 1 year online
```

#### Step 4: Archival (monthly cron)
```bash
# Archive old partitions to compressed CSV
pg_dump -t endpoint_events_2025_09 docvault | gzip > /backup/archive/events_2025_09.sql.gz

# Drop archived partition
psql docvault -c "DROP TABLE endpoint_events_2025_09;"
```

### audit_logs retention
audit_logs is much smaller (~2M rows/year) and has legal significance. Partition by year, keep 2+ years online, archive older. Never delete — only archive.

---

## Test Strategy

### Test file naming convention
```
internal/vault/encryption.go      -> internal/vault/encryption_test.go
internal/audit/repository.go      -> internal/audit/repository_test.go
internal/alert/engine.go          -> internal/alert/engine_test.go
```

### What to test per package

#### vault (CRITICAL — data integrity depends on this)
```go
// encryption_test.go
func TestEncryptDecryptRoundTrip(t *testing.T)         // encrypt -> decrypt -> compare with original
func TestEncryptDecryptLargeFile(t *testing.T)          // 500MB streaming (use io.LimitReader)
func TestDecryptWithWrongKey(t *testing.T)              // must fail with auth error
func TestDecryptTamperedData(t *testing.T)              // GCM auth must catch tampering
func TestEnvelopeEncryption(t *testing.T)               // file key encrypted by master key
func TestHashVerification(t *testing.T)                 // SHA-256 of decrypted matches original

// storage_test.go
func TestStoreAndRetrieve(t *testing.T)                 // write blob, read back, identical
func TestDirectoryStructure(t *testing.T)               // verify /vault/{org}/{year}/{month}/{uuid}/v{n}.enc
func TestConcurrentUploads(t *testing.T)                // 10 goroutines uploading simultaneously
```

#### audit
```go
// middleware_test.go
func TestAuditMiddlewareLogsAllRequests(t *testing.T)   // every request generates log
func TestAuditMiddlewareLogsFailures(t *testing.T)      // 403, 404 also logged
func TestAuditMiddlewareCapturesIP(t *testing.T)

// repository_test.go
func TestUnifiedTimeline(t *testing.T)                  // web + endpoint merged correctly
func TestTimelineOrdering(t *testing.T)                 // sorted by timestamp DESC
func TestFullTextSearch(t *testing.T)                   // search by filename, username
```

#### endpoint
```go
// osquery_test.go
func TestNormalizeFileEvent(t *testing.T)               // raw osquery -> EndpointEvent
func TestDetectDriveType(t *testing.T)                  // C:->local, E:->removable, \\->network
func TestBatchEventProcessing(t *testing.T)             // batch of 100 events
func TestUnknownHostname(t *testing.T)                  // stored with user_id=NULL
```

#### alert
```go
// engine_test.go
func TestUSBCopyAlert(t *testing.T)                     // USB write -> HIGH alert
func TestAfterHoursAlert(t *testing.T)                  // 23:00 access -> MEDIUM
func TestBulkDownloadAlert(t *testing.T)                // 10+ in 5 min -> HIGH
func TestNoFalsePositive(t *testing.T)                  // normal activity -> no alert
func TestAgentOfflineAlert(t *testing.T)                // no heartbeat 10 min -> HIGH
```

#### auth
```go
// jwt_test.go
func TestJWTGenerateAndValidate(t *testing.T)
func TestJWTExpired(t *testing.T)
func TestJWTInvalidSignature(t *testing.T)
func TestRefreshToken(t *testing.T)

// handler_test.go
func TestLoginSuccess(t *testing.T)
func TestLoginWrongPassword(t *testing.T)
func TestLoginRateLimiting(t *testing.T)                // 5 failures -> locked
```

### Test patterns

#### Table-driven tests (ALWAYS use this pattern)
```go
func TestDetectDriveType(t *testing.T) {
    tests := []struct {
        name     string
        path     string
        expected string
    }{
        {"local C drive", "C:\\Users\\Kim\\doc.dwg", "local"},
        {"local D drive", "D:\\Projects\\plan.dwg", "local"},
        {"removable E", "E:\\backup\\file.xlsx", "removable"},
        {"network UNC", "\\\\server\\share\\file.pdf", "network"},
        {"unknown", "X:\\something", "unknown"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := detectDriveType(tt.path)
            if got != tt.expected {
                t.Errorf("detectDriveType(%q) = %q, want %q", tt.path, got, tt.expected)
            }
        })
    }
}
```

#### Integration tests with real DB
```go
// Use testcontainers-go for PostgreSQL in CI, or a local test DB:
func TestMain(m *testing.M) {
    // Setup: create test database, run migrations
    // Teardown: drop test database
    os.Exit(m.Run())
}
```

#### Mock strategy
- Repository interfaces for handler testing (mock the DB layer)
- httptest.NewRecorder for HTTP handler testing
- No external mock libraries — stdlib interfaces are sufficient

```go
// Define interface in handler package (not repository package)
type FileRepository interface {
    GetByID(ctx context.Context, id uuid.UUID) (*File, error)
    Create(ctx context.Context, file *File) error
}

// Real implementation in repository.go
// Mock implementation in handler_test.go
type mockFileRepo struct {
    files map[uuid.UUID]*File
}
func (m *mockFileRepo) GetByID(ctx context.Context, id uuid.UUID) (*File, error) {
    f, ok := m.files[id]
    if !ok { return nil, ErrNotFound }
    return f, nil
}
```

---

## Implementation Order (FOLLOW THIS EXACTLY)

### Phase 1: Foundation (Day 1)
1. `go mod init github.com/docvault/docvault`
2. `internal/config/config.go` — env-based config struct
3. `internal/database/db.go` — pgx connection pool
4. `internal/apierror/error.go` — standardized error responses
5. All migration SQL files in order (001-008), INCLUDING INDEXES
6. `internal/auth/` — JWT + bcrypt + login handler + middleware
7. `internal/web/router.go` — chi router with auth middleware
8. `internal/auth/jwt_test.go` — JWT round-trip tests
9. **Verify**: can login and get JWT token via curl

### Phase 2: File Vault (Day 2)
1. `internal/vault/encryption.go` — AES-256-GCM streaming encrypt/decrypt
2. `internal/vault/encryption_test.go` — round-trip, wrong key, tamper detection
3. `internal/vault/keymanager.go` — envelope encryption with master key
4. `internal/vault/storage.go` — disk read/write with directory structure
5. `internal/vault/repository.go` — files, file_versions CRUD
6. `internal/vault/handler.go` — upload, download endpoints
7. **Verify**: upload a .dwg file, download it back, SHA-256 matches

### Phase 3: Folders & Permissions (Day 3)
1. `internal/folder/` — full CRUD with nested folder support
2. `internal/folder/` — permission checking on all vault operations
3. `internal/vault/handler.go` — add version history, checkout/checkin
4. `internal/user/` — admin CRUD for user management
5. `internal/agent/` — hostname mapping CRUD, agent registry
6. **Verify**: create folder tree, set permissions, verify access denied for unauthorized roles

### Phase 4: Audit System (Day 4)
1. `internal/audit/middleware.go` — auto-log middleware (THE MOST IMPORTANT PATTERN)
2. `internal/audit/repository.go` — insert + search + aggregate queries
3. `internal/audit/handler.go` — user timeline, file timeline, search API
4. `internal/audit/repository_test.go` — unified timeline tests
5. **Verify**: every API call generates an audit log entry automatically

### Phase 5: Endpoint Events (Day 5)
1. `internal/endpoint/osquery.go` — receive + normalize osquery batch events
2. `internal/endpoint/clipboard.go` — receive clipboard events
3. `internal/endpoint/repository.go` — store events with hostname-to-user mapping
4. `internal/endpoint/osquery_test.go` — normalization tests
5. Agent auth middleware for /api/events/* routes
6. Unified timeline query: merge audit_logs + endpoint_events by timestamp
7. **Verify**: simulate osquery POST, see events in user/file timeline

### Phase 6: Alerts (Day 6)
1. `internal/alert/engine.go` — rule evaluation against incoming events
2. `internal/alert/engine_test.go` — all rule types tested
3. `internal/alert/notifier.go` — Slack webhook integration
4. `internal/alert/handler.go` — list, acknowledge, configure rules
5. **Verify**: simulate USB copy event, alert fires and notification sent

### Phase 7: Frontend (Day 7-8)
1. Base layout with navigation (htmx + Go templates)
2. Login page
3. File browser (folder tree + file list)
4. File detail page (versions + access log)
5. Dashboard (stats + alerts + activity feed)
6. User audit timeline page
7. File audit timeline page
8. Admin: user management page (including hostname mapping)
9. Admin: alerts page
10. Admin: agent status page

### Phase 8: Deployment & Agents (Day 9-10)
1. `deploy/osquery/osquery.conf` — copy the config from this CLAUDE.md verbatim
2. `deploy/osquery/enrollment.ps1` — Windows enrollment script
3. `cmd/clipagent/main.go` — Windows clipboard monitoring agent
4. `deploy/clipagent/install.ps1` — clipboard agent installer
5. `internal/retention/cleaner.go` — partition management + archival
6. `deploy/nginx/docvault.conf` — Nginx config with TLS
7. `deploy/systemd/docvault.service` — systemd service file
8. `deploy/backup/backup.sh` — Daily pg_dump + rsync script
9. Integration testing on actual Windows PCs

---

## Critical Architecture Patterns

### 1. Audit Middleware (NEVER skip this)
Every API endpoint MUST be wrapped in audit middleware. Audit logging is a CROSS-CUTTING CONCERN, not per-handler logic. If a new endpoint is added without audit logging, it's a bug.

```go
func AuditMiddleware(auditRepo *audit.Repository) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := auth.UserFromContext(r.Context())
            wrapped := &statusRecorder{ResponseWriter: w, status: 200}
            next.ServeHTTP(wrapped, r)
            auditRepo.Log(r.Context(), audit.Entry{
                UserID:    user.ID,
                Action:    deriveAction(r.Method, r.URL.Path),
                TargetID:  extractTargetID(r),
                IP:        r.RemoteAddr,
                UserAgent: r.UserAgent(),
            })
        })
    }
}
```

### 2. Streaming File I/O (NEVER buffer entire files)
File upload and download MUST stream. Never call ioutil.ReadAll or load entire file into memory.

```go
// CORRECT: streaming encrypt
func EncryptStream(key, nonce []byte, src io.Reader, dst io.Writer) error {
    block, _ := aes.NewCipher(key)
    stream := cipher.NewCTR(block, nonce)
    writer := &cipher.StreamWriter{S: stream, W: dst}
    _, err := io.Copy(writer, src)
    return err
}

// WRONG: loading entire file
func EncryptBad(key []byte, data []byte) []byte { ... }
```

### 3. Envelope Encryption (NEVER store raw keys)
File encryption keys are themselves encrypted by the master key before storage.

```
Master Key (in config file, chmod 600)
  |-- encrypts -> File Key A (stored in DB as encrypted_key)
  |     |-- encrypts -> File A content (stored on disk)
  |-- encrypts -> File Key B
        |-- encrypts -> File B content
```

### 4. Unified Timeline Query
The unified user/file timeline merges web audit_logs and endpoint_events:

```sql
SELECT * FROM (
    SELECT created_at as ts, 'WEB' as source, action as event_type,
           target_name as file_name, detail, ip_address
    FROM audit_logs WHERE user_id = $1
    UNION ALL
    SELECT event_time as ts, 'ENDPOINT' as source, event_type,
           file_name, detail, NULL as ip_address
    FROM endpoint_events WHERE user_id = $1
) combined
ORDER BY ts DESC
LIMIT $2 OFFSET $3;
```

### 5. Soft Delete (NEVER hard delete files)
Files are never physically deleted. Soft delete sets is_deleted=true. Encrypted blobs remain on disk. This ensures audit trail integrity — you can always prove a file existed and who accessed it.

---

## Coding Style

### Go Conventions
- Use `context.Context` as first parameter for all repository methods
- Return `(result, error)` tuples, never panic
- Use structured logging (slog package)
- Table-driven tests
- No global state, all dependencies injected via constructor
- Define interfaces at the consumer site (handler defines the repo interface it needs)

### Error Handling
```go
// CORRECT: wrap errors with context
if err != nil {
    return fmt.Errorf("encrypt file %s: %w", fileID, err)
}

// WRONG: bare error return
if err != nil {
    return err
}
```

### Database Queries
- Use pgx directly with parameterized queries ($1, $2)
- No ORM
- All queries in repository files, never in handlers
- Use transactions for multi-step operations (upload file + create version + log audit)

### HTTP Handler Pattern
```go
// Every handler follows this pattern:
func (h *Handler) DoSomething(w http.ResponseWriter, r *http.Request) {
    // 1. Parse input
    // 2. Validate
    // 3. Check permissions
    // 4. Call repository / service
    // 5. Return JSON response or error
    // Audit logging happens AUTOMATICALLY via middleware — don't add it here
}
```

---

## Configuration (Environment Variables)
```
DOCVAULT_DB_URL=postgres://user:pass@localhost:5432/docvault
DOCVAULT_MASTER_KEY=hex-encoded-32-byte-key
DOCVAULT_VAULT_PATH=/vault
DOCVAULT_JWT_SECRET=jwt-signing-secret
DOCVAULT_JWT_ACCESS_TTL=15m
DOCVAULT_JWT_REFRESH_TTL=168h
DOCVAULT_LISTEN_ADDR=:8080
DOCVAULT_OSQUERY_PSK=pre-shared-key-for-osquery-agents
DOCVAULT_CLIP_PSK=pre-shared-key-for-clipboard-agents
DOCVAULT_SLACK_WEBHOOK=https://hooks.slack.com/services/xxx
DOCVAULT_ALERT_EMAIL=admin@company.kr
DOCVAULT_MAX_UPLOAD_SIZE=1073741824
DOCVAULT_RETENTION_EVENTS_MONTHS=6
DOCVAULT_RETENTION_AUDIT_YEARS=2
DOCVAULT_BACKUP_PATH=/backup
```

---

## HOOKS: Direction Guards (CHECK BEFORE EVERY PHASE)

### Before writing any code, verify:
- [ ] Am I following the Implementation Order above?
- [ ] Does this handler have audit middleware?
- [ ] Am I streaming file I/O (not buffering)?
- [ ] Am I using parameterized SQL (not string concatenation)?
- [ ] Am I returning standardized APIError responses (not plain text)?
- [ ] Am I wrapping errors with context?
- [ ] Have I written tests for the critical path?
- [ ] Have I added necessary DB indexes?

### Before moving to next phase, verify:
- [ ] All tests pass (`go test ./...`)
- [ ] No race conditions (`go test -race ./...`)
- [ ] API endpoints return correct status codes using APIError
- [ ] Audit logs are generated for every action
- [ ] Error cases are handled (unauthorized, not found, validation failure)
- [ ] No TODO or placeholder code left

### Before deployment, verify:
- [ ] Master key is not in source code
- [ ] All passwords are bcrypt hashed
- [ ] JWT tokens expire properly
- [ ] Nginx TLS is configured correctly
- [ ] Backup script runs successfully
- [ ] osquery agents connect and send events
- [ ] Clipboard agents connect and send events
- [ ] Hostname-to-user mappings are configured for all 40 PCs
- [ ] Alert notifications fire correctly
- [ ] Data retention cron is scheduled
- [ ] All DB indexes are created
- [ ] agent_registry shows all agents as active