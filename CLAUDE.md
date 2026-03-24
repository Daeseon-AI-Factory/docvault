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
- Near-zero performance impact on employee PCs
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
- **Frontend**: htmx + Go html/template
- **Endpoint Agent**: osquery 5.x (pre-built, we only configure)
- **Clipboard Agent**: Custom Go binary using golang.org/x/sys/windows
- **Reverse Proxy**: Nginx
- **Migration**: golang-migrate

## Project Structure
```
docvault/
├── CLAUDE.md                    # This file
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
│   │       ├── 003_audit_logs.up.sql
│   │       ├── 004_endpoint_events.up.sql
│   │       ├── 005_alerts.up.sql
│   │       └── 006_encryption_keys.up.sql
│   ├── auth/
│   │   ├── jwt.go               # JWT generation, validation, refresh
│   │   ├── middleware.go         # Auth middleware (extract user from JWT)
│   │   └── handler.go           # Login, logout, refresh endpoints
│   ├── user/
│   │   ├── model.go             # User struct, roles enum
│   │   ├── repository.go        # DB queries (CRUD)
│   │   └── handler.go           # Admin user management endpoints
│   ├── vault/
│   │   ├── encryption.go        # AES-256-GCM encrypt/decrypt streaming
│   │   ├── storage.go           # Disk storage (write/read encrypted blobs)
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
│   │   ├── middleware.go         # Auto-logging middleware (cross-cutting)
│   │   ├── repository.go        # DB queries (insert, search, aggregate)
│   │   └── handler.go           # User audit view, file audit view, search, dashboard stats
│   ├── endpoint/
│   │   ├── model.go             # EndpointEvent struct, event type enum
│   │   ├── osquery.go           # osquery event receiver, normalizer
│   │   ├── clipboard.go         # Clipboard event receiver
│   │   ├── repository.go        # DB queries for endpoint events
│   │   └── handler.go           # POST /api/events/osquery, /api/events/clipboard
│   ├── alert/
│   │   ├── model.go             # Alert, AlertRule structs
│   │   ├── engine.go            # Rule evaluation engine
│   │   ├── notifier.go          # Slack webhook, email notifications
│   │   ├── repository.go        # DB queries
│   │   └── handler.go           # Alert list, acknowledge endpoints
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
│   │   ├── osquery.conf         # osquery configuration (monitored paths, query schedule)
│   │   └── osquery.flags        # osquery daemon flags (TLS endpoint, enroll secret)
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

## Implementation Order (FOLLOW THIS EXACTLY)

### Phase 1: Foundation (Day 1)
1. `go mod init github.com/docvault/docvault`
2. `internal/config/config.go` — env-based config struct
3. `internal/database/db.go` — pgx connection pool
4. All migration SQL files in order (001-006)
5. `internal/auth/` — JWT + bcrypt + login handler + middleware
6. `internal/web/router.go` — chi router with auth middleware
7. **Verify**: can login and get JWT token via curl

### Phase 2: File Vault (Day 2)
1. `internal/vault/encryption.go` — AES-256-GCM streaming encrypt/decrypt
2. `internal/vault/keymanager.go` — envelope encryption with master key
3. `internal/vault/storage.go` — disk read/write with directory structure
4. `internal/vault/repository.go` — files, file_versions CRUD
5. `internal/vault/handler.go` — upload, download endpoints
6. **Verify**: upload a .dwg file, download it back, SHA-256 matches

### Phase 3: Folders & Permissions (Day 3)
1. `internal/folder/` — full CRUD with nested folder support
2. `internal/folder/` — permission checking on all vault operations
3. `internal/vault/handler.go` — add version history, checkout/checkin
4. `internal/user/` — admin CRUD for user management
5. **Verify**: create folder tree, set permissions, verify access denied for unauthorized roles

### Phase 4: Audit System (Day 4)
1. `internal/audit/middleware.go` — auto-log middleware (THE MOST IMPORTANT PATTERN)
2. `internal/audit/repository.go` — insert + search + aggregate queries
3. `internal/audit/handler.go` — user timeline, file timeline, search API
4. **Verify**: every API call generates an audit log entry automatically

### Phase 5: Endpoint Events (Day 5)
1. `internal/endpoint/osquery.go` — receive + normalize osquery batch events
2. `internal/endpoint/clipboard.go` — receive clipboard events
3. `internal/endpoint/repository.go` — store events with hostname-to-user mapping
4. Unified timeline query: merge audit_logs + endpoint_events by timestamp
5. **Verify**: simulate osquery POST, see events in user/file timeline

### Phase 6: Alerts (Day 6)
1. `internal/alert/engine.go` — rule evaluation against incoming events
2. `internal/alert/notifier.go` — Slack webhook integration
3. `internal/alert/handler.go` — list, acknowledge, configure rules
4. **Verify**: simulate USB copy event, alert fires and notification sent

### Phase 7: Frontend (Day 7-8)
1. Base layout with navigation (htmx + Go templates)
2. Login page
3. File browser (folder tree + file list)
4. File detail page (versions + access log)
5. Dashboard (stats + alerts + activity feed)
6. User audit timeline page
7. File audit timeline page
8. Admin: user management page
9. Admin: alerts page
10. Admin: agent status page

### Phase 8: Deployment & Agents (Day 9-10)
1. osquery.conf with monitored paths and query schedule
2. Clipboard agent (cmd/clipagent) — Windows clipboard monitoring
3. Nginx config with TLS
4. systemd service file
5. Backup script (pg_dump + rsync)
6. Integration testing on actual Windows PCs

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
  └── encrypts → File Key A (stored in DB as encrypted_key)
        └── encrypts → File A content (stored on disk)
  └── encrypts → File Key B
        └── encrypts → File B content
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

## Coding Style

### Go Conventions
- Use `context.Context` as first parameter for all repository methods
- Return `(result, error)` tuples, never panic
- Use structured logging (slog package)
- Table-driven tests
- No global state, all dependencies injected via constructor

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

## Configuration (Environment Variables)
```
DOCVAULT_DB_URL=postgres://user:pass@localhost:5432/docvault
DOCVAULT_MASTER_KEY=hex-encoded-32-byte-key
DOCVAULT_VAULT_PATH=/vault
DOCVAULT_JWT_SECRET=jwt-signing-secret
DOCVAULT_LISTEN_ADDR=:8080
DOCVAULT_OSQUERY_PSK=pre-shared-key-for-osquery-agents
DOCVAULT_SLACK_WEBHOOK=https://hooks.slack.com/services/xxx
DOCVAULT_ALERT_EMAIL=admin@company.kr
```

## HOOKS: Direction Guards (CHECK BEFORE EVERY PHASE)

### Before writing any code, verify:
- [ ] Am I following the Implementation Order above?
- [ ] Does this handler have audit middleware?
- [ ] Am I streaming file I/O (not buffering)?
- [ ] Am I using parameterized SQL (not string concatenation)?
- [ ] Am I returning proper HTTP error codes?
- [ ] Am I wrapping errors with context?

### Before moving to next phase, verify:
- [ ] All tests pass (`go test ./...`)
- [ ] No race conditions (`go test -race ./...`)
- [ ] API endpoints return correct status codes
- [ ] Audit logs are generated for every action
- [ ] Error cases are handled (unauthorized, not found, validation failure)

### Before deployment, verify:
- [ ] Master key is not in source code
- [ ] All passwords are bcrypt hashed
- [ ] JWT tokens expire properly
- [ ] Nginx TLS is configured correctly
- [ ] Backup script runs successfully
- [ ] osquery agents connect and send events
- [ ] Alert notifications fire correctly
