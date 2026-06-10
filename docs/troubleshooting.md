# Troubleshooting log

Issues hit and the fix for each. Newest at the bottom.

Format for each entry: **Symptom** · **Cause** · **Fix** · **Commit** · (optional **Pattern**).

When you fix a non-trivial issue, append an entry below. The Stop hook in `.claude/settings.json` reminds about this after any recent commit.

---

## How to add a new entry

```markdown
## <short title>

- **Symptom**: <literal error message or observable behavior>
- **Cause**: <verified explanation> (or `Hypothesis: ... Verified by: ...`)
- **Fix**: <files/functions changed, mechanism>
- **Commit**: <hash from `git rev-parse HEAD` AFTER committing>
- **Pattern**: <one-line recurring lesson — optional>
```

Concrete only. Numbers, file paths, commit hashes. No "lessons learned" essays.

---

## File encryption used AES-CTR without MAC

- **Symptom**: Files written by `internal/vault/encryption.go` had no integrity protection. A bit flip in the on-disk ciphertext decrypted silently to corrupted plaintext. CTR's malleability also permits targeted plaintext bit-flips when the attacker knows a byte position.
- **Cause**: `EncryptStream`/`DecryptStream` used `cipher.NewCTR` + `cipher.StreamWriter`. CTR provides confidentiality only, no authentication. README and ADR-008 claimed AES-256-GCM, but GCM was only applied to the file *keys* in `keymanager.go` (envelope); the file *body* was CTR.
- **Fix**: Rewrote `encryption.go` to use chunked AES-256-GCM. 64 KiB plaintext per chunk. Per-chunk nonce = `base_nonce[:8] || chunk_index (3 bytes BE) || final_flag (1 byte)`. Final flag defeats truncation; chunk index defeats reorder. Added `TestTamperDetection` (4 mutation sites), `TestTruncationDetection`, `TestChunkReorderDetection`, `TestWrongNonceFails`, `TestShortNonceRejected` to `encryption_test.go`. Same signature `EncryptStream(key, baseNonce, src, dst)`, so `storage.go` callers unchanged. Documented in `docs/DECISIONS.md` ADR-008 (rewritten) and `docs/LIMITATIONS.md` L-SEC-1 (marked resolved).
- **Commit**: 22d8bd7
- **Pattern**: Streaming-friendly cipher modes (CTR, stream cipher) without an explicit MAC are unsafe for data at rest when integrity matters. Use AEAD chunked (GCM per chunk with index in the nonce). Audit README/ADR crypto claims against the actual code.

## Hash chain trigger had concurrent-INSERT race

- **Symptom**: `compute_audit_hash()` and `compute_endpoint_hash()` triggers (from migration `008_log_integrity`) read `SELECT row_hash FROM <table> ORDER BY id DESC LIMIT 1` to chain. Under concurrent INSERTs in the same table, two transactions could read the same `prev_hash`, producing a forked chain. `VerifyHashChain` walked one branch and missed the divergence.
- **Cause**: No serialization within the trigger. PostgreSQL doesn't serialize trigger logic across concurrent rows; both INSERTs run in parallel transactions, and there is no unique index on `prev_hash`/`row_hash` to force conflict at commit.
- **Fix**: Migration `013_audit_advisory_lock` adds `PERFORM pg_advisory_xact_lock(hashtext('audit_logs_chain'))` (and `endpoint_events_chain`) at the top of each trigger function via `CREATE OR REPLACE FUNCTION`. Transaction-scoped — released automatically at COMMIT/ROLLBACK. Trade-off documented in `docs/LIMITATIONS.md` L-SEC-3 (marked resolved): hash chain INSERTs become serialized per table; at the documented ~50K events/day target this is well under the bottleneck.
- **Commit**: 22d8bd7
- **Pattern**: A trigger that derives state from "the latest row" must explicitly serialize concurrent triggers. `pg_advisory_xact_lock(hashtext(key))` is the lightest tool — no schema change, no SERIALIZABLE isolation cost.
<!-- skipped: 810b55b Fill commit hashes in troubleshooting entries [no-log] -->
<!-- skipped: 524ae05 Backfill 3 log entries from git history [no-log] -->

## Access-control and export hardening after full repository review

- **Symptom**:

```text
Full repository review found admin web routes protected only by login middleware, file APIs missing folder permission checks, agent endpoints accepting unauthenticated traffic when DOCVAULT_OSQUERY_PSK was empty, and CSV exports built by ad hoc string concatenation.
```

- **Cause**: Verified in the inspected code before commit `e0d498d`: `internal/web/router.go` registered `/admin/...` routes inside `auth.AuthMiddleware` without `auth.RequireRole(user.RoleAdmin)`; `internal/vault/handler.go` did not receive a `folder.Repository` and could not enforce folder permissions; `internal/endpoint/handler.go` checked PSK only inside `if h.psk != ""`; `internal/audit/handler.go` and `internal/web/pages.go` wrote CSV rows manually instead of using `encoding/csv`.
- **Fix**: Commit `e0d498d` adds admin-only route grouping, folder permission checks for vault/page/form paths, inherited folder access with creator admin ownership, required `DOCVAULT_OSQUERY_PSK`, fail-closed agent PSK checks, JWT token-type validation, Secure auth/CSRF cookies, `encoding/csv` exports with spreadsheet formula escaping, and regression tests in `internal/audit/csv_test.go`, `internal/endpoint/handler_test.go`, and `internal/web/csv_test.go`.
- **Commit**: e0d498d
- **Pattern**: Access control should sit at route and repository/service boundaries, not only in templates or navigation.

## Protected web actions were not all covered by audit logging

- **Symptom**:

```text
`internal/web/router.go` attached `audit.Middleware` to the protected JSON API group only. Protected HTML form POST routes such as `/files/upload`, `/folders/create`, `/admin/users/create`, `/admin/monitoring/...`, `/admin/tracking/...`, and `/account/2fa/...` were in the cookie-authenticated web group without audit middleware. Public login/logout routes were also outside the protected audit middleware path.
```

- **Cause**: `audit.Middleware` derived actions for JSON API paths and required `auth.UserFromContext`, so public login routes could not be logged by that middleware. The middleware's `statusRecorder` also did not preserve `http.Flusher`, which could break SSE handlers wrapped by the audit middleware.
- **Fix**: Commit `6df4c71` attaches `audit.Middleware` to the protected web group, adds action mappings for web form POSTs, preserves `http.Flusher`, and adds route/action tests. Commit `9f81995` adds explicit audit logging for API login, web login, 2FA login completion/failure, and logout after validating the session token.
- **Commit**: 6df4c71, 9f81995
- **Pattern**: Audit middleware covers authenticated request groups well, but authentication boundary events need explicit logging because the user context is created during the handler.

## JSON login endpoint bypassed 2FA and had no rate limit

- **Symptom**:

```text
POST /api/auth/login validated the password and immediately returned full access + refresh tokens — it never checked totp_enabled, while the web /login flow did enforce TOTP. The same API endpoint also had no brute-force throttle (the login rate limiter existed only in the web LoginSubmit path).
```

- **Cause**: Verified in `internal/auth/handler.go`: `Login` ran `user.CheckPassword` then `GenerateTokenPair` with no TOTP branch; `findUserByUsername` did not even select `totp_secret`/`totp_enabled`. The `LoginRateLimiter` was instantiated only in `internal/web/pages.go` for the cookie login.
- **Fix**: Commit `5e6b325`. `Login` now selects `totp_secret`/`totp_enabled` and, when 2FA is enabled, requires a `totp_code` validated via `ValidateTOTP` (returns `401 {"requires_2fa":true}` when absent). Added `LoginRateLimitMiddleware` to `internal/web/ratelimit.go` (records 401/403 as failures, clears on 2xx) and wired it onto `/api/auth/login` in `internal/web/router.go`. `go build` / `vet` / `test ./...` all pass.
- **Commit**: 5e6b325
- **Pattern**: Parallel API and web auth paths must share the same factors and throttling. Verify the alternate endpoint, not just the UI flow.

## osquery agent could not talk to the server (enroll/auth protocol mismatch)

- **Symptom**:

```text
deploy/osquery/osquery.flags + osquery.conf use the standard osquery TLS plugin (enroll_secret -> node_key), but the server's /api/enroll returned {hostname, username} with no node_key, and /api/events/osquery authenticated via the X-Osquery-PSK header — which osquery does not send. A stock osquery node would fail to enroll and its config/log requests would be rejected.
```

- **Cause**: Verified in the code before commit `7726828`: `Enroll` in `internal/endpoint/handler.go` issued no `node_key`; `ReceiveOsquery` gated on the `X-Osquery-PSK` header. osquery instead exchanges a shared `enroll_secret` for a `node_key` it carries on every subsequent config/log request.
- **Fix**: Commit `7726828`. Implemented the real osquery TLS protocol in `internal/endpoint/osquery_tls.go`: `/api/osquery/enroll` validates the enroll secret (the shared `DOCVAULT_OSQUERY_PSK`, constant-time) and issues a `node_key` stored on `endpoint_agents` (migration `014`); `/api/osquery/config` and `/api/osquery/log` authenticate by `node_key`. Extracted `processOsqueryBatch` from `ReceiveOsquery` so the TLS logger path reuses the existing normalize/store/alert pipeline. Pointed `osquery.flags`/`osquery.conf` at `/api/osquery/enroll|config|log`. NOTE: not yet verified against a live osquery daemon.
- **Commit**: 7726828
- **Pattern**: When integrating a third-party agent, implement its actual wire protocol — a custom header scheme silently breaks the stock client.

## Clipboard agent dropped events on any network blip

- **Symptom**:

```text
cmd/clipagent/agent.go sent each event with `go sendEvent(...)` fire-and-forget; on any send error it logged and discarded the event. Enrollment happened once at startup, so a server restart or IP change silently stopped attribution.
```

- **Cause**: No retry, no queue, no re-enroll. For a remote-over-internet agent, transient outages are normal and meant permanent data loss exactly during the moments that matter.
- **Fix**: Commit `7726828`. Rewrote the agent around a bounded in-memory queue drained by a sender goroutine with exponential backoff (4 attempts), periodic re-enroll every 5 minutes, and a best-effort flush on shutdown. Verified cross-builds for `windows/amd64` and `darwin/arm64`.
- **Commit**: 7726828
- **Pattern**: A monitoring agent over an unreliable link needs at least a bounded retry queue; fire-and-forget loses the very events an incident depends on.

## No one-command deploy; example secrets accepted; server started against empty schema

- **Symptom**:

```text
docker-compose.yml ran only `serve` against an empty database (no migration step), shipped the literal example master key / JWT secret, and the Dockerfile pinned Go 1.22 while go.mod declares go 1.26.1. seed created admin/admin1234! and logged the password.
```

- **Cause**: Verified — the old compose had no migrate service; `.env.example` and `docker-compose.yml` carried the example master key `0123…cdef`; `cmd/server/seed.go` hashed the constant `admin1234!` and logged it.
- **Fix**: Commit `5e6b325`. `docker-compose.prod.yml` orchestrates `db → migrate → seed → server → caddy` (migrations auto-apply from the embedded FS). `config.Load` rejects known example/weak secrets and enforces JWT/PSK minimum length. `scripts/gen-env.sh` generates strong secrets into a `chmod 600 .env`; `.env.prod.example` documents the dedicated-server and friend's-PC all-in-one scenarios. `deploy/caddy/Caddyfile` provides automatic HTTPS. `seed.go` uses `DOCVAULT_ADMIN_PASSWORD` or a random password and never logs it. `Dockerfile` → `golang:1.26-alpine`. NOTE: `docker compose build/up` was not run in this environment — Go build/vet/test verified only; container build to be confirmed on the server.
- **Commit**: 5e6b325
- **Pattern**: Bundle migrations into the deploy orchestration and refuse example secrets at startup, so a known-key deploy fails fast instead of silently running insecure.
<!-- skipped: 4b1098a Log API 2FA enforcement and production deploy stack [no-log] -->

## Backups were unencrypted and held password hashes / TOTP secrets

- **Symptom**: deploy/backup/backup.sh wrote a plain pg_dump and an unencrypted vault tar to /opt/docvault/backups — including bcrypt password hashes and plaintext TOTP secrets — kept 30 days on the same host.
- **Cause**: No encryption step, and pg_dump had no documented auth handling.
- **Fix**: Commit 4cc9337d417acd68cf5181aec9027e6f614b5eda. backup.sh now pipes pg_dump and the vault tar through openssl enc -aes-256-cbc -pbkdf2, keyed by a separate /opt/docvault/backup.key; it fails closed if the key is missing, documents restore and off-host copy, and uses set -euo pipefail.
- **Commit**: 4cc9337d417acd68cf5181aec9027e6f614b5eda
- **Pattern**: A backup that contains secrets must be encrypted at rest with a key kept off the backed-up host.
<!-- skipped: 262d1ce Log backup encryption [no-log] -->
<!-- skipped: 30abd7e Remove hardcoded dev secrets from compose and .env.example [no-log] -->

## Login rate limit never tripped (keyed on IP:port instead of IP)

- **Symptom**: After bringing the stack up with docker compose, 7 consecutive wrong logins to /api/auth/login all returned 401 — the 5-attempt lockout never fired (no 429).
- **Cause**: web.ExtractIP returned r.RemoteAddr unchanged, which is host:port. Each connection uses a fresh ephemeral source port, so every attempt was counted as a different client and the per-IP counter never reached the threshold.
- **Fix**: Commit 720e3c4368d14046603a70214e77a0d065168f54. ExtractIP now strips the port via net.SplitHostPort (and takes the first X-Forwarded-For hop). After rebuild, 7 wrong logins returned 401 x5 then 429 x2 as expected.
- **Commit**: 720e3c4368d14046603a70214e77a0d065168f54
- **Pattern**: An IP-keyed limiter must key on the IP only; RemoteAddr includes a per-connection port that silently defeats it. Verify limiters by hammering the running endpoint, not just unit tests.
<!-- skipped: e8334f9 Log rate-limit IP-key fix [no-log] -->

## No automated Windows verification for the agent

- **Symptom**: clipagent targets Windows but CI built only on ubuntu; Windows build and service registration were never verified automatically.
- **Cause**: .github/workflows/ci.yml had a single ubuntu job, pinned to Go 1.22 (go.mod wants 1.26).
- **Fix**: Commit 308a01e3dcbd89f0c0bc3ca195ac48aee0856be8. Added a windows-latest CI job (build server+agent, vet, unit tests, and a service install/uninstall smoke via docvault-clip.exe). Bumped CI Go to 1.26. Added docs/WINDOWS_VM_TEST.md for manual clipboard verification in a UTM Windows-ARM VM, and landing/guide.html (bilingual KO/EN setup tutorial).
- **Commit**: 308a01e3dcbd89f0c0bc3ca195ac48aee0856be8
- **Pattern**: cross-platform agents need a CI job per target OS; GUI-only behavior (clipboard) still needs a VM or real device.

## CI was red: clipagent did not build on Linux

- **Symptom**: every GitHub Actions run failed at go build ./... with "cmd/clipagent/agent.go:59:14: undefined: getUsername". Local macOS builds passed, hiding it.
- **Cause**: cmd/clipagent defined getUsername/newClipboardMonitor and platformMain only under windows and darwin build tags; on linux (CI ubuntu) none existed.
- **Fix**: Commit 39b6cfdf3288e417849e4cc99dec355cbf268b04. Added clipboard_other.go and service_other.go (build tag !windows && !darwin) with a no-op clipboard monitor. Verified GOOS=linux/windows/darwin go build ./cmd/clipagent and GOOS=linux go build ./...
- **Commit**: 39b6cfdf3288e417849e4cc99dec355cbf268b04
- **Pattern**: platform _windows/_darwin files need a fallback for every OS CI builds on, or go build ./... breaks there. Watch CI status, not just local builds.
