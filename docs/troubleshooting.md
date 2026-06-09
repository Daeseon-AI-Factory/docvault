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

## No one-command deploy; example secrets accepted; server started against empty schema

- **Symptom**:

```text
docker-compose.yml ran only `serve` against an empty database (no migration step), shipped the literal example master key / JWT secret, and the Dockerfile pinned Go 1.22 while go.mod declares go 1.26.1. seed created admin/admin1234! and logged the password.
```

- **Cause**: Verified — the old compose had no migrate service; `.env.example` and `docker-compose.yml` carried the example master key `0123…cdef`; `cmd/server/seed.go` hashed the constant `admin1234!` and logged it.
- **Fix**: Commit `5e6b325`. `docker-compose.prod.yml` orchestrates `db → migrate → seed → server → caddy` (migrations auto-apply from the embedded FS). `config.Load` rejects known example/weak secrets and enforces JWT/PSK minimum length. `scripts/gen-env.sh` generates strong secrets into a `chmod 600 .env`; `.env.prod.example` documents the dedicated-server and friend's-PC all-in-one scenarios. `deploy/caddy/Caddyfile` provides automatic HTTPS. `seed.go` uses `DOCVAULT_ADMIN_PASSWORD` or a random password and never logs it. `Dockerfile` → `golang:1.26-alpine`. NOTE: `docker compose build/up` was not run in this environment — Go build/vet/test verified only; container build to be confirmed on the server.
- **Commit**: 5e6b325
- **Pattern**: Bundle migrations into the deploy orchestration and refuse example secrets at startup, so a known-key deploy fails fast instead of silently running insecure.
