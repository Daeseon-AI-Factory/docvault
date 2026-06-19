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

## Backup encryption still left a plaintext vault staging copy

- **Symptom**: although `db_*.dump.enc` and `vault_*.tar.gz.enc` were encrypted, the script also kept `/opt/docvault/backups/vault_latest/` as a plaintext rsync staging copy.
- **Cause**: the archive was built from a local incremental staging directory to make tar creation convenient. That defeated the "encrypted at rest" claim for vault files.
- **Fix**: `deploy/backup/backup.sh` now streams `tar` directly from the vault directory into `openssl enc` and removes any old `vault_latest` staging directory.
- **Pattern**: backup encryption must include temporary/staging paths, not just final artifact filenames. If a staging copy remains, the backup is still plaintext at rest.

## TOTP secrets were stored plaintext in `users.totp_secret`

- **Symptom**: enabling 2FA wrote the base32 TOTP seed directly into `users.totp_secret`; a database leak would let an attacker generate valid second-factor codes.
- **Cause**: the TOTP implementation validated the raw seed directly from the DB and had no small-secret encryption helper.
- **Fix**: Added `auth.SecretProtector`, using AES-256-GCM with `DOCVAULT_MASTER_KEY` and an `enc:v1:` prefix. Migration `016_totp_secret_encryption` changes `users.totp_secret` to `TEXT` because protected values exceed the old plaintext-sized `VARCHAR(64)`. Web 2FA setup stores protected secrets, and API/web login + disable paths decrypt protected values before validation. Legacy plaintext values remain readable until users rotate 2FA.
- **Pattern**: encrypt small auth seeds with the application master key, but keep prefix-based backward compatibility so existing users are not locked out during rollout.

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
<!-- skipped: db94515 Log clipagent Linux build fix [no-log] -->
<!-- skipped: d7b71d1 Link the bilingual setup guide from the landing page [no-log] -->
<!-- skipped: a29a69a Add in-app sidebar link to the bilingual setup guide [no-log] -->

## Added an optional AI summary layer on top of the rule engine

- **Symptom**: the alert engine flags individual events but there was no natural-language "what happened" summary for an admin.
- **Cause**: feature gap — rule-based alerts only (by design), no aggregated briefing.
- **Fix**: Commit 0cf0a5037ad91f60bc8a9c175419448a54311603. internal/insight builds a compact DB digest (event counts, recent notable events, unacked alerts) and calls the Anthropic Messages API via raw net/http to produce a short Korean briefing. Admin-only GET /api/insight/summary, disabled unless DOCVAULT_ANTHROPIC_API_KEY is set; model via DOCVAULT_AI_MODEL.
- **Commit**: 0cf0a5037ad91f60bc8a9c175419448a54311603
- **Pattern**: keep paid AI calls optional + admin-gated, and send a pre-aggregated digest rather than raw rows to bound token cost.
<!-- skipped: f65c361 Log AI summary bot [no-log] -->

## AI bot/agent on Gemini: retired model + thinking-token leak

- **Symptom**: `GET /api/insight/summary` returned 502; container log: `gemini 404: This model models/gemini-2.0-flash is no longer available`. After changing the model the summary text was the model's reasoning scratchpad, truncated (e.g. `". Let's do "위험 수준: 보통"...`).
- **Cause**: (1) `gemini-2.0-flash` was retired by Google. (2) `gemini-flash-latest` is a thinking model; default thinking consumed the 1024 `maxOutputTokens`, so only the scratchpad came back.
- **Fix**: Commit cb2e545b4ec0fa89a61a7be5fa51bd169ca20e5a. Default Gemini model = `gemini-flash-latest` (alias auto-tracks the current flash, won't get retired); set `generationConfig.thinkingConfig.thinkingBudget=0` to disable thinking. Verified: real Korean briefing grounded in 354 events.
- **Commit**: cb2e545b4ec0fa89a61a7be5fa51bd169ca20e5a
- **Pattern**: pin Gemini to the `*-latest` alias, and set `thinkingBudget=0` for brief/JSON tasks or the answer gets eaten by thinking tokens.

## Root disk hit 100% (build failed) — BuildKit cache on the boot volume

- **Symptom**: `docker build` failed with `no space left on device` (`mkdir /tmp/go-build...`); `df /` showed the 9.8G boot disk 100% used, 0 free. SSH also started timing out.
- **Cause**: repeated on-box docvault image builds left BuildKit cache under `/var/lib/docker/buildkit` (on the root volume) — separate from the daemon data-root (`/data/docker`, 45G free). Moving data-root does NOT move the BuildKit cache.
- **Fix**: `docker builder prune -af` reclaimed ~1.2GB → root back to ~58%. Run a prune after each on-box build (ops action, not in a commit).
- **Pattern**: on a small boot disk, prune builder cache after builds — or build off-box and `docker load` the image so nothing accumulates on root.

## SSH locked out after ISP changed the operator's IP

- **Symptom**: `ssh root@<box>` timed out repeatedly while HTTPS (443) kept working.
- **Cause**: the ACG inbound rule for port 22 was pinned to one residential IP; the ISP reassigned it. 443 is open to 0.0.0.0/0 so the web stayed up while SSH (restricted) was dropped.
- **Fix**: re-add the current public IP to ACG 22 via the NCP signed API before each SSH session. Verified by reconnecting.
- **Pattern**: pinning SSH to a dynamic residential IP is fragile; use a stable jump IP / VPN, or accept re-adding the IP. A web-works-but-SSH-times-out split points at a firewall rule, not the host.
<!-- skipped: 004859f Harden agent against prompt injection in tool data [no-log] -->

## Agent status showed event activity, not agent liveness

- **Symptom**: the Agent Status page could mark a healthy installed PC offline if it had not produced an endpoint event recently, and a newly installed agent with no captured clipboard/file activity had weak visibility after enrollment.
- **Cause**: `endpoint_agents.last_checkin` existed, but the UI's primary status table was derived from `endpoint_events.MAX(event_time)`. Successful clipboard/osquery event posts and osquery TLS config/log polling did not consistently update `last_checkin`, so "last event" and "last report" were conflated.
- **Fix**: Added `endpoint.Repository.TouchAgent` and call it from clipboard event ingest, osquery batch ingest, osquery node-key auth, and the clipboard agent's explicit `/api/heartbeat`. The admin page now uses `endpoint_agents.last_checkin` for "보고중/오프라인" and shows an offline warning when an agent has not reported for 10 minutes. The clipboard agent sends heartbeat every 60 seconds, so a newly installed but idle PC still appears as reporting.
- **Pattern**: monitoring agent health is a heartbeat/check-in concept, not an event-volume concept. Quiet but connected agents should still look alive.

## Host assignment was source-row scoped instead of hostname scoped

- **Symptom**: a PC can have both `clipboard` and `osquery` rows for the same hostname. Assigning one row to an employee could leave the other row unassigned, and hostname-to-user lookup could hit the wrong/null row.
- **Cause**: `AssignAgent` updated one `endpoint_agents.id`, while `lookupUserByHostname` queried active rows by hostname without requiring a non-null user or deterministic latest row.
- **Fix**: hostname lookup now chooses the latest active row with a non-null `user_id`. Web host assignment updates every `endpoint_agents` row for that hostname, and AI `assign_host` does the same while storing per-row previous state for rollback. Endpoint events are immutable hash-chained records, so assignment affects future attribution; existing events remain queryable by hostname.
- **Pattern**: the operator thinks in "PC/hostname", not "source row". Keep assignment semantics hostname-wide whenever downstream event attribution is hostname-wide.

## AI action tools could run from tool-output prompt injection

- **Symptom**: the AI assistant had read tools and mutating tools in the same tool-use loop. Attacker-controlled fields such as file names, process names, or window titles could enter tool output and influence a later model turn into calling `create_user`, `assign_host`, or `acknowledge_alert`.
- **Cause**: the defense was primarily in the system prompt. Rollback reduced blast radius after the fact, but did not stop the action from running first.
- **Fix**: action tools now carry `RequiresConfirmation=true`. If the model requests any mutating tool and the latest user turn is not an explicit confirmation following a server-generated confirmation prompt, the engine returns a deterministic confirmation message and executes nothing. The dashboard copy now tells admins that state changes require `실행 승인`.
- **Pattern**: for tool-use agents, prompt instructions are not an authorization boundary. Gate mutating tools in deterministic application code and require a fresh human confirmation turn.

## `internal/agent` and `internal/insight` had no unit tests

- **Symptom**: the newest AI surfaces had no package-level tests even though they touched admin actions and paid/provider-specific API behavior.
- **Cause**: they shipped as integration-oriented features first; the rest of the suite covered surrounding packages but not these two.
- **Fix**: Added `internal/agent` tests for read tool execution, mutating-tool pre-confirmation blocking, and post-confirmation execution. Added `internal/insight` tests for provider default selection and the disabled summary handler's JSON 503 response.
- **Pattern**: AI/provider code still needs deterministic unit tests around local control flow. Mock the provider; do not call external APIs in unit tests.

## Non-technical installer confusion: friend installed Docker, choked on the PSK placeholder

- **Symptom**: a non-technical end user, told to install the Windows agent, instead opened **Docker Desktop** (unrelated) which failed with `There was a problem with WSL ... wsl.exe --version: exit status 0xffffffff`. Separately they asked what to put for the install command's `관리자에게-받은-인증키` (PSK) placeholder — i.e. the manual PSK substitution + "run PowerShell as admin" steps were too technical.
- **Cause**: the only install path was a multi-line PowerShell snippet requiring (1) running PowerShell elevated and (2) hand-substituting the PSK. A non-techie can't reliably do either, and the public install guide can't embed the secret PSK, so the placeholder stayed for the user to fill — a trap.
- **Fix**: Commit bf2c948bad2182f97c4b8bcde9627885d3558c48. Added an admin-only one-click installer endpoint `GET /admin/agent-installer.bat` (`PageHandler.AgentInstaller` in internal/web/pages.go) that bakes the server URL + PSK into a self-elevating `.bat`: it UAC-elevates, downloads `dvclip.exe`, writes `DOCVAULT_SERVER_URL`/`DOCVAULT_AGENT_PSK` into the **service's own registry `Environment` (REG_MULTI_SZ)** so the service reads them without a reboot, then installs + starts. Added a prominent download button on the Agent Status page (admin_agents.html), moved the manual PowerShell path into a `<details>`, and pointed manual.ko.html at the one-click flow. The friend now just double-clicks one file.
- **Commit**: bf2c948bad2182f97c4b8bcde9627885d3558c48
- **Pattern**: for non-technical end users, never ship a copy-paste-and-substitute install. Generate a per-deploy installer with secrets baked in server-side (admin-only download) and use a self-elevating wrapper so it's one double-click. Bake service env into the service's registry `Environment` key, not machine env, to avoid reboot/refresh races.
- **Verified**: real amd64 Windows (GitHub Actions `windows-latest`, workflow `.github/workflows/win-install-test.yml`, run 27661890975). After `dvclip.exe install` → `reg add ...\DocVaultClipAgent /v Environment /t REG_MULTI_SZ /d "DOCVAULT_SERVER_URL=...\0DOCVAULT_AGENT_PSK=..."` → `net start`, the service reached `STATE: 4 RUNNING` and POSTed `/api/enroll` to the configured URL with header `X-Agent-PSK: <psk>` (listener log: `HIT port=9099 method=POST path=/api/enroll psk=ci-test-psk-123`). So the SCM does apply the per-service `Environment` REG_MULTI_SZ to the process and the Go agent reads both vars via `os.Getenv` with no reboot — the risky claim holds. UAC + SmartScreen clicks remain inherently manual (no automation clicks a secure-desktop prompt); those are covered by the visual guide only.
<!-- skipped: bbb44f1 Fix commit hash in one-click installer troubleshooting entry [no-log] -->

## Even a one-click .bat trips non-technical users: SmartScreen + email blocks the file

- **Symptom**: after shipping the one-click `.bat`, two real-world blockers remained for a non-technical end user: (1) double-clicking an unsigned downloaded `.bat` triggers an "열린 파일 - 보안 경고", then UAC, then a full-screen **SmartScreen** "Windows의 PC를 보호했습니다" where the **Run button is hidden until you click "추가 정보"** — a non-techie stops here; (2) **`.bat` files are blocked as dangerous by Gmail and some messengers**, so the file may never reach the user.
- **Cause**: the agent binary is unsigned (no code-signing cert), so SmartScreen always fires; mail providers refuse executable attachments by policy. The prior `/download/install-windows.ko.html` was a text-only PowerShell guide that didn't depict these dialogs.
- **Fix**: Commit 0988b03bb6e87833e22fd089dcfbbb6363d4b429. Rewrote `internal/web/static/install-windows.ko.html` (served at `/download/install-windows.ko.html`) into a one-click-first visual guide with CSS **mockups of each dialog** (Security Warning / UAC / SmartScreen with the "추가 정보 → 실행" two-step / cmd "설치 완료") showing exactly which button to press; moved the PowerShell path into a `<details>` fallback. The Agent Status card (`admin_agents.html`) now warns that **email blocks `.bat` (use KakaoTalk/USB)**, links the guide to forward to the employee, and recommends **remote install (AnyDesk/TeamViewer)** as the most reliable path for non-technical users.
- **Commit**: 0988b03bb6e87833e22fd089dcfbbb6363d4b429
- **Pattern**: an unsigned Windows installer ALWAYS trips SmartScreen — guide users with recognizable dialog mockups and name the exact button, don't just say "click Run". And never deliver a `.bat` by email (silently blocked); use a messenger/USB/link, or remote-install it for non-technical users.
<!-- skipped: 9338d4e Add Windows install-mechanism end-to-end CI test [no-log] -->

## Install download + guide were not reachable as one in-app page

- **Symptom**: the admin couldn't reach "install" from the web app as a single place. The `.bat` download button lived buried inside the Agent Status page (mixed with the agent list), and the install guide was a separate static page (`/download/install-windows.ko.html`) that opened in a new browser tab — not an in-app page. The operator expected to click one nav item and land on a page with both the download and the instructions.
- **Cause**: the download (admin-only, PSK-bearing) and the public friend-facing guide were deliberately separate artifacts; there was no in-app page that composed them, and the sidebar only linked the external static guide.
- **Fix**: Commit e60a363. Added an in-app, admin-only page `GET /admin/install` (`PageHandler.InstallPage` → `templates/admin_install.html`, registered in `render.go` layoutPages) that combines the one-click `.bat` download button + transfer guidance (KakaoTalk/USB, email-blocks-.bat warning, remote-install tip) + the step-by-step visual dialog guide (the same Security Warning / UAC / SmartScreen / cmd-done mockups). Added a sidebar nav item "📥 Install Agent / 에이전트 설치" under Admin (`layout.html` + i18n dict) and the route in `router.go`. Verified live: `/admin/install` returns 200 with the download button, the SmartScreen mockup, and the nav link present on the dashboard.
- **Commit**: e60a363
- **Pattern**: when a workflow spans an admin-only secret (the installer) and public instructions, give the operator one in-app page that composes both, rather than scattering the pieces across a status page and an external static file.
<!-- skipped: 9338d4e Add Windows install-mechanism end-to-end CI test [no-log] -->

## Windows onboarding still required manual delivery, host assignment, and capture verification

- **Symptom**: even after the one-click `.bat`, the admin still had to download a PSK-bearing installer, send it out-of-band, assign the host to the employee after it appeared, and infer whether clipboard capture was actually working by searching endpoint events.
- **Cause**: installer generation was admin-only and not tied to a user. `endpoint_agents` tracked liveness (`last_checkin`) but not install-token provenance, running mode, self-test time, clipboard API availability, or the last real clipboard event.
- **Fix**: Added migration `018_windows_onboarding`. `/admin/install` now creates one-time employee install links backed by hashed `install_tokens`; public `/install/{token}` serves a Windows-only employee page and `/install/{token}/download` generates the `.bat` with `DOCVAULT_INSTALL_TOKEN` injected while keeping PSK hidden from the page. The clipagent now posts `/api/agent/self-test` plus the token in enroll/heartbeat/clipboard payloads. Token-backed enroll/self-test auto-assigns the hostname to the selected user. `/admin/agents` and the dashboard show health states: unassigned, offline, capture waiting, capture OK, problem, and service-account suspicion.
- **Pattern**: onboarding state needs to be first-class product data, not a support checklist. Store the install link, host mapping, self-test result, and real capture evidence so the admin can see "installed" vs "capture verified" without manual searches.

## Portfolio demo must not share the friend/product database

- **Symptom**: the same product instance was being considered for a public English portfolio demo, which would risk mixing sample data with a real user's server/DB.
- **Cause**: there was no first-class demo stack or English-default runtime mode.
- **Fix**: Added `DOCVAULT_DEFAULT_LANG`, `DOCVAULT_INSTANCE_LABEL`, English install/manual pages, and `docker-compose.demo.yml` with its own project name, Postgres volume, vault volume, local port, and optional `DOCVAULT_DEMO_SEED=true` sample data. Added demo-only `DOCVAULT_DEMO_LOGIN_ENABLED=true`, which exposes a separate **Try Demo** button that signs into `DOCVAULT_DEMO_LOGIN_USERNAME` without showing a password. Added `scripts/deploy-demo-box.sh` and an external Caddy vhost example; demo secrets reuse the existing `scripts/gen-env.sh` flow and live in ignored `.env.demo`.
- **Pattern**: portfolio demos should be isolated infrastructure, not a flag on a real customer's database.

## Demo trial login could grant a passwordless admin session; agent still unsigned

- **Symptom**: adversarial review of the demo-login feature found `web.DemoLoginSubmit` issues a full session for `DOCVAULT_DEMO_LOGIN_USERNAME` (default `admin`) with **no password**, gated only by `DOCVAULT_DEMO_LOGIN_ENABLED`. If that flag were ever set on a real-data instance, anyone hitting `POST /login/demo` would get an admin session. (Prod verified safe: flag off → `/login/demo` returns 404, no cookie.) Separately, the agent binary is unsigned, so Windows SmartScreen always warns on install.
- **Cause**: the demo login resolves a real account by username and skips password verification by design; the default demo username was `admin`, so the demo box logged in as the real admin. Code-signing was a Makefile stub that only printed instructions.
- **Fix**: Commit 747339547bd115ab393fec37b7d0abf612c63191. `DemoLoginSubmit` now refuses accounts with `user.RoleAdmin` (defense-in-depth — worst case becomes a non-admin session). Added a dedicated non-admin `demo` viewer (role `manager`) in `seedDemoData`; `docker-compose.demo.yml` sets `DOCVAULT_DEMO_LOGIN_USERNAME=demo`. Made `make sign-windows` actually sign via `osslsigncode` when a `.pfx` cert is provided, and wrote `docs/CODE_SIGNING.md` (which cert to buy + how to publish the signed exe). The cert itself is an external/paid step the operator must do; the pipeline is otherwise complete.
- **Commit**: 747339547bd115ab393fec37b7d0abf612c63191
- **Pattern**: a passwordless convenience login must hard-refuse privileged roles, not rely solely on an enable flag. And code-signing can be fully wired in advance, but only a real (paid, identity-verified) Authenticode cert removes SmartScreen — that part can't be faked.
