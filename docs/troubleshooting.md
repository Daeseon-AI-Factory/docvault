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
