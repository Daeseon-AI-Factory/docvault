# DocVault — Handoff & Blueprint (for Codex / any new contributor)

_Last updated: 2026-06-18. Source of truth for "where we are and where we're going."_

## 1. What it is (and isn't)

DocVault is a **small-team insider-threat event collector & viewer**. osquery + a custom
clipboard agent collect endpoint activity → PostgreSQL → htmx web UI. A DB-trigger hash
chain detects app-level tampering; threshold rules score anomalies (no ML).

**NOT**: DRM, ML-based UEBA, legal-evidence system, or a hardened public-internet product.
See `docs/LIMITATIONS.md`.

## 2. Where it is right now (verified)

- **Live**: https://docvault.daeseon.ai
- **Hosting**: co-located on a shared NCP Seoul box (`mimi-backend`) behind another project's
  Caddy. Deployed by **rsync → docker build → compose recreate** (NOT git-based auto-deploy).
- **Repo**: GitHub `Daeseon-AI-Factory/docvault`. **Go module path is legacy:
  `github.com/JasonAIFactory/Product024_JasonDRM`** (imports use this, not the repo name).
- **Branch flow**: work on `feat/*`, `main` is PR-merge only. `main` is current (HEAD `7bc4b9e`).
- **Stack**: Go 1.26, chi, pgx/PostgreSQL 16, JWT, AES-256-GCM (chunked), DB-trigger hash chain,
  html/template + htmx (SSR, no JS build), `//go:embed` for templates/static/migrations.
- **Packages** (`internal/`): auth, user, vault, folder, audit, endpoint, alert, agent, insight,
  monitoring, tracking, ueba, web, config, database. **18 migrations** (001–018).

## 3. What this session delivered

- **Windows-first onboarding**: admin `/admin/install` creates one-time employee install links
  (`/install/{token}`) backed by hashed `install_tokens`. The employee page is public and only
  shows a Windows download button + SmartScreen/UAC steps; PSK stays server-injected in the
  generated `.bat`.
- **One-click Windows installer**: the `.bat` self-elevates, removes old LocalSystem service-mode
  installs, installs a per-user hidden Scheduled Task, and starts `dvclip.exe` inside the
  interactive Windows session. The agent posts `/api/enroll`, `/api/heartbeat`,
  `/api/agent/self-test`, and clipboard events with `DOCVAULT_INSTALL_TOKEN` when present.
- **Automatic mapping + health**: token-backed installs auto-assign the host to the selected
  employee. `endpoint_agents` now tracks running mode, session user, self-test time, clipboard
  availability, and last real clipboard event; dashboard/admin agents show unassigned/offline/
  capture-unverified/problem queues.
- **Host→employee assignment**, **CSV bulk user import**, **AI assistant** (`internal/agent`:
  OpenAI/Gemini tool-use, read + actions, every action logged to `agent_actions` with one-click
  rollback), **AI security briefing** (`internal/insight`, Anthropic or Gemini).
- **Korean-default UI** with KO/EN toggle.
- **Guardrails**: `CLAUDE.md → Guardrails`, one-shot `scripts/deploy-box.sh`. Retros in
  `content/logs/docvault/2026-06-1{6,7}-*.mdx`.

## 4. Build / test / deploy

```bash
go build ./...                     # build everything
go test ./...                      # tests (needs a Postgres for some)
bash scripts/deploy-box.sh         # rsync→build→recreate→prune→verify /health (needs scripts/.deploy.env)
```
`scripts/.deploy.env` (gitignored) holds `DOCVAULT_DEPLOY_HOST/KEY/SRC/COMPOSE/URL`.
Real-Windows agent testing = `windows-latest` CI (dev Mac is Apple-Silicon; no usable local VM).

## 5. Open gaps (honest — verify, don't assume)

| Area | Status |
|---|---|
| Friend's actual PC | **Not installed yet** — needs a human to run the link-downloaded `.bat` (UAC/SmartScreen clicks). |
| Clipboard CAPTURE on real Windows | **CI-covered on `windows-latest`** for Scheduled Task + real `Set-Clipboard`; still verify once on the actual friend PC. |
| osquery end-to-end | **Unverified** against a live daemon. |
| AI agent prompt-injection | **Mitigated in app code**: mutating tools now require a server-generated confirmation turn + explicit `실행 승인`. Tool-output fields are still attacker-influenceable and must stay treated as untrusted. |
| Unit tests for `agent`/`insight` | Added deterministic unit tests for action confirmation and insight provider defaults. Rollback DB integration still needs coverage. |
| Security-at-rest (pre-"internet-safe") | New/rotated TOTP secrets are encrypted with the master key. Legacy plaintext secrets remain readable until rotated; recovery codes still plaintext; backups are encrypted but still need off-host copy verification. (`docs/DEPLOY.md`) |
| Dashboard stat discrepancy | Earlier "전체 이벤트" count looked off — unexplained, needs a look. |

## 6. Roadmap / direction (prioritized)

**P0 — make it real for the first customer (the friend)**
1. Get one real Windows PC installed via `/admin/install` → one-time link and confirm
   dashboard status reaches **캡처 검증됨** after a Ctrl+C.
2. Per-agent **"reporting / last seen"** liveness is now based on `endpoint_agents.last_checkin`.
   The clipboard agent sends `/api/heartbeat` every 60 seconds, so idle Windows PCs still show
   as reporting. Remaining: production notification policy for offline alerts.

**P1 — trust & safety of the new AI agent**
3. **Prompt injection via tool output** now has deterministic mutating-tool confirmation. Remaining:
   sanitize/flag attacker-controlled fields in read output.
4. More `internal/agent` tests: rollback inverse-state with a real test DB.

**P2 — kill the onboarding friction**
5. **Code-sign the agent binary** → reduces SmartScreen friction (the #1 non-techie blocker).
   `make sign-windows` now documents the signtool path; a real certificate is still needed.

**P2 — security hardening before any wider exposure**
7. Finish security at rest: rotate legacy plaintext TOTP secrets, protect recovery codes, verify
   encrypted backups are copied off-host, and verify osquery e2e.

**P3 — depth**
8. Audit what `internal/ueba` / `tracking` / `monitoring` actually do (present but unreviewed this
   session); investigate the dashboard stat discrepancy; polish the unified timeline.

## 7. Conventions any contributor (incl. Codex) MUST follow

See **`CLAUDE.md → Guardrails`** (loaded every session). In short:
1. **Verify before claiming done** — paste this-run proof (curl status / `/health` 200 / CI / screenshot).
2. **Check your git branch** before any git op; `main` is PR-only.
3. **Don't `git --amend` after writing a commit hash into a tracked file.**
4. **Confirm the shape/actor of a UX deliverable before building it.**
5. **Deploy via `scripts/deploy-box.sh`** (atomic + verifies); never hand-run the steps.
6. **Audit/Log discipline**: every non-trivial change → `docs/troubleshooting.md` + a dated
   `content/logs/docvault/*.mdx` (anti-hallucination rules in `CLAUDE.md`).
7. Audit middleware on every endpoint; stream file I/O; envelope encryption; soft-delete only;
   parameterized SQL. (`CLAUDE.md → Critical Architecture Patterns`.)
