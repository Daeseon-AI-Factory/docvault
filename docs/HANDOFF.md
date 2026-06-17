# DocVault — Handoff & Blueprint (for Codex / any new contributor)

_Last updated: 2026-06-17. Source of truth for "where we are and where we're going."_

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
  monitoring, tracking, ueba, web, config, database. **15 migrations** (001–015).

## 3. What this session delivered

- **One-click Windows installer**: admin-only `GET /admin/agent-installer.bat` → self-elevating
  `.bat` with server URL + PSK baked in; env injected into the service registry `Environment`
  (REG_MULTI_SZ), read with no reboot. **Verified on real amd64 Windows** via
  `.github/workflows/win-install-test.yml` (CI run 27661890975: service installs, reads env,
  enrolls). UAC/SmartScreen clicks remain inherently manual.
- **In-app install page** `/admin/install` (download + step-by-step visual dialog guide in one),
  linked from the sidebar (관리자 → 📥 에이전트 설치). Public friend guide at
  `/download/install-windows.ko.html`; user manual at `/download/manual.ko.html`.
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
| Friend's actual PC | **Not installed yet** — needs a human to run the `.bat` (UAC/SmartScreen clicks). |
| Clipboard CAPTURE on a real desktop | **Unverified** — CI proved *enroll/connect* only; capture needs an interactive session. |
| osquery end-to-end | **Unverified** against a live daemon. |
| AI agent prompt-injection | Tool output includes attacker-influenceable fields (file names, window titles) → can reach action tools. Rollback limits blast radius; the action still runs first. **Unmitigated.** |
| Unit tests for `agent`/`insight` | **0.** Rest of suite passes. |
| Security-at-rest (pre-"internet-safe") | TOTP secrets unencrypted at rest; backups unencrypted/local-only. (`docs/DEPLOY.md`) |
| Dashboard stat discrepancy | Earlier "전체 이벤트" count looked off — unexplained, needs a look. |

## 6. Roadmap / direction (prioritized)

**P0 — make it real for the first customer (the friend)**
1. Get one real Windows PC installed and confirm **events actually flow** (enroll ≠ capture).
2. Add a per-agent **"reporting / last seen"** liveness signal + offline alert, so the operator
   knows a PC stopped reporting.

**P1 — trust & safety of the new AI agent**
3. Mitigate **prompt injection via tool output**: separate read-only vs action paths, require
   explicit operator confirmation for mutating tools, and/or sanitize/flag attacker-controlled
   fields before they enter the model context.
4. **Unit tests** for `internal/agent` (tool dispatch, rollback inverse-state) and `internal/insight`.

**P2 — kill the onboarding friction**
5. **Code-sign the agent binary** → removes SmartScreen entirely (the #1 non-techie blocker).
6. **One-time tokenized download link** so the friend self-downloads the personalized installer
   (no admin-only gate, no `.bat`-by-email problem). Keep the PSK server-side.

**P2 — security hardening before any wider exposure**
7. Encrypt TOTP secrets at rest (master key); encrypt + offsite the backups; verify osquery e2e.

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
