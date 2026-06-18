# DocVault Deployment Guide

DocVault has two parts:

- **Server** — the Go app + PostgreSQL, run with Docker Compose. Holds the web UI and receives agent events.
- **Agents** — installed on each monitored Windows PC: the **clipboard agent** (DocVault's own binary) and, optionally, **osquery** (file / USB / process monitoring).

It supports two deployment shapes with the **same** compose file and `.env`:

| | Scenario A — dedicated server | Scenario B — all-in-one |
|---|---|---|
| Server runs on | your Linux/cloud VM | the friend's PC (Docker Desktop) |
| `DOCVAULT_DOMAIN` | `docvault.example.com` (public) | `localhost` |
| TLS | real Let's Encrypt cert (automatic) | local self-signed cert (automatic) |
| Agent `DOCVAULT_SERVER_URL` | `https://docvault.example.com` | `https://localhost` |

> Honesty note: the commands below are written to spec but were **not executed in the authoring environment** (no Docker / no Windows / no osquery here). Treat the first run as a smoke test and follow the verification checklist at the end.

---

## Prerequisites

**Server host:** Docker + the Docker Compose v2 plugin, ports 80 and 443 open. For Scenario A you also need a domain whose DNS A record points at the server.

**Each monitored PC:** Windows 10/11, administrator access. For osquery, the osquery MSI from osquery.io.

---

## Part 1 — Server

```bash
git clone <this repo> && cd docvault

# Scenario A (public domain):
bash scripts/deploy-server.sh docvault.example.com

# Scenario B (all-in-one on one PC):
bash scripts/deploy-server.sh localhost
```

`deploy-server.sh` will:

1. generate `.env` with strong random secrets (`scripts/gen-env.sh`) and print the **admin password**, **agent PSK**, and **URL** — save these;
2. `docker compose -f docker-compose.prod.yml up -d --build`, which runs `db → migrate → seed → server → caddy`. Migrations and the admin account are created automatically.

Retrieve the admin password later from the seed log:

```bash
docker compose -f docker-compose.prod.yml logs seed
```

Log in at `https://<domain>` as `admin` and **change the password immediately** (Admin → Users).

---

## Portfolio demo server (separate from the product/friend instance)

Do **not** use the production/friend database for portfolio demos. The repo includes
an isolated demo stack:

- `docker-compose.demo.yml` overrides the normal local compose project name to `docvault-demo`;
- it creates separate Postgres and vault volumes;
- it binds the app to `127.0.0.1:18080` by default;
- `DOCVAULT_DEFAULT_LANG=en` makes the UI open in English;
- `DOCVAULT_DEMO_SEED=true` seeds sample employees, agents, health states,
  alerts, and endpoint events.

Local demo:

```bash
bash scripts/gen-env.sh localhost
mv .env .env.demo
cat >> .env.demo <<'EOF'
DOCVAULT_DEMO_HTTP_PORT=18080
DOCVAULT_DEFAULT_LANG=en
DOCVAULT_INSTANCE_LABEL=Portfolio Demo
DOCVAULT_DEMO_SEED=true
EOF

docker compose --env-file .env.demo -f docker-compose.yml -f docker-compose.demo.yml up -d --build
docker compose --env-file .env.demo -f docker-compose.yml -f docker-compose.demo.yml logs seed
open http://localhost:18080
```

Public portfolio demo on the same box as another DocVault instance:

1. keep a separate source dir such as `/opt/docvault-demo-src`;
2. keep a separate `.env.demo`;
3. run `scripts/deploy-demo-box.sh` with `scripts/.deploy-demo.env`;
4. put an external Caddy/Nginx vhost in front of `127.0.0.1:18080`.

Example Caddy vhost: `deploy/caddy/demo-site.Caddyfile`.

This gives you a real server + real demo DB + real seeded UI without touching
the friend/customer product instance.

---

## Part 2 — Clipboard agent (the friend's PC)

This is DocVault's own agent and is the quickest path to a working product.

1. **Build and publish the Windows binary** where `/download/dvclip-windows-amd64.exe`
   can serve it:

   ```bash
   GOOS=windows GOARCH=amd64 go build -o /vault/agents/dvclip-windows-amd64.exe ./cmd/clipagent
   ```

2. Log in as admin and open `/admin/install`.

3. Select the employee and create a one-time Windows install link.

4. Send only that link to the employee. The employee page shows a download
   button and Windows warning-dialog steps; it does not show the PSK.

5. The downloaded `docvault-install.bat` self-elevates, downloads
   `dvclip.exe`, removes any old LocalSystem service-mode install, creates a
   per-user hidden Scheduled Task, and starts the agent in the interactive
   Windows session. Clipboard capture depends on that interactive session.

6. On the dashboard, confirm the Windows onboarding queue clears. Under
   **Agents**, the PC should show `보고중`; after the employee copies anything
   with Ctrl+C, it should move from capture waiting to `캡처 검증됨`.

The agent buffers events (bounded in-memory queue) and retries with backoff if the server is briefly unreachable, and re-enrolls every 5 minutes — so a dropped connection does not silently lose data.

---

## Part 3 — osquery (optional: file / USB / process monitoring)

The server now implements the osquery TLS protocol at `/api/osquery/enroll|config|log` (enroll secret → `node_key`).

1. Install osquery (osquery.io MSI) on the PC.
2. Place the enroll secret — **the same `DOCVAULT_OSQUERY_PSK`** — at `C:\ProgramData\osquery\enroll_secret` (a single line, no trailing newline).
3. Copy `deploy/osquery/osquery.flags` and `deploy/osquery/osquery.conf` to `C:\ProgramData\osquery\`.
4. Edit `osquery.flags`:
   - set `--tls_hostname=docvault.example.com` (your domain, no scheme);
   - with a **public Let's Encrypt** cert (Scenario A), remove the `--tls_server_certs=...` line — the system trust store already trusts it;
   - with a **self-signed/localhost** cert (Scenario B), export Caddy's local CA and point `--tls_server_certs` at it.
5. Restart the `osqueryd` service. The node enrolls and starts shipping scheduled-query results.

> osquery end-to-end has **not** been verified against a live daemon here. Validate this part on the actual PC; if enrollment fails, check `osqueryd.results.log` and the server logs for `osquery node enrolled` / `node_invalid`.

---

## Smoke test checklist

- [ ] `docker compose -f docker-compose.prod.yml ps` shows `db`, `server`, `caddy` healthy; `migrate` and `seed` exited 0.
- [ ] `https://<domain>` loads the login page over HTTPS (valid cert in Scenario A).
- [ ] Admin login works; the API login refuses a wrong password and (if 2FA enabled) requires a TOTP code.
- [ ] Clipboard agent service is `Running`; copying a file/text on the PC produces an event on the dashboard.
- [ ] (osquery) the PC appears as an osquery node; a USB insert / file write shows up.
- [ ] Restarting the server does not require reinstalling agents (they re-enroll automatically).

---

## Still open before "safe on the public internet"

These are tracked and not yet done:

- New/rotated TOTP secrets are encrypted at rest with the master key. Existing plaintext TOTP secrets remain valid until users rotate 2FA.
- TOTP recovery codes are still stored plaintext; protect them before wider internet exposure.
- Backups (`deploy/backup/backup.sh`) are encrypted, but copying encrypted artifacts off-host is still an operational TODO.
- osquery end-to-end is unverified against a live daemon.

For Scenario B (all-in-one on a single trusted PC, LAN only) these matter less; for Scenario A (internet-exposed) close them before relying on it.
