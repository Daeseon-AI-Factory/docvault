#!/usr/bin/env bash
# Atomic deploy to the co-located box, with verification — one command.
#
# Exists because hand-running rsync/build/restart piecemeal caused redeploy churn,
# filled the box's 10 GB root disk (BuildKit cache), and let "deployed but never
# verified" slip through. See content/logs/docvault/2026-06-17-onboarding-retro.mdx.
#
# Steps: rsync source -> docker build -> compose recreate -> builder prune -> verify /health.
#
# Config (never committed): create scripts/.deploy.env (gitignored) with:
#   DOCVAULT_DEPLOY_HOST=root@<box-ip-or-host>
#   DOCVAULT_DEPLOY_KEY=/abs/path/to/ssh/key
#   DOCVAULT_DEPLOY_SRC=/opt/docvault-src          # build context on the box
#   DOCVAULT_DEPLOY_COMPOSE=/opt/mimi              # dir holding the compose files
#   DOCVAULT_DEPLOY_URL=https://docvault.daeseon.ai
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f scripts/.deploy.env ] && . scripts/.deploy.env
: "${DOCVAULT_DEPLOY_HOST:?set DOCVAULT_DEPLOY_HOST (see header / scripts/.deploy.env)}"
: "${DOCVAULT_DEPLOY_KEY:?set DOCVAULT_DEPLOY_KEY}"
: "${DOCVAULT_DEPLOY_SRC:?set DOCVAULT_DEPLOY_SRC}"
: "${DOCVAULT_DEPLOY_COMPOSE:?set DOCVAULT_DEPLOY_COMPOSE}"
: "${DOCVAULT_DEPLOY_URL:?set DOCVAULT_DEPLOY_URL}"

SSH="ssh -i ${DOCVAULT_DEPLOY_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=12"

echo "==> branch: $(git branch --show-current)   HEAD: $(git rev-parse --short HEAD)"
echo "==> rsync -> ${DOCVAULT_DEPLOY_HOST}:${DOCVAULT_DEPLOY_SRC}"
rsync -az --delete \
  --exclude='.git' --exclude='bin' --exclude='claude_review' --exclude='codex_review' \
  --exclude='content' --exclude='*.png' --exclude='*.docx' --exclude='/server' \
  -e "${SSH}" ./ "${DOCVAULT_DEPLOY_HOST}:${DOCVAULT_DEPLOY_SRC}/"

echo "==> build + recreate + prune (on box)"
${SSH} "${DOCVAULT_DEPLOY_HOST}" "
  set -e
  docker build -t docvault:latest '${DOCVAULT_DEPLOY_SRC}' 2>&1 | tail -2
  cd '${DOCVAULT_DEPLOY_COMPOSE}'
  docker compose run --rm docvault-migrate
  docker compose up -d --force-recreate docvault 2>&1 | tail -2
  docker builder prune -af >/dev/null 2>&1
  echo -n 'root disk: '; df -h / | tail -1
"

echo "==> verify ${DOCVAULT_DEPLOY_URL}/health"
sleep 4
code="$(curl -s -o /dev/null -w '%{http_code}' "${DOCVAULT_DEPLOY_URL}/health")"
if [ "${code}" = "200" ]; then
  echo "PASS: /health 200 — deploy verified"
else
  echo "FAIL: /health returned ${code}" >&2
  exit 1
fi
