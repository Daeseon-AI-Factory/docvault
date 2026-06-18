#!/usr/bin/env bash
# Deploy the isolated portfolio demo instance to a box.
#
# Config (never committed): create scripts/.deploy-demo.env with:
#   DOCVAULT_DEMO_DEPLOY_HOST=root@<box-ip-or-host>
#   DOCVAULT_DEMO_DEPLOY_KEY=/abs/path/to/ssh/key
#   DOCVAULT_DEMO_DEPLOY_SRC=/opt/docvault-demo-src
#   DOCVAULT_DEMO_DEPLOY_URL=https://demo-docvault.example.com
#   DOCVAULT_DEMO_ENV_FILE=.env.demo
#
# The demo stack uses docker-compose.yml plus docker-compose.demo.yml and
# publishes only to 127.0.0.1:${DOCVAULT_DEMO_HTTP_PORT:-18080}. Put an
# external Caddy/Nginx vhost in front of it for a public portfolio URL.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f scripts/.deploy-demo.env ] && . scripts/.deploy-demo.env
: "${DOCVAULT_DEMO_DEPLOY_HOST:?set DOCVAULT_DEMO_DEPLOY_HOST}"
: "${DOCVAULT_DEMO_DEPLOY_KEY:?set DOCVAULT_DEMO_DEPLOY_KEY}"
: "${DOCVAULT_DEMO_DEPLOY_SRC:?set DOCVAULT_DEMO_DEPLOY_SRC}"
: "${DOCVAULT_DEMO_DEPLOY_URL:?set DOCVAULT_DEMO_DEPLOY_URL}"

DOCVAULT_DEMO_ENV_FILE="${DOCVAULT_DEMO_ENV_FILE:-.env.demo}"
if [ ! -f "${DOCVAULT_DEMO_ENV_FILE}" ]; then
	echo "ERROR: ${DOCVAULT_DEMO_ENV_FILE} not found. Generate .env, move it to .env.demo, then append demo settings." >&2
	exit 1
fi

SSH="ssh -i ${DOCVAULT_DEMO_DEPLOY_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=12"

echo "==> branch: $(git branch --show-current)   HEAD: $(git rev-parse --short HEAD)"
echo "==> rsync demo source -> ${DOCVAULT_DEMO_DEPLOY_HOST}:${DOCVAULT_DEMO_DEPLOY_SRC}"
rsync -az --delete \
  --exclude='.git' --exclude='bin' --exclude='claude_review' --exclude='codex_review' \
  --exclude='content' --exclude='*.png' --exclude='*.docx' --exclude='/server' \
  --exclude='.env' --exclude='.env.local' \
  -e "${SSH}" ./ "${DOCVAULT_DEMO_DEPLOY_HOST}:${DOCVAULT_DEMO_DEPLOY_SRC}/"

echo "==> build + migrate + seed + recreate demo (on box)"
${SSH} "${DOCVAULT_DEMO_DEPLOY_HOST}" "
  set -e
  cd '${DOCVAULT_DEMO_DEPLOY_SRC}'
  docker compose --env-file '${DOCVAULT_DEMO_ENV_FILE}' -f docker-compose.yml -f docker-compose.demo.yml build
  docker compose --env-file '${DOCVAULT_DEMO_ENV_FILE}' -f docker-compose.yml -f docker-compose.demo.yml up -d db
  docker compose --env-file '${DOCVAULT_DEMO_ENV_FILE}' -f docker-compose.yml -f docker-compose.demo.yml run --rm migrate
  docker compose --env-file '${DOCVAULT_DEMO_ENV_FILE}' -f docker-compose.yml -f docker-compose.demo.yml run --rm seed
  docker compose --env-file '${DOCVAULT_DEMO_ENV_FILE}' -f docker-compose.yml -f docker-compose.demo.yml up -d --force-recreate server
  docker builder prune -af >/dev/null 2>&1
  echo -n 'root disk: '; df -h / | tail -1
"

echo "==> verify ${DOCVAULT_DEMO_DEPLOY_URL}/health"
sleep 4
code="$(curl -s -o /dev/null -w '%{http_code}' "${DOCVAULT_DEMO_DEPLOY_URL}/health")"
if [ "${code}" = "200" ]; then
  echo "PASS: demo /health 200 — deploy verified"
else
  echo "FAIL: demo /health returned ${code}" >&2
  exit 1
fi
