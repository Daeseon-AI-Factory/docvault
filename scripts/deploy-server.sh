#!/usr/bin/env bash
# One-command DocVault server deploy via Docker Compose.
#
# Works for both scenarios:
#   - dedicated Linux/cloud server with a public domain
#   - all-in-one box (e.g. friend's PC with Docker Desktop), DOCVAULT_DOMAIN=localhost
#
# Usage:
#   bash scripts/deploy-server.sh [domain]
#
# If no .env exists, one is generated (scripts/gen-env.sh). Migrations and the
# admin seed run automatically as part of the compose stack.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker is required. Install Docker + the compose plugin first." >&2
	exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
	echo "ERROR: 'docker compose' (v2) is required." >&2
	exit 1
fi

if [ ! -f .env ]; then
	echo "No .env found — generating secrets..."
	bash scripts/gen-env.sh "${1:-}"
	echo
fi

echo "Building images and starting the stack (db -> migrate -> seed -> server -> caddy)..."
docker compose -f docker-compose.prod.yml up -d --build

DOMAIN="$(grep '^DOCVAULT_DOMAIN=' .env | cut -d= -f2-)"
PSK="$(grep '^DOCVAULT_OSQUERY_PSK=' .env | cut -d= -f2-)"

echo
echo "=============================================================="
echo " DocVault is starting."
echo "   URL        : https://${DOMAIN}"
echo "   Agent PSK  : ${PSK}"
echo
echo " Admin password (if it was just generated) is in the seed log:"
echo "   docker compose -f docker-compose.prod.yml logs seed"
echo
echo " Check status:"
echo "   docker compose -f docker-compose.prod.yml ps"
echo "   docker compose -f docker-compose.prod.yml logs -f server"
echo "=============================================================="
