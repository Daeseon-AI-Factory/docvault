#!/usr/bin/env bash
# Generate a production .env for DocVault with strong random secrets.
#
# Usage:
#   bash scripts/gen-env.sh [domain]
#
#   domain = your public domain (e.g. docvault.example.com) for a dedicated
#            server, OR "localhost" for an all-in-one install on a single PC.
#
# Refuses to overwrite an existing .env. Requires openssl.
set -euo pipefail

cd "$(dirname "$0")/.."
ENV_FILE=".env"

if [ -f "$ENV_FILE" ]; then
	echo "ERROR: $ENV_FILE already exists — refusing to overwrite." >&2
	echo "Delete it first if you really want to regenerate secrets." >&2
	exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
	echo "ERROR: openssl is required but not found." >&2
	exit 1
fi

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
	read -rp "Server domain (public domain, or 'localhost' for all-in-one): " DOMAIN
fi
if [ -z "$DOMAIN" ]; then
	echo "ERROR: a domain (or 'localhost') is required." >&2
	exit 1
fi

# 32 bytes hex = exactly the AES-256 master key DocVault expects.
MASTER_KEY="$(openssl rand -hex 32)"
JWT_SECRET="$(openssl rand -hex 32)"
OSQUERY_PSK="$(openssl rand -hex 24)"
DB_PASSWORD="$(openssl rand -hex 24)"
# URL-safe admin password, ~24 chars.
ADMIN_PASSWORD="$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '=')"

umask 077
cat > "$ENV_FILE" <<EOF
# DocVault production environment — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# KEEP THIS FILE SECRET. It is chmod 600 and must never be committed.

DOCVAULT_DOMAIN=${DOMAIN}

DOCVAULT_DB_PASSWORD=${DB_PASSWORD}
DOCVAULT_MASTER_KEY=${MASTER_KEY}
DOCVAULT_JWT_SECRET=${JWT_SECRET}
DOCVAULT_OSQUERY_PSK=${OSQUERY_PSK}
DOCVAULT_ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Optional integrations
DOCVAULT_SLACK_WEBHOOK=
DOCVAULT_ALERT_EMAIL=
EOF
chmod 600 "$ENV_FILE"

echo "Wrote $ENV_FILE (chmod 600)."
echo
echo "=============================================================="
echo " SAVE THESE NOW — needed to log in and to install the agent:"
echo "   Admin login : admin / ${ADMIN_PASSWORD}"
echo "   Agent PSK   : ${OSQUERY_PSK}"
echo "   Server URL  : https://${DOMAIN}"
echo "=============================================================="
