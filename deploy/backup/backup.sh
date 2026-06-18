#!/bin/bash
set -euo pipefail

# DocVault daily backup script — encrypted at rest.
# Add to crontab: 0 2 * * * /opt/docvault/deploy/backup/backup.sh
#
# Backups contain password hashes and TOTP secrets, so they are encrypted with
# a symmetric key before being written. Create the key once (keep it OFF this
# host / in a password manager too):
#
#   openssl rand -base64 48 > /opt/docvault/backup.key && chmod 600 /opt/docvault/backup.key
#
# Restore:
#   openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/opt/docvault/backup.key \
#       -in db_YYYYMMDD_HHMMSS.dump.enc | pg_restore -d docvault
#
# DB auth: set PGPASSWORD or use ~/.pgpass for the docvault_app role.

BACKUP_DIR="/opt/docvault/backups"
VAULT_DIR="/opt/docvault/vault"
DB_NAME="docvault"
DB_USER="docvault_app"
RETENTION_DAYS=30
KEY_FILE="${DOCVAULT_BACKUP_KEY_FILE:-/opt/docvault/backup.key}"
DATE=$(date +%Y%m%d_%H%M%S)

if [ ! -f "$KEY_FILE" ]; then
	echo "ERROR: backup key not found at $KEY_FILE" >&2
	echo "Create it: openssl rand -base64 48 > $KEY_FILE && chmod 600 $KEY_FILE" >&2
	exit 1
fi

mkdir -p "$BACKUP_DIR"
enc() { openssl enc -aes-256-cbc -pbkdf2 -salt -pass "file:$KEY_FILE"; }

echo "[$(date)] Starting DocVault backup..."

# 1. Database backup (piped straight into encryption — no plaintext on disk)
echo "[$(date)] Backing up PostgreSQL database..."
pg_dump -U "$DB_USER" -Fc "$DB_NAME" | enc > "$BACKUP_DIR/db_${DATE}.dump.enc"

# 2. Vault files: stream directly into encryption — no plaintext staging copy.
echo "[$(date)] Creating encrypted vault archive..."
tar czf - -C "$VAULT_DIR" . | enc > "$BACKUP_DIR/vault_${DATE}.tar.gz.enc"
rm -rf "$BACKUP_DIR/vault_latest"

# 3. Cleanup old encrypted backups
echo "[$(date)] Cleaning up backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "db_*.dump.enc" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "vault_*.tar.gz.enc" -mtime +${RETENTION_DAYS} -delete

# 4. Report
DB_SIZE=$(du -sh "$BACKUP_DIR/db_${DATE}.dump.enc" | cut -f1)
VAULT_SIZE=$(du -sh "$BACKUP_DIR/vault_${DATE}.tar.gz.enc" | cut -f1)

echo "[$(date)] Backup complete (encrypted)."
echo "  Database: $DB_SIZE ($BACKUP_DIR/db_${DATE}.dump.enc)"
echo "  Vault:    $VAULT_SIZE ($BACKUP_DIR/vault_${DATE}.tar.gz.enc)"
echo "  NOTE: copy these off-host (rsync to a remote/offsite location)."
