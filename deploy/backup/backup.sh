#!/bin/bash
set -euo pipefail

# DocVault daily backup script
# Add to crontab: 0 2 * * * /opt/docvault/deploy/backup/backup.sh

BACKUP_DIR="/opt/docvault/backups"
VAULT_DIR="/opt/docvault/vault"
DB_NAME="docvault"
DB_USER="docvault_app"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "[$(date)] Starting DocVault backup..."

# 1. Database backup
echo "[$(date)] Backing up PostgreSQL database..."
pg_dump -U "$DB_USER" -Fc "$DB_NAME" > "$BACKUP_DIR/db_${DATE}.dump"

# 2. Vault files backup (rsync for incremental)
echo "[$(date)] Syncing vault files..."
rsync -a --delete "$VAULT_DIR/" "$BACKUP_DIR/vault_latest/"

# 3. Compress vault snapshot
echo "[$(date)] Creating vault archive..."
tar czf "$BACKUP_DIR/vault_${DATE}.tar.gz" -C "$BACKUP_DIR" vault_latest/

# 4. Cleanup old backups
echo "[$(date)] Cleaning up backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "db_*.dump" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "vault_*.tar.gz" -mtime +${RETENTION_DAYS} -delete

# 5. Report
DB_SIZE=$(du -sh "$BACKUP_DIR/db_${DATE}.dump" | cut -f1)
VAULT_SIZE=$(du -sh "$BACKUP_DIR/vault_${DATE}.tar.gz" | cut -f1)

echo "[$(date)] Backup complete."
echo "  Database: $DB_SIZE ($BACKUP_DIR/db_${DATE}.dump)"
echo "  Vault:    $VAULT_SIZE ($BACKUP_DIR/vault_${DATE}.tar.gz)"
