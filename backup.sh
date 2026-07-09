#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/heaas}"
DB_SRC="$(dirname "$0")/data/he_saas.db"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
DEST="${BACKUP_DIR}/he_saas_${TIMESTAMP}.db"

[ -f "$DB_SRC" ] || { echo "DB not found: $DB_SRC"; exit 1; }
mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_SRC" ".backup $DEST"
gzip "$DEST"
find "$BACKUP_DIR" -name "he_saas_*.db.gz" -mtime +7 -delete
echo "Backup: ${DEST}.gz"
