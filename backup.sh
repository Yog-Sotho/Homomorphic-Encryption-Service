#!/usr/bin/env bash
# Backs up everything HEaaS keeps: the database (a consistent snapshot taken
# while the server runs), users' server keys and the job store. Run as root
# from the directory with docker-compose.yml, e.g. daily from cron. Restoring
# is described in README.md ("Backups").
set -euo pipefail
cd "$(dirname "$0")"

# Must be the BACKUP_DIR compose was started with (it is mounted at /backups).
BACKUP_DIR="${BACKUP_DIR:-/var/backups/heaas}"
KEEP_DAYS="${KEEP_DAYS:-7}"
NAME="heaas_$(date -u +%Y%m%d_%H%M%S)"

# The backend runs as uid 65532 and writes the backup through the mount.
install -d -m 0700 -o 65532 -g 65532 "$BACKUP_DIR"
docker compose exec -T backend he-backend backup "/backups/$NAME"

tar -C "$BACKUP_DIR" -czf "$BACKUP_DIR/$NAME.tar.gz" "$NAME"
rm -rf "${BACKUP_DIR:?}/$NAME"
chmod 0600 "$BACKUP_DIR/$NAME.tar.gz"
find "$BACKUP_DIR" -maxdepth 1 -name 'heaas_*.tar.gz' -mtime +"$KEEP_DAYS" -delete
echo "Backup: $BACKUP_DIR/$NAME.tar.gz"
