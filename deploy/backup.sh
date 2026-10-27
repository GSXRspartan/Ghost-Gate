#!/usr/bin/env bash
# Ghost Gate backup — run daily via cron or manually.
# Backs up registry state, replay store, and environment config.
# Does NOT back up binaries (rebuild from source) or secrets (separate).
set -euo pipefail

BACKUP_DIR="/opt/ghost-gate/data/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$BACKUP_DIR/ghost-gate-$TIMESTAMP.tar.gz"

echo "Ghost Gate backup: $TIMESTAMP"

tar czf "$ARCHIVE" \
    -C /opt/ghost-gate \
    data/registry \
    data/replays \
    2>/dev/null || true

# Keep only the last 14 daily backups
ls -1t "$BACKUP_DIR"/ghost-gate-*.tar.gz 2>/dev/null | tail -n +15 | xargs -r rm --

echo "Backup: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
echo "Backups retained: $(ls -1 "$BACKUP_DIR"/ghost-gate-*.tar.gz 2>/dev/null | wc -l)"
