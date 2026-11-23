#!/usr/bin/env bash
# Ghost Gate backup — run daily via cron or manually.
# Backs up security-sensitive registry and replay state. The archive can contain administrator
# credentials, session grants, and replay records, so it must remain readable only by root.
# Does NOT back up binaries or service environment/credential files.
set -euo pipefail
umask 077

BACKUP_DIR="/opt/ghost-gate/data/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$BACKUP_DIR/ghost-gate-$TIMESTAMP.tar.gz"
TEMP_ARCHIVE="$BACKUP_DIR/.ghost-gate-$TIMESTAMP.tar.gz.tmp"

install -d -o root -g root -m 0700 "$BACKUP_DIR"
trap 'rm -f -- "$TEMP_ARCHIVE"' EXIT

echo "Ghost Gate backup: $TIMESTAMP"

tar czf "$TEMP_ARCHIVE" \
    -C /opt/ghost-gate \
    data/registry \
    data/replays
chmod 0600 "$TEMP_ARCHIVE"
mv -f -- "$TEMP_ARCHIVE" "$ARCHIVE"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
chmod 0600 "$ARCHIVE.sha256"
trap - EXIT

# Keep only the last 14 daily backups
ls -1t "$BACKUP_DIR"/ghost-gate-*.tar.gz 2>/dev/null | tail -n +15 | while read -r old; do
    rm -f -- "$old" "$old.sha256"
done

echo "Backup: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
echo "Backups retained: $(ls -1 "$BACKUP_DIR"/ghost-gate-*.tar.gz 2>/dev/null | wc -l)"
