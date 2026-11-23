#!/usr/bin/env bash
# Ghost Gate security-state restore — DANGEROUS, operator-only.
#
# Restores a verified backup of registry/replay state while preserving monotonic security state:
# generation ledger, audit log, halt latch and bootstrap token are NEVER taken from the backup.
# By default the current replay store is also preserved, because rolling replay records backwards
# can re-authorise spent challenges.
#
# Usage:
#   GG_CONFIRM_RESTORE=1 sudo -E bash deploy/restore.sh /opt/ghost-gate/data/backups/ghost-gate-....tar.gz
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "restore: must run as root" >&2
    exit 1
fi
if [ "${GG_CONFIRM_RESTORE:-}" != "1" ]; then
    echo "restore: refusing to change security state without explicit confirmation." >&2
    echo "Set GG_CONFIRM_RESTORE=1 only after you have reviewed the backup and the rollback plan." >&2
    exit 1
fi

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "usage: GG_CONFIRM_RESTORE=1 bash restore.sh <backup.tar.gz>" >&2
    exit 1
fi
if [ ! -f "$ARCHIVE.sha256" ]; then
    echo "restore: missing checksum file $ARCHIVE.sha256" >&2
    exit 1
fi

echo "restore: verifying archive checksum"
( cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" )

BASE="/opt/ghost-gate"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TMP="$BASE/data/.restore-$TIMESTAMP"
install -d -o root -g root -m 0700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT

echo "restore: extracting into staging directory"
tar xzf "$ARCHIVE" -C "$TMP"
if [ ! -d "$TMP/data/registry" ] || [ ! -d "$TMP/data/replays" ]; then
    echo "restore: archive does not contain data/registry and data/replays" >&2
    exit 1
fi

# Monotonic security state is never rolled back. Preserve the CURRENT versions if present.
for f in generations.ndjson reset_halt.json audit.ndjson bootstrap.token; do
    current="$BASE/data/registry/$f"
    if [ -f "$current" ]; then
        cp -p -- "$current" "$TMP/data/registry/$f"
        echo "restore: preserved current $f"
    else
        rm -f -- "$TMP/data/registry/$f"
    fi
done
rm -f -- "$TMP/data/registry/store.lock"

if [ "${GG_ALLOW_REPLAY_RESTORE:-}" != "1" ]; then
    echo "restore: preserving current replay state (set GG_ALLOW_REPLAY_RESTORE=1 to override)"
    cp -a -- "$BASE/data/replays/." "$TMP/data/replays/"
fi

echo "restore: taking a fresh safety backup of current state"
if [ -x "$BASE/source/backup.sh" ]; then
    bash "$BASE/source/backup.sh"
else
    echo "restore: warning: backup.sh not found at $BASE/source/backup.sh" >&2
fi

echo "restore: stopping services"
systemctl stop ghost-gate-telegram ghost-gate-bridge ghost-gate-admin || true

echo "restore: swapping directories"
mv -- "$BASE/data/registry" "$BASE/data/registry.pre-restore-$TIMESTAMP"
mv -- "$BASE/data/replays" "$BASE/data/replays.pre-restore-$TIMESTAMP"
mv -- "$TMP/data/registry" "$BASE/data/registry"
mv -- "$TMP/data/replays" "$BASE/data/replays"
chown -R ghostgate-registry:ghostgate-registry "$BASE/data/registry" "$BASE/data/replays"
chmod -R go-rwx "$BASE/data/registry" "$BASE/data/replays"

echo "restore: starting services"
systemctl start ghost-gate-bridge
sleep 2
systemctl start ghost-gate-telegram ghost-gate-admin || true

if [ -x "$BASE/source/healthcheck.sh" ]; then
    bash "$BASE/source/healthcheck.sh"
fi

echo "restore: complete"
echo "Previous state retained at:"
echo "  $BASE/data/registry.pre-restore-$TIMESTAMP"
echo "  $BASE/data/replays.pre-restore-$TIMESTAMP"
echo "Do not delete those directories until the restored system has been verified."
