#!/usr/bin/env bash
# Ghost Gate health check — returns 0 when both services are healthy.
# Use with monitoring (cron, uptime robot, etc).
set -euo pipefail

BRIDGE_URL="http://127.0.0.1:7799/health"
STATUS=0

# Bridge health
if BRIDGE=$(curl -sf --max-time 5 "$BRIDGE_URL" 2>/dev/null); then
    echo "bridge: OK"
else
    echo "bridge: UNREACHABLE"
    STATUS=1
fi

# Telegram bot: check systemd unit is active
if systemctl is-active --quiet ghost-gate-telegram 2>/dev/null; then
    echo "telegram: ACTIVE"
else
    echo "telegram: INACTIVE"
    STATUS=1
fi

# Cloudflared tunnel
if systemctl is-active --quiet cloudflared 2>/dev/null; then
    echo "tunnel: ACTIVE"
else
    echo "tunnel: INACTIVE"
    STATUS=1
fi

exit $STATUS
