#!/usr/bin/env bash
# Ghost Gate VPS setup — Ubuntu 24.04 LTS
# Run as root on a fresh VPS. Stops before starting services.
#
# What this script does:
#   1. Creates three no-login service accounts with separate service configuration
#   2. Creates the directory structure
#   3. Installs cloudflared
#   4. Places systemd units
#   5. Prints next steps (binary upload, secrets, tunnel setup)
#
# What this script does NOT do:
#   - Upload binaries (you scp them)
#   - Set secrets (you edit the two service-specific environment files)
#   - Create the Cloudflare tunnel (you run cloudflared tunnel login)
#   - Start any services (you do that after verification)

set -euo pipefail

echo "=== Ghost Gate VPS Setup ==="
echo ""

# ── 1. Service accounts ─────────────────────────────────────────────────────
if ! getent group ghostgate-registry >/dev/null; then
    groupadd --system ghostgate-registry
    echo "[ok] Created narrow registry-sharing group: ghostgate-registry"
fi

for account in ghostgate-bridge ghostgate-telegram ghostgate-admin; do
    if ! id -u "$account" >/dev/null 2>&1; then
        useradd --system --user-group --shell /usr/sbin/nologin --home-dir /nonexistent "$account"
        echo "[ok] Created no-login service account: $account"
    else
        echo "[ok] Service account already exists: $account"
    fi
done

# ── 2. Directory structure ──────────────────────────────────────────────────
mkdir -p /opt/ghost-gate/{bin,etc,source,data/{registry,replays,backups}}

# Binaries: owned by root, executable
chown root:root /opt/ghost-gate/bin
chmod 755 /opt/ghost-gate/bin

# Config: root-writable only. Each service receives a distinct secret file.
chown root:root /opt/ghost-gate/etc
chmod 750 /opt/ghost-gate/etc

# Data isolation: only the bridge receives replay-store access.  Registry access is shared only
# by the bridge and private admin dashboard, through a dedicated group; Telegram gets neither.
chown ghostgate-bridge:ghostgate-bridge /opt/ghost-gate/data/replays
chmod 700 /opt/ghost-gate/data/replays
chown ghostgate-admin:ghostgate-registry /opt/ghost-gate/data/registry
chmod 2770 /opt/ghost-gate/data/registry
usermod -a -G ghostgate-registry ghostgate-bridge
usermod -a -G ghostgate-registry ghostgate-admin
chown root:root /opt/ghost-gate/data
chmod 755 /opt/ghost-gate/data

echo "[ok] Directory structure created at /opt/ghost-gate/"
echo "     bin/       — ghost-gate-bridge, ghost-gate-telegram"
echo "     etc/       — service-specific environment files, cloudflared config"
echo "     data/      — registry, replays, backups"

# ── 3. Install cloudflared ──────────────────────────────────────────────────
if ! command -v cloudflared >/dev/null 2>&1; then
    echo ""
    echo "Installing cloudflared..."
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
        | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
        | tee /etc/apt/sources.list.d/cloudflared.list
    apt-get update -qq
    apt-get install -y -qq cloudflared
    echo "[ok] cloudflared installed: $(cloudflared --version)"
else
    echo "[ok] cloudflared already installed: $(cloudflared --version)"
fi

# ── 4. Place systemd units ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cp "$SCRIPT_DIR/ghost-gate-bridge.service" /etc/systemd/system/
cp "$SCRIPT_DIR/ghost-gate-telegram.service" /etc/systemd/system/
cp "$SCRIPT_DIR/ghost-gate-admin.service" /etc/systemd/system/
systemctl daemon-reload
echo "[ok] systemd units installed"

# ── 5. Place config templates ───────────────────────────────────────────────
for service in bridge telegram admin; do
    target="/opt/ghost-gate/etc/ghost-gate-$service.env"
    source="$SCRIPT_DIR/ghost-gate-$service.env.template"
    owner="ghostgate-$service"
    if [ ! -f "$target" ]; then
        cp "$source" "$target"
        chown "root:$owner" "$target"
        chmod 640 "$target"
        echo "[ok] Environment template placed at $target"
    else
        echo "[ok] $target already exists (not overwritten)"
    fi
done

if [ ! -f /opt/ghost-gate/etc/cloudflared-config.yml ]; then
    cp "$SCRIPT_DIR/cloudflared-config.yml.template" /opt/ghost-gate/etc/cloudflared-config.yml
    chown root:root /opt/ghost-gate/etc/cloudflared-config.yml
    chmod 644 /opt/ghost-gate/etc/cloudflared-config.yml
    echo "[ok] Cloudflared config template placed"
else
    echo "[ok] Cloudflared config already exists (not overwritten)"
fi

# ── 6. Place helper scripts ─────────────────────────────────────────────────
cp "$SCRIPT_DIR/backup.sh" /opt/ghost-gate/bin/backup.sh
cp "$SCRIPT_DIR/healthcheck.sh" /opt/ghost-gate/bin/healthcheck.sh
chmod +x /opt/ghost-gate/bin/backup.sh /opt/ghost-gate/bin/healthcheck.sh
echo "[ok] Helper scripts placed"

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete. Next steps: ==="
echo ""
echo "1. Transfer the reviewed source archive, then build on this VPS with at most two jobs:"
echo "   cd /opt/ghost-gate/source/ghost-gate-staging-source-<commit>/ghost-gate-laptop && CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/var/tmp/ghost-gate-target cargo build --locked --release -j 2 -p ghost-gate-walletd -p ghost-gate-telegram -p ghost-gate-admin"
echo "   (binary names: ghost-gate-bridge, ghost-gate-telegram, ghost-gate-admin)"
echo ""
echo "2. Install the locally built Linux binaries (root-owned, mode 0755):"
echo "   install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-bridge /opt/ghost-gate/bin/ghost-gate-bridge"
echo "   install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-telegram /opt/ghost-gate/bin/ghost-gate-telegram"
echo "   install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-admin /opt/ghost-gate/bin/ghost-gate-admin"
echo ""
echo "3. Initialise the empty private admin registry over SSH; never copy laptop admin sessions, user sessions, wallets, or replay data."
echo "   systemctl start ghost-gate-admin"
echo "   # Read its one-time bootstrap token only through the SSH session/journal, then register a new admin passkey or wallet public key."
echo ""
echo "4. Edit /opt/ghost-gate/etc/ghost-gate-bridge.env and ghost-gate-telegram.env:"
echo "   - Keep staging secrets in their owning service file only"
echo "   - Set GG_BRIDGE_ORIGINS to the exact staging Worker origin"
echo "   - Set GG_JOIN_BASE_URL to the exact staging Worker origin"
echo ""
echo "5. Set up the Cloudflare tunnel:"
echo "   cloudflared tunnel login"
echo "   cloudflared tunnel create ghost-gate"
echo "   # Note the tunnel ID, update /opt/ghost-gate/etc/cloudflared-config.yml"
echo "   # Create DNS records:"
echo "   cloudflared tunnel route dns ghost-gate bridge.YOUR_DOMAIN"
echo "   cloudflared tunnel route dns ghost-gate claim.YOUR_DOMAIN"
echo ""
echo "6. Install cloudflared as a service:"
echo "   cloudflared service install --config /opt/ghost-gate/etc/cloudflared-config.yml"
echo ""
echo "7. With Cloudflare approval, deploy only the separate staging Worker configuration:"
echo "   cd cloudflare; cp wrangler.staging.toml.template wrangler.staging.toml"
echo "   wrangler deploy --config wrangler.staging.toml"
echo "   wrangler secret put --config wrangler.staging.toml GG_COORDINATOR_TOKEN"
echo "   wrangler secret put --config wrangler.staging.toml GG_VERIFIER_TOKEN"
echo "   wrangler secret put --config wrangler.staging.toml GG_VERIFIER_REQUEST_KEY"
echo "   wrangler secret put --config wrangler.staging.toml GG_VERIFIER_RESPONSE_KEY"
echo "   # Set exact staging GG_VERIFIER_ORIGIN and GG_GATE_CATALOG in the staging config"
echo ""
echo "8. Start services:"
echo "   # The admin dashboard stays private: ssh -N -L 7811:127.0.0.1:7811 USER@VPS, then open http://localhost:7811"
echo "   systemctl enable --now ghost-gate-admin"
echo "   systemctl enable --now ghost-gate-bridge"
echo "   systemctl enable --now ghost-gate-telegram"
echo ""
echo "9. Verify:"
echo "   curl -s http://127.0.0.1:7799/health"
echo "   journalctl -u ghost-gate-bridge -f"
echo "   journalctl -u ghost-gate-telegram -f"
