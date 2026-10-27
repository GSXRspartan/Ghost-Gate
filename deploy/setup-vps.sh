#!/usr/bin/env bash
# Ghost Gate VPS setup — Ubuntu 24.04 LTS
# Run as root on a fresh VPS. Stops before starting services.
#
# What this script does:
#   1. Creates a ghostgate system user
#   2. Creates the directory structure
#   3. Installs cloudflared
#   4. Places systemd units
#   5. Prints next steps (binary upload, secrets, tunnel setup)
#
# What this script does NOT do:
#   - Upload binaries (you scp them)
#   - Set secrets (you edit ghost-gate.env)
#   - Create the Cloudflare tunnel (you run cloudflared tunnel login)
#   - Start any services (you do that after verification)

set -euo pipefail

echo "=== Ghost Gate VPS Setup ==="
echo ""

# ── 1. System user ──────────────────────────────────────────────────────────
if ! id -u ghostgate >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --home-dir /opt/ghost-gate ghostgate
    echo "[ok] Created system user: ghostgate"
else
    echo "[ok] User ghostgate already exists"
fi

# ── 2. Directory structure ──────────────────────────────────────────────────
mkdir -p /opt/ghost-gate/{bin,etc,data/{registry,replays,backups}}

# Binaries: owned by root, executable
chown root:root /opt/ghost-gate/bin
chmod 755 /opt/ghost-gate/bin

# Config: readable by ghostgate, writable only by root
chown root:ghostgate /opt/ghost-gate/etc
chmod 750 /opt/ghost-gate/etc

# Data: writable by ghostgate (sessions, replays, registry state)
chown -R ghostgate:ghostgate /opt/ghost-gate/data
chmod -R 750 /opt/ghost-gate/data

echo "[ok] Directory structure created at /opt/ghost-gate/"
echo "     bin/       — ghost-gate-bridge, ghost-gate-telegram"
echo "     etc/       — ghost-gate.env, cloudflared config"
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
systemctl daemon-reload
echo "[ok] systemd units installed"

# ── 5. Place config templates ───────────────────────────────────────────────
if [ ! -f /opt/ghost-gate/etc/ghost-gate.env ]; then
    cp "$SCRIPT_DIR/ghost-gate.env.template" /opt/ghost-gate/etc/ghost-gate.env
    chown root:ghostgate /opt/ghost-gate/etc/ghost-gate.env
    chmod 640 /opt/ghost-gate/etc/ghost-gate.env
    echo "[ok] Environment template placed at /opt/ghost-gate/etc/ghost-gate.env"
    echo "     EDIT THIS FILE — replace all placeholder values"
else
    echo "[ok] /opt/ghost-gate/etc/ghost-gate.env already exists (not overwritten)"
fi

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
echo "1. Cross-compile the binaries on your dev machine:"
echo "   CARGO_TARGET_DIR=_cargo-target-native cargo build --release --target x86_64-unknown-linux-gnu -p ghost-gate-walletd -p ghost-gate-telegram"
echo "   (binary names: ghost-gate-bridge, ghost-gate-telegram)"
echo ""
echo "2. Upload binaries to the VPS:"
echo "   scp _cargo-target-native/x86_64-unknown-linux-gnu/release/ghost-gate-bridge root@VPS:/opt/ghost-gate/bin/"
echo "   scp _cargo-target-native/x86_64-unknown-linux-gnu/release/ghost-gate-telegram root@VPS:/opt/ghost-gate/bin/"
echo "   chmod 755 /opt/ghost-gate/bin/ghost-gate-{bridge,telegram}"
echo ""
echo "3. Copy the registry data from your laptop:"
echo "   scp -r C:\\Users\\pdark\\ghost-gate-admin\\* root@VPS:/opt/ghost-gate/data/registry/"
echo "   chown -R ghostgate:ghostgate /opt/ghost-gate/data/registry"
echo ""
echo "4. Edit /opt/ghost-gate/etc/ghost-gate.env:"
echo "   - Set GG_TG_BOT_TOKEN (from your secure storage)"
echo "   - Set GG_BRIDGE_ORIGINS to your actual CF Worker + tunnel domains"
echo "   - Set GG_JOIN_BASE_URL to your CF Worker's public URL"
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
echo "7. Deploy the CF Worker:"
echo "   cd cloudflare && wrangler deploy"
echo "   wrangler secret put GG_COORDINATOR_TOKEN"
echo "   wrangler secret put GG_VERIFIER_TOKEN"
echo "   wrangler secret put GG_VERIFIER_REQUEST_KEY"
echo "   wrangler secret put GG_VERIFIER_RESPONSE_KEY"
echo "   # Set GG_VERIFIER_ORIGIN to https://bridge.YOUR_DOMAIN"
echo "   # Set GG_GATE_CATALOG in wrangler.toml [vars]"
echo ""
echo "8. Start services:"
echo "   systemctl enable --now ghost-gate-bridge"
echo "   systemctl enable --now ghost-gate-telegram"
echo ""
echo "9. Verify:"
echo "   curl -s http://127.0.0.1:7899/health"
echo "   journalctl -u ghost-gate-bridge -f"
echo "   journalctl -u ghost-gate-telegram -f"
