# Ghost Gate VPS Deployment

Target: OVHcloud VPS-1 (2 vCores / 4 GB RAM, Ubuntu 24.04 LTS)

## Architecture

```
  Browser / Universe         Cloudflare Edge           VPS (OVHcloud)
  ──────────────────    ──────────────────────    ──────────────────────
  hosted.html (CF)  ──> CF Worker + Durable Obj
                            │ proof route           cloudflared tunnel
                            │ trustedVerify()  ───> 127.0.0.1:7799 (bridge)
                            │                         ├── credential verifier
                            │                         ├── challenge book
                            │                         └── access plane
  join.html (CF)    ──> challenge + credential
                        via bridge tunnel      ───> 127.0.0.1:7799 (bridge)
                        claim POST             ───> 127.0.0.1:7808 (telegram)
                                                      └── long-polls Telegram API
```

Two binaries on the VPS:
- `ghost-gate-bridge` — the existing bridge with credential verification (Mode B)
- `ghost-gate-telegram` — the Telegram bot with claim endpoint

The CF Worker handles:
- Static asset serving (web/ directory)
- Durable Object replay coordination
- Proof requests proxied to bridge through Cloudflare Tunnel

No walletd, no admin dashboard, no hosted verifier binary on the VPS.
The bridge's own credential verification path (proven with Sapient on Esmeralda) is the verifier.

## Files in this directory

- `ghost-gate-bridge.service` — systemd unit for the bridge
- `ghost-gate-telegram.service` — systemd unit for the Telegram bot
- `ghost-gate-bridge.env.template` — bridge-only environment variables and verifier placeholders
- `ghost-gate-telegram.env.template` — Telegram-only environment variables and bot-token placeholder
- `setup-vps.sh` — deployment script for a fresh Ubuntu 24.04 VPS
- `backup.sh` — backup script for persistent state
- `healthcheck.sh` — basic health monitoring
