# Private VPS administration

`ghost-gate-admin` preserves the existing HTML dashboard and is deliberately not a Cloudflare
service. It is the only registry writer; the bridge consumes the published `bindings.json`
snapshot and the Telegram bot remains a loopback client of the bridge.

## Install after the policy-hardening commit

The VPS binaries built from `4174dc9` predate this change. Before starting any service, transfer a
source archive containing the later commit and build exactly that revision on Linux:

```bash
cd /opt/ghost-gate/source/ghost-gate-staging-source-<COMMIT>/ghost-gate-laptop
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/var/tmp/ghost-gate-target \
  cargo build --locked --release -j 2 \
  -p ghost-gate-walletd -p ghost-gate-telegram -p ghost-gate-admin
sudo install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-bridge /opt/ghost-gate/bin/
sudo install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-telegram /opt/ghost-gate/bin/
sudo install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-admin /opt/ghost-gate/bin/
```

Run `sudo /opt/ghost-gate/source/.../deploy/setup-vps.sh` once to create the accounts, the
`ghostgate-registry` sharing group, the three units, and the service-specific environment files.
It does not start services or upload secrets.

The admin unit reads only `/opt/ghost-gate/data/registry`; bridge replay data stays in
`/opt/ghost-gate/data/replays`, and bridge/Worker HMAC credentials stay in the bridge environment
file. No wallet private key, browser login session, or laptop registry is copied to the VPS.

## First private bootstrap

```bash
sudo systemctl daemon-reload
sudo systemctl start ghost-gate-admin
sudo journalctl -u ghost-gate-admin -n 50 --no-pager
```

Use the one-time bootstrap token only in the private forwarded browser session to register a new
administrator passkey or wallet **public** key. Do not paste a wallet private key into the VPS.
After the first administrator exists, the bootstrap token is void.

From an administrator workstation, keep SSH running:

```bash
ssh -N -L 7811:127.0.0.1:7811 VPS_USER@VPS_HOST
```

Then open `http://localhost:7811`. `GG_ADMIN_HOSTNAME=localhost` keeps the browser's WebAuthn
relying-party origin as localhost. Do not use the VPS IP address or a Cloudflare hostname for the
dashboard.

## Publish and Worker catalog procedure

1. Save arbitrary changes as drafts in the dashboard. They are not written to the bridge binding
   snapshot and hosted issuance fails closed while any draft is outstanding.
2. Use **Publish**. It validates the complete application, cuts v2 policy versions atomically,
   writes the registry and derived bindings, and retires sessions/challenges bound to earlier
   policy hashes.
3. Read the published binding entries in `/opt/ghost-gate/data/registry/bindings.json` over SSH.
   Use `scripts/render-worker-catalog.ps1` with that snapshot and an explicit staging
   `tenant/gate -> https origin` map to render `GG_GATE_CATALOG`; the script refuses drafts,
   non-HTTPS origins, Telegram-only gates, unsupported proof modes, and missing policy hashes.
4. Deploy the separate staging Worker only with explicit approval. Until then, a Worker catalog
   mismatch is rejected by the bridge's exact policy check; it never falls back to draft state.

For a legacy v1 registry, explicitly publish once before changing application topology, default TTL
or production trust requirements. v1 hashes remain validated with their original serialization;
they are never silently reinterpreted as v2.

The Tunnel template must continue to expose only listed bridge/claim paths and a 404 fallback.
Never route `/admin`, port 7811, walletd, diagnostics, or a wildcard bridge path through it.
