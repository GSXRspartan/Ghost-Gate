# Ghost Gate — VPS + Cloudflare Deployment Preflight

**Date:** 2026-10-27  
**Deadline:** October 31, 5 PM Pacific  
**Status:** Awaiting approval before provisioning VPS, changing DNS, deploying CF resources, or uploading secrets.

---

## Architecture

| Component | Location | Role |
|---|---|---|
| CF Worker + Durable Objects | Cloudflare edge | Public HTTPS, static assets, replay coordination |
| `ghost-gate-bridge` | VPS (127.0.0.1:7899) | Credential verification via existing Sapient Mode B path |
| `ghost-gate-telegram` | VPS (127.0.0.1:7808) | Telegram bot + claim endpoint |
| `cloudflared` | VPS | Tunnel from CF edge to bridge + claim on loopback |

**No hosted verifier binary.** The CF Worker's `trustedVerify()` calls the bridge through the Cloudflare Tunnel. The bridge IS the verifier — it runs the same `CredentialVerifier::verify` path that already works end-to-end with Sapient on Esmeralda.

**No walletd on the VPS.** Credential-only gates (Mode B) need only the indexer, not a wallet daemon. The bridge starts without `GG_WALLETD_ENDPOINT` and refuses Mode A proofs with an honest message.

---

## 1. Verification Path: CF Worker → Bridge (Requirement #1)

### Problem
The hosted verifier returns UNKNOWN. The CF Worker calls it at `POST /v1/hosted/verify` and gets `UNKNOWN` back.

### Solution: Bridge as the verifier

The bridge's credential route (`POST /gate/{g}/credential`) is a working, proven verifier. Instead of calling the hosted verifier binary, the CF Worker calls the bridge through the Cloudflare Tunnel.

**Two options for the proof flow:**

#### Option A: Worker proxies to bridge (recommended)
The CF Worker's `trustedVerify()` changes its target from the hosted verifier to the bridge. The bridge's credential route does the actual verification.

But the HMAC contract differs: the hosted verifier expects `HostedVerificationRequest` with HMAC signatures, while the bridge expects `CredentialProofRequest` without HMAC. 

**Simplest implementation:** Add a new `/v1/hosted/verify` route to the bridge that accepts the same HMAC-authenticated request the Worker already sends, unpacks it into a `CredentialProofRequest`, runs `CredentialVerifier::verify`, and returns a `HostedVerificationResult` with the same HMAC-signed response. This keeps the Worker code unchanged and adds one adapter route to the bridge.

**Code changes:**
- `crates/ghost-gate-bridge/src/server.rs` — add `Route::HostedVerify` handling the `/v1/hosted/verify` endpoint
- The route: validates bearer token, validates request HMAC, unpacks proof JSON, runs credential verification, returns HMAC-signed verdict
- Env vars: `GG_VERIFIER_TOKEN`, `GG_VERIFIER_REQUEST_KEY`, `GG_VERIFIER_RESPONSE_KEY` (same as the hosted verifier uses)
- The bridge already depends on `ghost-gate-verifier` for the HMAC functions

**Worker changes: zero.** `GG_VERIFIER_ORIGIN` points at the tunnel hostname instead of a separate verifier binary.

#### Option B: Browser talks to bridge directly
The hosted page (`hosted.js`) POSTs to the bridge through its tunnel hostname. No Worker proxy needed. But this requires the bridge's CORS and Host checks to accept the CF origin, and the proof body format differs (Worker vs bridge routes). Adds complexity to the frontend.

**Recommendation: Option A.** One new route on the bridge, zero Worker changes.

### Evidence classification
The bridge's credential path yields `EvidenceClass::IndexerAsserted` (F-04). With `GG_OPERATOR_TRUSTED_INDEXER=1`, this reaches `OperatorTrustedTestnet`. `GG_MAX_TRUST_TIER=operator-trusted-testnet` caps it there. This is the correct classification — no promotion to consensus.

---

## 2. Telegram Route Mismatch (Requirement #2)

### Problem
`claim.js` uses bridge routes (`/gate/{g}/challenge`, `/gate/{g}/credential`).  
The Worker uses Worker routes (`/api/tenants/{t}/gates/{g}/challenge`, `/api/tenants/{t}/gates/{g}/proof`).

### Solution: Telegram flow stays on the bridge

The bot mints join links pointing at the CF Worker's public URL (where `join.html` is served as a static asset). The `claim` query parameter points at the tunneled claim endpoint.

Join link format:
```
https://WORKER_DOMAIN/telegram/join?token=XXX&gate=crypt&claim=https://claim.TUNNEL_DOMAIN/claim
```

`claim.js` needs to know where the bridge is. Two options:

**Option A (minimal change):** Add a `bridge` query parameter to the join link. The bot sets it to the tunneled bridge URL. `claim.js` uses it for gate metadata, challenges, and credential proofs.

```
https://WORKER_DOMAIN/telegram/join?token=XXX&gate=crypt&claim=https://claim.DOMAIN/claim&bridge=https://bridge.DOMAIN
```

Code change in `claim.js`: replace hardcoded `/gate/${gate}` paths with `${bridgeUrl}/gate/${gate}`.

Code change in `main.rs` (Telegram bot): add the `bridge` parameter to the join link format string at line 583. Use a new env var `GG_BRIDGE_PUBLIC_URL` (the tunnel hostname).

**Option B:** `claim.js` detects whether it's on the bridge origin and falls back to a known bridge URL from the page's own config.

**Recommendation: Option A.** Explicit is safer than detection.

### Bridge CORS and Host changes
The bridge must accept:
- **Origin:** `https://WORKER_DOMAIN` (the page serving `join.html`)
- **Host:** `bridge.TUNNEL_DOMAIN` (the tunnel hostname)

`GG_BRIDGE_ORIGINS` already accepts comma-separated origins. Add the Worker domain.
The Host check (server.rs:494) matches against `permitted_hosts`. These are derived from the bind address. For a tunnel, the bridge sees `Host: bridge.TUNNEL_DOMAIN` from cloudflared, which won't match `127.0.0.1`.

**Code change needed:** Add a `GG_BRIDGE_PERMITTED_HOSTS` env var to allow additional hostnames beyond the loopback defaults. Or: cloudflared can rewrite the Host header to `127.0.0.1:7899` — check if this is configurable.

Actually, cloudflared by default passes through the original Host header. The bridge needs to accept the tunnel hostname. Checking the bridge code more carefully:

```rust
if !self.permitted_hosts.iter().any(|p| p.eq_ignore_ascii_case(&name)) {
    return Response::error(403, "GG: this bridge is bound to the loopback interface...");
}
```

`permitted_hosts` is populated from the bind address at startup. We need to add the tunnel hostname.

**Code change:** In the bridge binary (`ghost-gate-bridge.rs`), read `GG_BRIDGE_PERMITTED_HOSTS` as additional allowed hostnames. ~5 lines of code.

---

## 3. Endpoint Exposure Audit (Requirement #3)

### What's publicly accessible through the tunnel

The tunnel exposes the bridge on `bridge.TUNNEL_DOMAIN`. Every bridge route is reachable. Critical routes:

| Route | Exposed? | Risk | Mitigation |
|---|---|---|---|
| `GET /health` | Yes | **None** — service name, version, gate list |
| `GET /gate/{id}` | Yes | **None** — public gate metadata |
| `POST /gate/{id}/challenge` | Yes | **Low** — issues single-use nonces |
| `POST /gate/{id}/credential` | Yes | **Safe** — the whole point; verification only |
| `GET /proof/{id}/status` | Yes | **Low** — proof status, session-bound |
| `GET /wallet/status` | Yes | **None** — reports "unavailable" (no walletd) |
| `POST /prove` | Yes | **None** — refuses (no walletd) |
| `POST /gate/{id}/prove` | Yes | **None** — refuses (no walletd) |
| `GET /admin` | **Yes** | **MEDIUM** | Bridge serves admin HTML from its asset dir |
| `POST /admin/*` | **Yes** | **HIGH** | Admin API: publish gates, revoke sessions |
| `GET /lab/*` | Yes | **None** — Privacy Lab HTML |
| `GET /access/check` | Yes | **Low** — requires valid session cookie |

### Critical finding: Admin routes are exposed

The bridge serves the admin dashboard at `/admin` with its associated API routes. On your laptop this is fine (loopback only). Through a tunnel, anyone can reach the admin API.

**Mitigation options:**

1. **Cloudflare Access policy** on the tunnel — require authentication for `/admin*` paths. CF Access can restrict by email, IP, or service token.

2. **Bridge code change:** Add a `GG_DISABLE_ADMIN_ROUTES=1` env var that blocks all `/admin*` routes when set. The VPS deployment sets this.

3. **Separate tunnels:** Only tunnel the specific paths the Worker needs (`/v1/hosted/verify`) and the Telegram flow needs (`/gate/*`). Use cloudflared's `ingress` rules.

**Recommendation: Option 2 + 3.** Disable admin routes in the bridge binary for the VPS build, AND use narrow ingress rules in cloudflared.

### Other sensitive routes
- No walletd routes expose anything (walletd is not connected)
- No diagnostic routes exist beyond `/health`
- The bridge never serves secrets, tokens, or keys through any route

---

## 4. Tunnel Protection (Requirement #4)

### Tunnel security layers

1. **Cloudflare Tunnel encryption** — traffic from CF edge to VPS is encrypted through the tunnel
2. **Bridge HMAC authentication** — the `/v1/hosted/verify` route (if added per §1) validates bearer token + request HMAC before processing
3. **Origin allowlist** — bridge checks `GG_BRIDGE_ORIGINS` before any route
4. **Host allowlist** — bridge checks the Host header
5. **Loopback binding** — bridge binds 127.0.0.1 only; not reachable except through the tunnel

### Additional hardening

- **Cloudflare Access** on the bridge tunnel hostname — restrict to CF Worker service token only (the Worker is the only caller that needs the bridge tunnel)
- **UFW firewall** on the VPS — only allow SSH (22) and cloudflared's outbound connections. Block all inbound except SSH.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable
```

No inbound ports need to be open — cloudflared initiates outbound connections to CF edge.

---

## 5. Telegram Bot (Requirement #5)

The Telegram bot runs **unchanged** on the VPS. Same binary, same env vars, same behavior.

Changes from the local setup:
- `GG_JOIN_BASE_URL` → the CF Worker's public HTTPS URL (where join.html is served)
- `GG_BRIDGE_ENDPOINT` stays `http://127.0.0.1:7899` (bridge is on the same VPS)
- The claim endpoint (`127.0.0.1:7808`) is tunneled to `claim.TUNNEL_DOMAIN`

The bot needs one additional env var for the `bridge` query parameter in join links (see §2):
- `GG_BRIDGE_PUBLIC_URL=https://bridge.TUNNEL_DOMAIN`

---

## 6. Staging Isolation (Requirement #6)

| Item | Your laptop | VPS |
|---|---|---|
| Bridge binary | `_cargo-target-native/release/ghost-gate-bridge.exe` | `/opt/ghost-gate/bin/ghost-gate-bridge` (Linux) |
| Bridge state | `<local Ghost Gate admin directory>` | `/opt/ghost-gate/data/registry/` (copy) |
| Replay store | bridge-local memory store | `/opt/ghost-gate/data/replays/` (durable files) |
| Telegram bot | `ghost-gate-telegram.exe` | `/opt/ghost-gate/bin/ghost-gate-telegram` |
| Env vars | PowerShell session | `/opt/ghost-gate/etc/ghost-gate.env` |
| CF Worker | Not deployed | `wrangler deploy` to CF edge |
| Secrets | Local env vars | Separate CF Worker secrets + VPS env file |

The VPS is a completely separate deployment. Your laptop's local demo continues unchanged.

---

## 7. Web Tari Universe (Requirement #7)

The CF Worker serves `hosted.html` at `https://WORKER_DOMAIN/`. Universe embeds it in an iframe over HTTPS. `hosted.html` loads Tari's official connector URL. `hosted.js` imports `universeProvider`.

**Remaining work:** `hosted.js` currently shows an "unavailable" warning and doesn't submit proofs. It needs a proof submission flow that:
1. Requests a challenge from the Worker (`POST /api/tenants/default/gates/crypt/challenge`)
2. Calls the wallet to create the proof output and sign the challenge
3. Packs the proof into `{ nonce, proof: { substate_id, public_key, public_nonce, signature, session_commitment } }`
4. Submits to the Worker (`POST /api/tenants/default/gates/crypt/proof`)

This is a JS-only change in `hosted.js`, modeling the same flow `claim.js` already implements.

---

## Required Code Changes (Minimum)

### Bridge (Rust)

1. **Add `/v1/hosted/verify` route** to `server.rs` — adapter from the hosted verifier HMAC contract to `CredentialVerifier::verify`. ~80 lines. Reads `GG_VERIFIER_TOKEN`, `GG_VERIFIER_REQUEST_KEY`, `GG_VERIFIER_RESPONSE_KEY` from env.

2. **Add `GG_BRIDGE_PERMITTED_HOSTS`** to the bridge binary — comma-separated additional hostnames accepted in the Host header. ~5 lines in `ghost-gate-bridge.rs`.

3. **Add `GG_DISABLE_ADMIN_ROUTES`** — when set, block all `/admin*` routes with 404. ~10 lines in `server.rs`.

### Telegram bot (Rust)

4. **Add `bridge` parameter to join links** — read `GG_BRIDGE_PUBLIC_URL` env var, append `&bridge=URL` to the join link format string at line 583. ~5 lines.

### Frontend (JS)

5. **`claim.js`** — read `bridge` query parameter, use it as the base URL for gate metadata, challenge, and credential requests. ~15 lines changed.

6. **`hosted.js`** — add proof submission flow (challenge → wallet → proof POST). ~60 lines added. Remove the "unavailable" warning.

### Worker (JS)

7. **Zero changes.** `GG_VERIFIER_ORIGIN` points at the tunnel hostname. The bridge speaks the same HMAC contract the hosted verifier did.

### Total: ~175 lines of code changes across 5 files.

---

## Deployment Files

See `deploy/` directory:
- `setup-vps.sh` — VPS provisioning script
- `ghost-gate-bridge.service` — systemd unit
- `ghost-gate-telegram.service` — systemd unit
- `ghost-gate.env.template` — environment configuration
- `cloudflared-config.yml.template` — tunnel configuration
- `backup.sh` — daily backup script
- `healthcheck.sh` — service monitoring

---

## Ordered Deployment Steps

### Phase 1: Code changes (before any deployment)
1. Implement the 6 code changes listed above
2. Run existing tests: `CARGO_TARGET_DIR=_cargo-target-native cargo test -p ghost-gate-bridge --lib`
3. Cross-compile for Linux x86_64
4. Test locally: bridge with new route, claim.js with bridge parameter

### Phase 2: VPS setup (requires your approval)
5. Provision OVHcloud VPS-1 (~$7/mo)
6. Run `setup-vps.sh` on the VPS
7. Upload Linux binaries via scp
8. Copy registry data from laptop
9. Edit `/opt/ghost-gate/etc/ghost-gate.env` with real values

### Phase 3: Tunnel + CF Worker (requires your approval)
10. `cloudflared tunnel login` on VPS
11. `cloudflared tunnel create ghost-gate`
12. Set up DNS records for tunnel hostnames
13. Deploy CF Worker: `wrangler deploy`
14. Set CF Worker secrets
15. Set `GG_VERIFIER_ORIGIN`, `GG_GATE_CATALOG` in Worker config

### Phase 4: Go live
16. Start services: `systemctl enable --now ghost-gate-bridge ghost-gate-telegram`
17. Start tunnel: `systemctl enable --now cloudflared`
18. Verify: health checks, Telegram join flow, Universe embedding
19. Set up daily backup cron
20. Monitor via `journalctl` and healthcheck script

---

## Cross-Compilation Notes

The bridge depends on `tari_crypto` (Ristretto curve operations). Cross-compiling from Windows to Linux x86_64 requires:
- Rust target: `rustup target add x86_64-unknown-linux-gnu`
- A Linux cross-compilation toolchain (e.g., `x86_64-linux-gnu-gcc`)
- Or: build on the VPS itself (simpler, needs Rust + build deps)

**Recommendation:** Build on the VPS. It has 2 cores / 4 GB RAM, enough for a release build. Install Rust + build dependencies as part of setup. This avoids cross-compilation complexity entirely.

```bash
# On the VPS:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
apt-get install -y build-essential pkg-config libssl-dev
# Clone the repo, build:
CARGO_TARGET_DIR=/tmp/gg-build cargo build --release -p ghost-gate-walletd -p ghost-gate-telegram
cp /tmp/gg-build/release/ghost-gate-bridge /opt/ghost-gate/bin/
cp /tmp/gg-build/release/ghost-gate-telegram /opt/ghost-gate/bin/
```

Note: the workspace has some crates that don't build (`randomx-rs` CMake dependency). The bridge and telegram binaries build independently of those.

---

## Risk Assessment

| Risk | Impact | Mitigation |
|---|---|---|
| Bridge admin routes exposed | HIGH | `GG_DISABLE_ADMIN_ROUTES=1` + CF Access |
| Tunnel hostname discovered | LOW | Bearer + HMAC auth on `/v1/hosted/verify`; origin check on all routes |
| VPS compromise | HIGH | No wallet seeds or private keys on the VPS; only public gate policy |
| Indexer downtime | MEDIUM | Bridge refuses proofs (fail-closed), does not serve stale data |
| CF Worker misconfiguration | MEDIUM | Worker fails closed without verifier secrets |
| Bridge crash | LOW | systemd auto-restart within 5 seconds |

---

## What This Does NOT Change

- Your local demo setup (bridge on 127.0.0.1:7899, Telegram on 7808)
- The admin dashboard or registry configuration workflow
- Wallet seeds, private keys, or wallet profiles
- Trust tier classification (stays OperatorTrustedTestnet)
- The Phase 2A trust-tier code
- Any on-chain state or deployments
