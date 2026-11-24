# Isolated non-authorizing Labs staging

This runbook records the staging boundary for the two non-authorizing privacy Labs and the exact changes that still require operator approval before any backend/origin work.

## Deployed isolated edge

- Worker name: `ghost-gate-labs-staging` (new; **not** the Worker serving `ghostgate.boo`).
- Config: `cloudflare/wrangler.labs-staging.toml` — no `[[routes]]`, no custom domain, no Durable Object binding, no secrets, no production vars.
- Public origin: `https://ghost-gate-labs-staging.gsxrspartan.workers.dev` (Cloudflare-managed HTTPS certificate).
- Generated assets: `labs-staging-web/` from `templates/labs-staging/` via `scripts/prepare-labs-staging-web.ps1`; ignored by Git.
- Routes: `/`, `/mainnet/`, `/ggbp1/`, `/labs.css`, `/labs.js`, `/lab/gates` (static draft metadata), `/_edge/health`. All proof, challenge, session, claim, bot, admin and fixture routes return 404.

## What this staging edge does and does not do

It provides public HTTPS pages for wallet capability discovery and for checking the displayed draft Crypt policy (network `0x00`, native TARI resource, illustrative 100 TARI threshold, `enabled=false`, `test_lane=true`, `chain_generation=0`) and the GGBP-1 v3 test-gate description (Esmeralda `0x26`, method names, non-authorizing status).

It does **not** run an ownership-proof backend. There is no bridge process, no indexer-backed challenge, no GGBP-1 proof verification endpoint and no session creation. A real-wallet proof observation requires the VPS staging services described below, which are **not deployed** without approval.

## Production inventory (read-only, recorded 2026-11-24)

- Production Worker serving `ghostgate.boo`: `ghost-gate-staging` (the name is historical). Latest recorded version `2c356f81-0359-4c4e-a35d-550f08073f3f`, annotation "Restore true pre-experiment production version" (2026-11-04). **Do not deploy to this Worker for staging.**
- Tunnel: `ghost-gate-staging`, id `50f00269-40fc-4b60-86ff-da2da9371eb3`, healthy, remote-managed via token file.
- VPS user/host: `ubuntu@40.160.90.9`. Services `ghost-gate-bridge`, `ghost-gate-telegram`, `ghost-gate-admin`, `cloudflared` all active.
- Production binaries (sha256): bridge `8654aee109ecbaf0e5eaa0c0575fc78010251c6bdcea64d81380ce05f70a31f8`, telegram `ee5c6cef81a2c162be7b94f8e73fede843713c7f246e50a597be5f4b1ce566a7`, admin `3ca8dadc0c75256413d2e035ec346c9a1a8d8130642865316e7059544a1fa35e`. Previous bridge version retained as `ghost-gate-bridge.4174dc9` (`8f1ae9d76c82f3f0a9f9c267403330e09e61504b91bf9f3000efdf79d890fad5`).
- Production health before staging: `https://ghostgate.boo/_edge/health` → 200 `{"service":"ghost-gate-edge","coordinator":true,"verifier":false}`; `https://bridge.ghostgate.boo/health` → 200 `{"credential_configured":true,"gates":["Crypt"],"live_challenges":0,"registry_backed":true,"xtm_configured":false}`.
- Data directories: `/opt/ghost-gate/data/{registry,replays,backups}` — never copied to staging.

## Exact changes that require approval before a functional backend can be published

1. Build `tools/m16-fixture-bridge` for Linux and install two **new** binaries under `/opt/ghost-gate-labs/bin/` (no overwrite of `/opt/ghost-gate/bin/*`).
2. Create two **new** systemd units with dedicated state directories and ports:
   - `ghost-gate-labs-mainnet.service`, bind `127.0.0.1:7798`, `GG_MAINNET_ADMISSIONS_ENABLED` unset, no `GG_BOT_KEY`, no access plane.
   - `ghost-gate-labs-ggbp1.service`, bind `127.0.0.1:7801`, `GG_GGBP1_TEST=1`, no `GG_BOT_KEY`, no `GG_BOT_AUTH_DB_DIR`.
3. Create a **new** Cloudflare Tunnel (isolated from `50f00269-…`) with ingress only for exact paths on new hostnames (for example `labs-mainnet.ghostgate.boo` and `labs-ggbp1.ghostgate.boo`) pointing at the two loopback ports. This avoids editing the production tunnel's ingress rules.
4. Add only new DNS records for those new hostnames. Do not modify existing `ghostgate.boo`, `bridge.ghostgate.boo` or `claim.ghostgate.boo` records.
5. Bind the Labs Worker to those exact new origins. Never reuse production secrets, replay namespaces or the production gate catalog.

Nothing in steps 1–5 has been applied. Publishing them without explicit approval would cross the production-ingress boundary.

## Rollback

- Static staging edge: `npx wrangler versions list --config cloudflare/wrangler.labs-staging.toml`, then `npx wrangler rollback <VERSION_ID> --config cloudflare/wrangler.labs-staging.toml`. Deleting the new Worker entirely (`npx wrangler delete ghost-gate-labs-staging`) also restores the original state because no production route points at it.
- Production Worker: `npx wrangler rollback 2c356f81-0359-4c4e-a35d-550f08073f3f --config cloudflare/wrangler.ghostgate.toml` **only if production was changed**. Do not roll back registry, replay, generation, audit or Telegram membership state.
- VPS staging services (if ever approved): `systemctl stop ghost-gate-labs-mainnet ghost-gate-labs-ggbp1`; remove the new systemd units and `/opt/ghost-gate-labs` only after confirming production services are unaffected.
