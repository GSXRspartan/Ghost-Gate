# Isolated non-authorizing Labs staging

This runbook records the staging boundary, the deployed components, and the single remaining blocker (new DNS records) for the two non-authorizing privacy Labs.

## Public staging edge (live)

- Worker name: `ghost-gate-labs-staging` (new; **not** the Worker serving `ghostgate.boo`).
- Config: `cloudflare/wrangler.labs-staging.toml` — no `[[routes]]`, no custom domain, no Durable Object binding, no secrets, no production vars.
- Public HTTPS origin: `https://ghost-gate-labs-staging.gsxrspartan.workers.dev` (Cloudflare certificate).
- Current version id: `c85060fb-8cfb-43c4-9d10-a09086ea42b1` (temporary `_edge/probe` route removed; it returned 404 after redeploy).
- Generated assets: `labs-staging-web/` from `templates/labs-staging/` via `scripts/prepare-labs-staging-web.ps1`; ignored by Git.
- Routes: `/`, `/mainnet/`, `/ggbp1/`, `/labs.css`, `/labs.js`, `/lab/gates` (static draft metadata), `/_edge/health`. All proof, challenge, session, claim, bot, admin and fixture routes return 404.
- Verified: all positive routes 200; `/v1/*`, `/proof/*`, `/claim`, `/admin/*`, `/lab/challenge|proof|session`, `/fixture/*` all 404.

## Isolated VPS staging backends (live, not yet publicly routed)

Built from `tools/m16-fixture-bridge` for Linux in WSL; installed only under `/opt/ghost-gate-labs/` (production `/opt/ghost-gate/` untouched).

- `ghost-gate-labs-mainnet.service` — `127.0.0.1:7798`; gate `Crypt`, network `0x00`, native TARI resource, `100000000` raw (100 TARI), real mainnet indexer; no `GG_BOT_KEY`, no access plane, `GG_MAINNET_ADMISSIONS_ENABLED` unset, GGBP-1 disabled.
- `ghost-gate-labs-ggbp1.service` — `127.0.0.1:7801`; gates `ggbp1lab` and `ggbp1xtm` (`proofMode: "xtm"`, Esmeralda `0x26`, GGBP-1 v3); `GG_GGBP1_TEST=1`, no bot key, no auth DB.
- Both report `sessionsAvailable: false`; the GGBP-1 gate reports `ggbp1TestAvailable: true` and `activatable: false`. No route can issue a session.
- Logs: `/opt/ghost-gate-labs/logs`; state: `/opt/ghost-gate-labs/data`; no production database copied.

Local health after start:

- `127.0.0.1:7798/health` → `{"gates":["Crypt"],"ggbp1_test_configured":false,"live_challenges":0,"sessionsAvailable":false}`
- `127.0.0.1:7801/health` → `{"gates":["ggbp1lab","ggbp1xtm"],"ggbp1_test_configured":true,"live_challenges":0}`

## New isolated tunnels (live)

- `ghost-gate-labs` — id `30f709ca-6936-4927-9931-c4e88f06687f` → mainnet port `7798`.
- `ghost-gate-labs-ggbp1` — id `37946028-c85e-499a-b2cf-e87133c8502d` → GGBP-1 port `7801`.
- Both healthy; both configured with path-only ingress allowlists ending in `http_status:404`. Allowed paths are only `/health`, `/wallet/status`, `/lab(/gates|/trace|/lab.css|/lab.js|/technical-state.js|/wallet-connection-state.js|/gate-list.js)`, `/gate/<id>/(challenge|prove|credential)`, `/proof/<id>/status` (plus `/gate/<id>/ggbp1/(challenge|verify)` on the GGBP-1 tunnel), the Lab's shared JS/vendor assets and the mainnet assets. No bot, claim, admin, session or fixture path is routed.
- Production tunnel `50f00269-40fc-4b60-86ff-da2da9371eb3` was not modified.

## Public hostnames (created by the operator, verified 2026-11-24)

| Type | Name | Target | Proxied |
| --- | --- | --- | --- |
| CNAME | `labs-mainnet.ghostgate.boo` | `30f709ca-6936-4927-9931-c4e88f06687f.cfargotunnel.com` | yes |
| CNAME | `labs-ggbp1.ghostgate.boo` | `37946028-c85e-499a-b2cf-e87133c8502d.cfargotunnel.com` | yes |

No production DNS record was modified. The earlier DNS-write blocker was resolved by the operator creating these two new records manually; `scripts/create-labs-dns.ps1` remains as an idempotent helper that refuses to overwrite existing records.

### Fix applied to the new tunnels only

Initially every public request returned 403 from the bridge's DNS-rebinding Host check: the tunnel forwarded `Host: labs-*.ghostgate.boo`, while the loopback bridge accepts only 127.0.0.1/localhost. `originRequest.httpHostHeader = "127.0.0.1"` was added to every allowlisted ingress rule on **both new tunnels** (the same pattern the production tunnel uses for `/claim`). The production tunnel `50f00269-…` was not changed. After the fix all six public endpoints returned 200.

The staging-only Worker templates were also updated to link to the two hosted Labs; the static pages remain capability-discovery previews and issue no proof request.

## Production inventory and health (2026-11-24)

- Production Worker serving `ghostgate.boo`: `ghost-gate-staging` (historical name). Latest version `2c356f81-0359-4c4e-a35d-550f08073f3f` ("Restore true pre-experiment production version"). Never deploy staging to it.
- Services `ghost-gate-bridge`, `ghost-gate-telegram`, `ghost-gate-admin`, `cloudflared` remained active throughout.
- Before: `https://ghostgate.boo/_edge/health` → 200 `{"service":"ghost-gate-edge","coordinator":true,"verifier":false}`; bridge → 200 `registry_backed:true`, `gates:["Crypt"]`.
- After: same responses. No production service was restarted or replaced; no production database, replay or membership record was read or written by staging.
- Production binaries (sha256): bridge `8654aee109ecbaf0e5eaa0c0575fc78010251c6bdcea64d81380ce05f70a31f8`, telegram `ee5c6cef81a2c162be7b94f8e73fede843713c7f246e50a597be5f4b1ce566a7`, admin `3ca8dadc0c75256413d2e035ec346c9a1a8d8130642865316e7059544a1fa35e`.

## Rollback

- Static staging Worker: `npx wrangler rollback <VERSION_ID> --config cloudflare/wrangler.labs-staging.toml`; previous known-good version `8b3c3074-9650-4a14-a9d6-c46f8097036e`.
- VPS staging services: `sudo systemctl disable --now ghost-gate-labs-mainnet ghost-gate-labs-ggbp1 ghost-gate-labs-tunnel-mainnet ghost-gate-labs-tunnel-ggbp1`, then remove `/etc/systemd/system/ghost-gate-labs-*.service` and `/opt/ghost-gate-labs` after confirming production services are healthy. No production service is a dependency.
- Tunnels: `npx wrangler tunnel delete <id>` for either new id; production tunnel id `50f00269-…` must never be deleted.
- Production Worker rollback is only relevant if production was changed (it was not): version `2c356f81-0359-4c4e-a35d-550f08073f3f`. Never roll back registry, replay, generation, audit or Telegram membership state.
