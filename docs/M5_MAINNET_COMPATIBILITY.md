# Ghost Gate M5 — Mainnet Compatibility and /mainnet Deliverable

**Date:** 2026-11-10  
**Baseline:** `27c806b` (HEAD) + three untracked docs + four new M5 files  
**Ootle latest (verified):** v0.52.0, released 2026-11-09  
**Ghost Gate cohort:** v0.42.0 (upgrade required before mainnet admissions)

---

## Phase 1 — Tari Ootle release audit

### Latest release status

| Release | Date | Mainnet-relevant |
|---------|------|-----------------|
| v0.42.0 | (current cohort) | Ghost Gate base |
| v0.48.0 | pre-Nov | **sr25519 signing** — wallets, SDKs, ootle-go, ootle-py, ootle.ts, Ledger must all upgrade |
| v0.49.2 | pre-Nov | Fleet-wide reset; testnet state wiped; batch cache bounds |
| v0.50.0 | pre-Nov | **Template V2** (`tari_template_lib ≥ 0.38`); MainNet genesis council key ships in binary; indexer indexes burnt UTXO substates |
| v0.50.1 | pre-Nov | Patch; v0.50.0 wallets must run this before Esmeralda epoch 12951 (Protocol V1 activation ~2026-11-08 07:00 UTC) |
| v0.51.0 | pre-Nov | `fee_claim_public_key` requirement; walletd permission changes |
| v0.52.0 | 2026-11-09 | **ClaimBurn→revealed TARI bucket** (validators+wallets upgrade together); consensus fix (`update_in_place`); _does not affect Ghost Gate_ (ClaimBurn unused) |
| v0.53.0 | (PR open) | ootle.ts upgrade target; not yet released |

**Nothing newer than v0.52.0 found.** The M5 prompt identified v0.52.0 as the latest; this is confirmed.

### Protocol V1 activation
Esmeralda Protocol V1 activated around 2026-11-08 07:00 UTC (epoch 12951). All Esmeralda nodes must run ≥ v0.50.1. The Ghost Gate walletd demo was pinned to v0.47.0; a fresh Esmeralda demo now requires v0.50.1 or later.

### Mainnet launch status
As of 2026-11-04, lobby.tari.com stated "mainnet burns are allowed but cannot yet be claimed because Ootle mainnet is not running." The v0.52.0 release includes mainnet binary settings (genesis council key). Mainnet TARI resource addresses and indexer endpoints have **not** been published at the time of this writing.

---

## Phase 2 — Wallet integration audit

### Sapient (Ootle L2 / TARI)

| Item | Status | Notes |
|------|--------|-------|
| Browser extension | functional (Esmeralda) | needs mainnet account after mainnet launch |
| `tari-dapp-bridge/1` protocol | compatible | confirmed in WEB_UNIVERSE_DAPP_FAILURE investigation |
| Credential proof mode | functional path | single-output substate commitment |
| Mainnet network byte | 0x00 | confirmed from ootle.ts `Network.MainNet = 0x00` |
| sr25519 signing (v0.48) | **breaking** vs v0.42 cohort | requires cohort upgrade |
| Template V2 (v0.50) | **breaking** vs v0.42 cohort | requires template rebuild |
| Mainnet resource address | **unknown** | not yet published by Tari Labs |

### Tari Universe / Web TU (Minotari L1 / XTM)

| Item | Status | Notes |
|------|--------|-------|
| Latest version | v1.6.23 (tari-ootle v0.52.0) | |
| dApp bridge protocol | compatible | `tari-dapp-bridge/1` matches Ghost Gate connector |
| COEP iframe embedding | allowed | Ghost Gate worker sets correct cross-origin headers for lab |
| GGBP-1 L1 proof API | **BLOCKED** | `ggbp1BalanceProof` capability explicitly disabled; no live L1 proof API |
| L2 Ootle account | needs fresh account | testnet reset wipes existing; mainnet requires funded account |
| XTM L1 mobile | out of scope | separate XTM workstream |

### walletd (local daemon)

| Item | Status | Notes |
|------|--------|-------|
| Last tested binary | v0.47.0 (Esmeralda demo) | needs upgrade to ≥ v0.50.1 |
| Mainnet binary | not yet published | pending Tari Labs mainnet release |
| Mainnet indexer URL | not yet published | ootle.ts `defaultIndexerUrl` throws for mainnet |
| Auth token bootstrap | functional | bridge bootstraps its own token |

---

## Phase 3 — Network configuration separation

### New constants (`cloudflare/src/contracts.js`)

```javascript
export const NETWORK_MAINNET = 0;        // Ootle mainnet (0x00)
export const NETWORK_ESMERALDA = 38;     // Esmeralda testnet (0x26)
export function isMainnetGate(gate) { return gate.network === NETWORK_MAINNET; }
export function mainnetAdmissionsEnabled(env) {
  return env.GG_MAINNET_ADMISSIONS_ENABLED === "1";
}
```

### Admission guard (`cloudflare/src/worker.js`)

A belt-and-suspenders check runs before any challenge or proof handler for mainnet gates:
```javascript
if (isMainnetGate(gate) && !mainnetAdmissionsEnabled(env)) {
  return failClosed("mainnet admissions are not yet enabled — this is a preview deployment");
}
```

This means:
- Even if a mainnet gate is added to `GG_GATE_CATALOG`, challenges and proofs fail closed until `GG_MAINNET_ADMISSIONS_ENABLED=1` is explicitly set by the operator.
- Testnet gates (network ≠ 0) bypass this guard entirely.
- Testnet proofs cannot be replayed to mainnet: each binding carries `network`, `resourceAddress`, `gateId`, and `policyVersion`, all of which differ between networks.

### Environment variables needed for mainnet activation

| Variable | Description | Status |
|----------|-------------|--------|
| `GG_GATE_CATALOG` (mainnet entry) | JSON array with mainnet gate, `network: 0`, real resource address | BLOCKED — resource address unknown |
| `GG_MAINNET_ADMISSIONS_ENABLED` | Must be `"1"` to enable mainnet challenges | Do not set until all blockers resolved |
| `GG_VERIFIER_ORIGIN` | Mainnet bridge URL | PENDING — mainnet bridge not deployed |
| `GG_VERIFIER_TOKEN` | Bearer token for bridge | PENDING |
| `GG_VERIFIER_REQUEST_KEY` | HMAC request signing key | PENDING |
| `GG_VERIFIER_RESPONSE_KEY` | HMAC response verification key | PENDING |

---

## Phase 4 — /mainnet page

### Files created

| File | Description |
|------|-------------|
| `web/mainnet/index.html` | Full polished mainnet preview page |
| `web/mainnet/mainnet.css` | Mainnet-specific styling (black/gold/neon) |
| `web/mainnet/mainnet.js` | Minimal JS: network detection, status pills, no admission calls |

### Design
- Background: near-black (`#07090a`) with warm gold radial gradient
- Primary accent: gold (`#c8a24e`) for mainnet identity
- Status pills: gold for network byte, amber for preview/disabled states
- Preserves Ghost Gate visual language from existing lab page
- Responsive grid: two columns (Ootle L2 / Minotari L1) collapsing to single column on mobile
- Prominent "MAINNET PREVIEW — ADMISSIONS NOT YET ENABLED" sticky banner
- Navigation: `← TEST LAB` link back to `/lab`

### Admission state
The page is served in permanent preview mode until the operator removes the banner and enables the admission flow. The JS never calls `/challenge`, `/proof`, or any credential API. No wallet connection is requested.

---

## Phase 5 — Cloudflare routing

### Change to `cloudflare/src/worker.js`

Added before the general asset fallback:
```javascript
if (parsed.pathname === "/mainnet" || parsed.pathname === "/mainnet/") {
  return hardenedAsset(await env.ASSETS.fetch(new Request(new URL("/mainnet/", request.url), request)));
}
```

The route:
- Returns a `200` for `/mainnet` and `/mainnet/` (Cloudflare Assets canonical redirect is absorbed internally)
- Applies `hardenedAsset` headers (`referrer-policy: no-referrer`, `x-content-type-options: nosniff`)
- Does NOT apply COEP headers (mainnet page is not embeddable in a wallet frame)
- Does NOT require any secrets or bridge configuration
- Does NOT affect any existing route

### No other Cloudflare changes required
The existing wrangler.toml already declares `../web` as the ASSETS directory and `run_worker_first = true`. The `web/mainnet/` directory will be served by the existing assets binding once deployed.

### Routing plan
No DNS, Tunnel, or Worker changes beyond the one-line route addition. The mainnet page deploys as a static asset alongside the existing lab page. Deployment requires only `wrangler deploy` (with explicit authorization from the operator).

---

## Phase 6 — Test results

**Test run: 2026-11-10**
```
node --test cloudflare/test/*.test.js
pass 86  fail 0
```

New test file `cloudflare/test/mainnet-page.test.js` adds 30 assertions across all 12 M5 test items:

| Item | Tests | Result |
|------|-------|--------|
| 1. Esmeralda routes unchanged | 1a, 1b, 1c, 1d | PASS |
| 2. /mainnet renders correctly | 2a, 2b, 2c, 2d | PASS |
| 3. No cross-contamination | 3a, 3b, 3c, 3d | PASS |
| 4. Wrong-network rejection | 4a, 4b | PASS |
| 5. Provider failures | 5a | PASS |
| 6. Unknown resources fail closed | 6a, 6b | PASS |
| 7. Testnet cannot authorize mainnet | 7a, 7b, 7c | PASS |
| 8. No browser Telegram auth | 8a, 8b | PASS |
| 9. Mainnet admission disabled | 9a, 9b, 9c | PASS |
| 10. No auto Telegram removal | 10a | PASS |
| 11. Existing tests pass | 11a, 11b, 11c | PASS |
| 12. Static route, no bot restart | 12a, 12b | PASS |

Tests requiring a live mainnet: **none** (all tests use isolated fixtures or static assertions).

---

## Phase 7 — Deliverables summary

### Files changed
- `cloudflare/src/contracts.js` — added `NETWORK_MAINNET`, `NETWORK_ESMERALDA`, `isMainnetGate`, `mainnetAdmissionsEnabled`
- `cloudflare/src/worker.js` — added `/mainnet` route + mainnet admission guard
- `web/mainnet/index.html` — new mainnet preview page
- `web/mainnet/mainnet.css` — mainnet-specific styles
- `web/mainnet/mainnet.js` — minimal client script
- `cloudflare/test/mainnet-page.test.js` — 30 new test assertions
- `docs/M5_MAINNET_COMPATIBILITY.md` — this document

### Version / dependency inventory (current)

| Component | Current | Required for mainnet |
|-----------|---------|---------------------|
| Ootle cohort | v0.42.0 | v0.52.0 |
| tari_template_lib | 0.33.0 | ≥ 0.38 |
| walletd binary | v0.47.0 (demo) | ≥ v0.50.1 (mainnet TBD) |
| ootle.ts | (unused directly) | v0.14.0+ for mainnet Network enum |
| Cloudflare compatibility_date | 2026-10-23 | no change needed |

### Required before mainnet goes live

1. Publish `_ootle-v052-ghost-gate` reference tree (checkout v0.52.0 + wallet-mvp patch)
2. Update Cargo.toml cohort paths to `_ootle-v052-ghost-gate`
3. Rebuild ghost_gate template against `tari_template_lib 0.38`
4. Update walletd client types for v0.51+ `fee_claim_public_key` and permission changes
5. Confirm sr25519 signing round-trip with Sapient mainnet extension
6. Obtain and configure mainnet TARI resource address (from Tari Labs post-launch)
7. Configure mainnet indexer and walletd endpoints
8. Resolve M3 High security findings (identity binding, restart recovery, admin isolation)
9. Run full test suite against v0.52 cohort
10. Run isolated end-to-end admission test with real mainnet credentials

### Deployment instructions (when authorized)
```
# 1. Ensure wrangler is authenticated
wrangler whoami

# 2. Deploy the preview page (no secrets needed; preview only)
cd cloudflare
wrangler deploy --config wrangler.toml

# 3. Verify
curl -si https://ghostgate.boo/mainnet | head -5
# Expected: HTTP/2 200, referrer-policy: no-referrer, x-content-type-options: nosniff

# 4. Confirm lab still works
curl -si https://ghostgate.boo/ | grep cross-origin-embedder-policy
# Expected: require-corp
```

### Rollback instructions
```
# The /mainnet route is additive. Rolling back = redeploying the previous worker version.
# The lab, bridge API, and Telegram routes are unchanged. No data migration.
wrangler rollback  # reverts to the previously deployed version
```

---

## GO / NO-GO

| Stage | Decision | Rationale |
|-------|----------|-----------|
| Publish `/mainnet` preview page | **GO** | Static, admissions disabled, no live admission path |
| Cloudflare deploy of preview page | **PENDING** — awaiting explicit operator authorization | Routing is prepared; deployment requires deliberate action |
| Enable mainnet credential verification | **NO-GO** | Cohort upgrade incomplete; mainnet resource address unknown; mainnet indexer unknown |
| Enable mainnet Telegram admission | **NO-GO** | M3 High findings unresolved; no live end-to-end mainnet test |

---

*No production deployments, live Telegram mutations, Cloudflare secret rotations, or mainnet transactions were performed in this M5 work.*
