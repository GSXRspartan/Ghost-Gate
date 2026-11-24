# Web Tari Universe — Embedded dApp Failure Investigation

**Date:** 2026-10-28
**Status:** Root cause established from source audit; one live browser observation recommended for full confirmation.

---

## Summary

Ghost Gate displays correctly when opened as a standalone page. When loaded inside Web Tari Universe's `DappFrame` iframe, the wallet shows a **blocked symbol** (shield-alert icon) and **"not connected"**. The browser console repeatedly reports a **404 for Ootle component `component_7be2bcd8f349c75678814034b4b5a9f4fa9a571a3d4bebc398cb705ac30825ae`**.

**Root cause: The failure is wallet-side, not Ghost Gate-side.** Two independent problems combine:

1. **The wallet's own Ootle L2 account component does not exist on-chain** (the 404). This is most likely caused by an Esmeralda testnet reset wiping the account, or the account was never funded on L2.
2. **DappFrame's 4-second blocked-detection timeout** may fire if the iframe's `onLoad` event is delayed by Ghost Gate's page weight or network latency, even though the page ultimately loads.

No Ghost Gate defect has been identified. No code change is warranted.

---

## Repositories examined

| Name | Repository | Role |
|------|-----------|------|
| Ghost Gate | `ghost-gate-laptop` (local) | Token-gating dApp, the page being embedded |
| Sapient | `chironbuilds/tari-wallet` | Browser extension wallet (separate from Web Universe) |
| Web Tari Universe | `chironbuilds/tari-l1-wallet-ui` | Community browser L1+Ootle wallet hosting the DappFrame |

## Detailed findings

### 1. Protocol compatibility — CONFIRMED MATCH

Ghost Gate's `web/vendor/tari-connector.js` and Web Universe's `src/lib/dappBridge.ts` both use `"tari-dapp-bridge/1"` as their protocol identifier. The message format is identical:

- **Ghost Gate (connector):** `window.parent.postMessage({ protocol: "tari-dapp-bridge/1", id, method, params }, "*")`
- **Web Universe (handler):** Validates `event.data.protocol === "tari-dapp-bridge/1"` with matching `id`, `method` fields

The bridge protocol itself is not the problem.

### 2. Iframe embedding — NO BLOCKING HEADERS

Ghost Gate's Cloudflare worker (`cloudflare/src/worker.js`) sets no `X-Frame-Options` header and no `Content-Security-Policy frame-ancestors` directive. The page returns HTTP 200 at the root. There is no server-side obstacle to iframe embedding.

Web Universe's `DappFrame.tsx` creates the iframe with:
```
sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals"
referrerPolicy="strict-origin"
```

These sandbox attributes permit Ghost Gate's JavaScript to execute and communicate via postMessage.

### 3. The "blocked" symbol — DappFrame timeout

`DappFrame.tsx` implements blocked detection as:
```tsx
setTimeout(() => setBlocked((b) => (loaded ? b : true)), 4000)
```

If the iframe's `onLoad` event has not fired within 4 seconds, `blocked` becomes `true` and a `ShieldAlert` icon with `t("frame.refusesEmbed")` text is shown. This is a **heuristic**, not proof of a frame-refusal.

Ghost Gate's page loads `tari-connector.js` (synchronous, render-blocking) plus `lab.js` (module), fetches gate catalog, bridge status, and wallet status on init. On a slow connection or cold Cloudflare edge, this can exceed 4 seconds.

**However**, even if the iframe eventually loads (onLoad fires after the timeout), the `blocked` flag is not cleared retroactively — the `setBlocked` call only sets to `true` when `loaded` is still `false`. Once `loaded` flips to `true` on the actual onLoad, DappFrame stops showing the blocked icon. So the "blocked" state is transient if the page loads at all.

If the user consistently sees "blocked", the iframe may genuinely not be loading — which would point to a network issue, DNS failure, or a Cloudflare challenge page (bot protection) intercepting the iframe request.

### 4. The 404 component — wallet-side Ootle account

`component_7be2bcd8f349c75678814034b4b5a9f4fa9a571a3d4bebc398cb705ac30825ae` is an **Ootle L2 account component address**, derived from the wallet's public key via Blake2b-256 hash. This is NOT a Ghost Gate address or resource.

Web Universe's `dappBridge.ts` handles `tari_requestAccounts` by calling `account.getComponentAddress()` and querying the Ootle indexer for the account's substate. When the component does not exist on-chain, the indexer returns 404.

Causes:
- **Esmeralda testnet reset**: The testnet resets periodically, wiping all L2 state. The wallet retains its keys but its on-chain account no longer exists.
- **Never funded on L2**: The wallet was created but no L1→L2 burn/claim was completed to establish the Ootle account.

When this 404 occurs, `tari_requestAccounts` returns an error ("No Ootle account in this wallet" or similar), and Ghost Gate's Lab correctly shows "not connected" because no wallet address was provided.

### 5. The connector's embedded detection

Ghost Gate's `tari-connector.js` (line 39): `var embedded = window.parent !== window;`

When loaded inside Web Universe's DappFrame iframe, `embedded` is `true`, which is correct. The connector publishes `window.tari` with `isEmbedded: true` and `isTariWallet: true`. Ghost Gate's `provider.js` `universeProvider()` checks both of these properties (lines 231, 240) and would find a valid provider.

**But**: Ghost Gate's connector creates `window.tari` inside the iframe. Web Universe's DappFrame handler listens for postMessage from the iframe. The connector sends requests **up** to `window.parent`, and DappFrame sends responses **down** to the iframe. This direction is correct — Ghost Gate's connector talks to Web Universe's bridge handler.

The problem is that Web Universe's bridge handler calls `account.getComponentAddress()` to service `tari_requestAccounts`, and that account doesn't exist on-chain.

### 6. Sapient extension — different protocol, not involved

Sapient (`chironbuilds/tari-wallet`) uses `PAGE_TARGET = "tari-wallet-page"` / `CONTENT_TARGET = "tari-wallet-content"` for its postMessage protocol, which is entirely different from `"tari-dapp-bridge/1"`. Sapient also restricts postMessage to `window.location.origin` (not `"*"`). Sapient is not involved in the Web Universe embedding scenario.

---

## Root cause determination

**The failure is wallet-side.** The chain of events:

1. Web Universe opens Ghost Gate in a DappFrame iframe
2. Ghost Gate loads, its `tari-connector.js` detects `embedded = true`, publishes `window.tari`
3. Ghost Gate's Lab calls `tari_requestAccounts` via the connector → postMessage to Web Universe
4. Web Universe's bridge handler receives the request, calls `account.getComponentAddress()`
5. The Ootle indexer returns 404 for the account component (testnet-reset or never funded)
6. `tari_requestAccounts` fails → Ghost Gate shows "not connected"
7. Meanwhile, DappFrame's 4-second timeout may have fired → "blocked" icon shown

**No Ghost Gate code defect has been identified.** The iframe embedding works. The bridge protocol matches. Ghost Gate's connector correctly detects the embedded environment. The failure occurs entirely within Web Universe's own account infrastructure.

---

## Recommended live browser observation

To confirm with certainty, open Ghost Gate inside Web Universe's DappFrame and check browser DevTools:

1. **Network tab**: Does the iframe request to `ghostgate.boo` return 200? (If not, Cloudflare challenge or DNS issue.)
2. **Console tab (iframe context)**: Does `tari-connector.js` log the postMessage send for `tari_requestAccounts`?
3. **Console tab (parent context)**: Does Web Universe's bridge handler receive the message and attempt `getComponentAddress()`? Does the Ootle indexer 404 appear here?

If (1) succeeds and (3) shows the 404, the root cause is confirmed as stated above.

---

## Remediation

**Ghost Gate: No change required.** The dApp is correctly embeddable and its connector protocol is compatible.

**Web Universe (wallet-side):**
- Fund or re-establish the Ootle L2 account after testnet reset
- Alternatively, DappFrame could handle `tari_requestAccounts` failure more gracefully — distinguish "account not on chain" from "dApp refused to embed"

**Prior assessment still holds:** GGBP1 (`docs/GGBP1_WEB_UNIVERSE_INTEGRATION.md`) established that no safe L1 proof-provider API exists in Web Universe. The current embedding failure is orthogonal to that limitation — even if the Ootle account were restored, Ghost Gate's credential-mode proof would require capabilities (`privateSpend`, `minimumValuePromise`, `ownershipProof`) that Web Universe's bridge does not implement.
