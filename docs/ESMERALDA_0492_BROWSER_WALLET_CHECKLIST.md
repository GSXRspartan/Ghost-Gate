# Esmeralda 0.49.2 browser-wallet compatibility checklist

Use this checklist to collect the missing real-provider evidence for Sapient and Web Tari Universe.
It tests connection and a basic wallet-ownership signature only. It does **not** authorize the final
Crypt credential flow, a shield/self-transfer request, a faucet claim, or any Ghost Gate deployment
transaction.

The operator must keep Stage 3B blocked until the network gates in
`docs/ESMERALDA_0492_READINESS.md` also pass. A browser-wallet pass does not override an indexer
release mismatch or unresolved genesis identity.

## Evidence and safety rules

- Use an isolated test wallet/profile. Never paste or record a seed phrase, private key, setup token,
  cookie, API token, wallet database, or complete signature payload.
- Record the wallet/app version, test timestamp with timezone, selected network, public account
  address only if approved for the test record, and PASS/FAIL results. Redact signature bytes and
  challenges; recording “response returned” is sufficient.
- Do not click **Prove access**, create a credential output, approve a transaction, or submit funds.
- The expected Ootle network is `esmeralda`, byte **38** (`0x26`). A displayed Minotari/L1 network
  is not a substitute for the Ootle network reported to the dApp.
- A 4100/not-connected response before site approval is an expected connection state. It passes only
  after the operator authorizes the site and the retry succeeds.
- A plain browser tab is not a Web Tari Universe test. Universe must expose its provider inside the
  wallet's actual embedded dApp frame.
- If any approval dialog describes a transaction, fee, transfer, shield/self-transfer, faucet claim,
  or output creation, cancel it and mark the basic-signature test **FAIL — unexpected transaction**.

## Preflight record

| Field | Operator record |
|---|---|
| Date/time and timezone | |
| Ghost Gate URL | `https://ghostgate.boo/` |
| Ghost Gate commit/reference | `8aab476754ec0a7ecd4a3c16db9abc8f58bd72a5` |
| Readiness script command | `.\scripts\check-esmeralda-0492-readiness.ps1` |
| Readiness script result | PASS / BLOCKED |
| Indexer A reported version | |
| Indexer B reported version | |
| Network name/byte | expected `esmeralda` / `38` |
| Operator initials/test case ID | |

The provider checks may be collected while the network gate is blocked, but no final credential or
deployment step follows them until the script and all Stage 3B gates pass.

## Sapient manual test

### Setup

1. Open the browser profile containing the intended Sapient test installation.
2. Open Sapient directly and record its displayed build/version and account type. Use a locally
   controlled test account. A daemon-relayed or transfer-only account is not sufficient evidence for
   Ghost Gate credential mode.
3. Unlock Sapient manually. Do not expose the unlock secret or recovery material.
4. Select the Ootle **Esmeralda** network. Record the exact network label Sapient displays.
5. Open `https://ghostgate.boo/` in a normal top-level browser tab. Confirm the URL is HTTPS and the
   host is exactly `ghostgate.boo`.

### Connection and basic signature

6. Select the configured **Crypt** gate and **Sapient** wallet in the Ghost Gate interface.
7. Press **Connect wallet**. The first provider operation must be an account/site connection request
   (`tari_requestAccounts`). Approve only the site connection in Sapient.
8. Confirm Ghost Gate reports the wallet's Ootle network as `esmeralda` and resolves it to byte 38.
   Mark FAIL for a missing network, another network, or a page that reports only the L1 network.
9. Confirm the capability result is returned after connection. The page must not treat an initial
   4100 response as “wallet not installed”. Record any missing/unsupported method exactly.
10. Continue the connection diagnostic when Ghost Gate requests a basic wallet-ownership signature
    (`tari_signWalletOwnershipChallenge`). Confirm Sapient displays an approval prompt that names or
    clearly scopes the requesting site and contains no transaction, amount, fee, or asset movement.
11. Approve the diagnostic signature. Confirm Ghost Gate reports a successful response and remains
    on the connected state. Do not copy the signature or challenge into this checklist.
12. Stop before **Prove access**. Do not invoke `tari_createTransactionRequest`,
    `tari_submitTransactionRequest`, or the final output-specific `tari_signOwnershipChallenge` in
    this stage.
13. Review the visible page status and browser console, if available. There must be no method-not-found
    or shape error that indicates a v0.47/v0.48 provider assumption, no use of removed legacy UTXO
    routes, and no request for a seed/private key or broad view access.

### Sapient result record

| Check | Expected | PASS / FAIL | Evidence or exact error |
|---|---|---|---|
| Sapient opens and unlocks | Existing test wallet opens without credential disclosure | | |
| Wallet build/version recorded | Exact displayed build/version | | |
| Account type suitable | Local account; not daemon-relayed/transfer-only | | |
| Esmeralda selected | Ootle network label is Esmeralda | | |
| Provider discovered | `window.tari`/Ghost Gate Sapient adapter responds | | |
| Site connection | Account request approval succeeds | | |
| Network identity | `esmeralda`, byte 38 | | |
| Capabilities returned | No 4100 after approved reconnect; no missing required diagnostic method | | |
| Signature approval UI | Site-scoped, no transaction/fee/asset movement | | |
| Basic signature response | Wallet-ownership response returns successfully | | |
| No obsolete API assumption | No v0.47/v0.48 method or response-shape error | | |
| No secret/view overreach | No seed/key request and no broad view-access request | | |
| Overall Sapient result | PASS only if every required row passes | | |

Classify the overall outcome as one of:

- **PASS — BASIC PROVIDER/SIGNING FLOW**;
- **FAIL — WALLET INCOMPATIBLE** (wrong network, missing method, rejected shape, or signature failure);
- **FAIL — WALLET/PROFILE NOT AVAILABLE**;
- **FAIL — UNEXPECTED TRANSACTION REQUEST**;
- **INCONCLUSIVE — GHOST GATE PAGE OR NETWORK DIAGNOSTIC UNAVAILABLE**.

## Web Tari Universe manual test

### Setup and embedding

1. Open the actual Web Tari Universe application and record its displayed build/version plus the
   connector/provider version when exposed. Do not substitute a normal browser visit to its website.
2. Unlock/select the isolated test wallet manually and select the Ootle **Esmeralda** network.
3. Open Ghost Gate from Universe's dApp catalogue or supported embedded-dApp action. Navigate to
   `https://ghostgate.boo/` inside the wallet's embedded frame.
4. Confirm the Ghost Gate page renders normally: gate selector, wallet selector, connection control,
   and network/status panels are visible. Record any blank frame, blocked navigation, CSP, mixed
   content, or redirect error.
5. Confirm the embedded provider is present. Ghost Gate must recognize a Tari wallet with
   `isEmbedded === true`; a provider visible only in the outer page or a plain tab fails this check.

### Connection, signature, and navigation

6. Select **Crypt** and **Tari Universe**, then press **Connect wallet**.
7. Approve only the site/account connection. Confirm Ghost Gate receives the account, capabilities,
   and Ootle network without leaving the embedded frame.
8. Confirm the reported Ootle network is `esmeralda` and resolves to byte 38.
9. Continue the connection diagnostic to the basic wallet-ownership signature. Confirm the approval
   UI is site-scoped and requests no transaction, fee, output creation, transfer, or faucet claim.
10. Approve the diagnostic signature and confirm a successful response returns to Ghost Gate.
11. Stop before **Prove access**. Do not create or submit a credential output.
12. Use the Ghost Gate Telegram/external-link control. Confirm it opens outside the embedded dApp
    frame in the wallet's supported external browser/navigation surface. Do not join a chat, send a
    message, or authorize Telegram membership. Return to Ghost Gate and confirm its state is intact.
13. Check another ordinary external documentation link if present. It must not replace the embedded
    wallet shell, trap navigation in a broken iframe, or expose provider data to the destination.
14. Record any provider method-not-found, response-shape, iframe, or navigation error exactly. Do not
    infer compatibility from the page merely loading.

### Web Tari Universe result record

| Check | Expected | PASS / FAIL | Evidence or exact error |
|---|---|---|---|
| Universe app opens | Actual wallet app, not a plain browser substitute | | |
| Build/provider version recorded | Exact displayed values where available | | |
| Esmeralda selected | Ootle network label is Esmeralda | | |
| Embedded Ghost Gate loads | Full dApp renders inside Universe | | |
| Embedded provider present | Tari provider present with `isEmbedded === true` | | |
| Connection handshake | Account/capability requests succeed | | |
| Network identity | `esmeralda`, byte 38 | | |
| Signature approval UI | Site-scoped, no transaction/fee/asset movement | | |
| Basic signature response | Wallet-ownership response returns successfully | | |
| Telegram link behavior | Opens outside iframe; no join/message performed | | |
| Other external navigation | Opens in supported external surface without losing wallet shell | | |
| No obsolete API assumption | No v0.47/v0.48 method or response-shape error | | |
| Overall Universe result | PASS only if every required row passes | | |

Classify the overall outcome as one of:

- **PASS — BASIC EMBEDDED PROVIDER/SIGNING FLOW**;
- **FAIL — WALLET INCOMPATIBLE**;
- **FAIL — EMBEDDED PROVIDER MISSING**;
- **FAIL — IFRAME/NAVIGATION REGRESSION**;
- **FAIL — UNEXPECTED TRANSACTION REQUEST**;
- **INCONCLUSIVE — UNIVERSE BUILD OR TEST SURFACE UNAVAILABLE**.

## Combined operator decision

| Gate | Required result | Recorded result |
|---|---|---|
| Sapient basic provider/signing | PASS | |
| Web Tari Universe embedded provider/signing | PASS | |
| Both report Esmeralda byte 38 | PASS | |
| No unexpected transaction request | PASS | |
| No obsolete provider/API regression | PASS | |
| Evidence contains no secret/signature bytes | PASS | |

Both wallet rows must pass independently. Do not convert an unavailable wallet, absent embedded
surface, cancelled signature, or missing provider capability into a pass. Attach only redacted
screenshots/log extracts if needed; keep wallet identifiers and signatures out of tracked files.

MANUAL BROWSER WALLET VERDICT: PASS / BLOCKED
