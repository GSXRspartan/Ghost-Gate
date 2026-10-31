# Tari browser-provider compatibility — capability matrix and findings

Status: research complete, adapters implemented against the documented contracts. Live wallet
testing (Sapient installed in a browser; Tari Universe iframe session) has **not** been performed in
this environment — no browser, no extension, no Universe instance. Every "tested" below means
contract-driven unit tests against the pinned type declarations and the reference verifier, never a
live wallet. See "What was actually tested" for the precise list.

Sources, read in full:

- `https://universe.tari.mw/integration/` — the shared `window.tari` contract
- `https://universe.tari.mw/integration/llms-full.txt` — the same, with full type signatures
- `https://universe.tari.mw/integration/tari-dapp.d.ts` — the typed contract
- `https://universe.tari.mw/paylink/` — the reference verifier; its bundle is where the byte-exact
  ownership-proof framing was confirmed (not inferred from prose)
- `https://github.com/chironbuilds/tari-wallet` — Sapient, the extension (README + source audit)
- `https://github.com/chironbuilds/tari-l1-wallet-ui` — Tari Universe web wallet (source audit)

---

## 1. The compatibility matrix

Wallets: **Local walletd** (our proven backend, `crates/ghost-gate-walletd`), **Sapient** (browser
extension, seed-derived local accounts), **Tari Universe** (web wallet at `universe.tari.mw`, dApps
run in a cross-origin iframe).

| Capability | Local walletd | Sapient (local acct) | Sapient (daemon acct) | Tari Universe |
| --- | --- | --- | --- | --- |
| Connection + account | our bridge API | `tari_requestAccounts` | `tari_requestAccounts` | `tari_requestAccounts` (iframe only) |
| Network report | gate binding | `tari_getNetwork` → Ootle net | same | same, and deliberately the **Ootle** net, not the L1 net |
| Balance read | never surfaced | `tari_getBalances` | same | same |
| Stealth UTXO inventory | wallet-side only, never to site | `tari_getShieldedOutputs` (needs view grant) | unavailable | same as Sapient |
| **Mode A: consensus proof** (MVP-bearing statement into `prove_access`) | **YES — the proven Gate 3 path** | **NO — see §2; unsound and unreachable** | **NO** | **NO** |
| **Mode B: credential proof** (`shield(MVP)` + ownership signature) | n/a (walletd builds statements directly) | **YES** — `minimumValuePromise` + `ownershipProof` caps | **NO** — daemon accounts refuse any nonzero promise | **YES** — same caps |
| Ownership signature verify | n/a | our bridge verifies (§4) | n/a | our bridge verifies (§4) |
| Committed-result lookup | `wait_transaction_result` | `tari_getTransactionResult` / request trio | same | same |
| Dry run (no prompt) | n/a | `dryRun: true` (round-trips the indexer) | same | same |
| Private-fee extension | n/a | `feeType`/`enforceFeeType` (Sapient-only field) | forced transparent | not documented upstream |
| L1 (Minotari) operations | out of scope | none | none | **none — see §6** |

Rule the UI encodes: a wallet offers the strongest mode its capabilities actually support, the bridge
refuses to treat a weaker mode as equivalent, and nothing downgrades automatically.

---

## 2. Why Mode A cannot go through a browser provider — the finding that shapes this design

Mode A asks the gate's `prove_access(challenge, statement)` with a `StealthTransferStatement`
argument, and the receipt attests the statement output's `minimum_value_promise`. Through `window.tari`
that argument is **unauthenticated caller data**:

- Every instruction argument is an opaque `{ Literal: hex }`; the wallet never decodes or validates
  argument contents (Sapient's `instructionSummary.ts` stops at `Literal` on purpose).
- No provider method returns a wallet-built statement, and no plan/quote/dry-run RPC reveals the
  UTXOs the wallet *would* choose (confirmed across Sapient's whole handler switch; dry runs never
  invoke the stealth authorizer at all).
- Raw `StealthTransfer` instructions are refused (`assertNoStealthTransferInstruction`) for
  `{ kind: "instructions" }` — the guard is not applied to `followUpInstructions`, but the wallet's
  stealth authorizer rejects a second stealth instruction regardless.
- The consensus rule itself cannot close the gap from inside a template: a `CallMethod` receives the
  statement as a value, the engine's `SpendContext` (which exposes engine-validated inputs/outputs)
  is injected **only** into spend-condition predicates, the template `Vault` model exposes no
  per-output promise accessor, and verifying the output's bulletproof inside a template is not
  feasible.

The concrete attack: a prover who holds *any* stealth UTXO of the gate's resource (or arranges for
the transaction to declare one their wallet will sign) builds
`CallMethod(gate, "prove_access", [challenge, forged_statement])` with a fabricated output carrying
`minimum_value_promise = threshold` and `balance_proof: Some(anything)` — our `find_qualifying_output`
checked presence of a balance proof, not validity, and never bound the statement to a real output.
The wallet prompts for an ordinary contract call whose arguments it cannot interpret, the user
approves, consensus accepts, and the gate attests a floor no output ever carried.

**This is a soundness limitation of the Gate 3 rule against untrusted callers, not a bug in the
walletd path.** Mode A stays correct through `walletd` because there the trusted local bridge asks the
user's own wallet daemon to build the statement, and the daemon rejects
`minimum_value_promise > blinded_amount` server-side (`applications/tari_walletd/src/handlers/
accounts.rs:1696`) before locking anything — the attested floor is bounded by a real, wallet-decrypted
holding. The browser surface has no such trusted local component: the relying site *is* the caller.

Consequence, implemented rather than implied: the browser adapters offer **Mode B only**, and the
bridge refuses credential proofs that were never issued against a challenge it minted. Nothing
silently substitutes one mode for the other (requirement: no automatic downgrade; equally, no
automatic upgrade of a weaker proof into a stronger-sounding claim).

The upstream extension that would make Mode A reachable from browsers is specified in §5.

---

## 3. The credential mode (Mode B), verified against chain state

The flow, per the provider docs, with the verifier's duties made explicit:

```text
1. site issues a fresh challenge + session commitment (our bridge, existing routes)
2. wallet: tari_createTransactionRequest { kind: "shield", resourceAddress: gate resource,
   amount: ≥ threshold, minimumValuePromise: threshold }   -> { requestId }
3. poll tari_getTransactionRequest until approved, then tari_submitTransactionRequest
   -> { transactionId, commitment, substateId, minimumValuePromise }
4. wallet: tari_signOwnershipChallenge { resourceAddress, substateId, challenge }
   -> { publicKey, publicNonce, signature }   (prompts; shows challenge verbatim)
5. site submits {substateId, ownership proof, challenge, session} to the bridge
6. BRIDGE verifies — trusting nothing from the page:
     a. challenge is live, session-bound, and minted by this bridge
     b. fetch the substate itself from the indexer (never from the page)
     c. substate is a UTXO of the gate's resource, still UP (unspent)
     d. output.minimum_value_promise >= gate.threshold   (read from chain, not echoed)
     e. auth path is a Key, and the signature verifies against THAT on-chain key
        (standard Tari Schnorr; message framed per §4), NOT against the page-supplied publicKey
     f. only then retire the challenge and record the receipt
```

What this mode is, stated plainly (all confirmed against the provider docs and Sapient source):

- **Public floor, permanent.** The MVP is stored in the clear in the output's range proof and is
  readable by anyone for as long as the output exists.
- **Exposed UTXO identifier.** `substateId` (`utxo_<resource>_<commitment>`) is in the proof the
  site holds and any link it builds. This is the property Mode A does not have: Mode A names no
  output at all.
- **One output, not a balance.** "This output is worth ≥ m", not "this account holds ≥ m".
- **Spend destroys the proof.** A verifier must re-check unspent status at view time; our bridge
  does exactly that at verification time, and nothing stops the output being spent a second later.
  Receipts therefore carry the floor as of a moment, and the site's own expiry policy governs
  session length afterwards.
- **Cross-session linkability.** Reusing the same output for two sessions links those sessions
  through the output. `shield` mints a fresh output per proof, so a fresh proof per session is the
  unlinkable path — at the cost of a setup transaction each time.
- **Setup fees.** Every `shield` is a real transaction with a real fee, paid from the wallet's
  revealed balance unless a private-fee extension applies. Mode A also costs a fee per access, so
  the fee is not the differentiator; the differentiator is that Mode B *stores* the disclosure.
- **Distinct replay model.** Mode A's single-use guarantee is the gate's burnt nonce. Mode B adds a
  second, independent guarantee — the challenge-bound ownership signature — so a stolen `substateId`
  alone proves nothing. But the *output* remains reusable as a floor artifact by anyone who also
  controls its key; the bridge binds one receipt to one challenge either way.

**Not silently substituted.** The UI labels the modes by name, the bridge records which mode produced
a receipt, and a wallet that only offers Mode B is shown as "credential mode" — never as the
consensus-proof flow (requirement 5; the same honesty runs in the other direction: walletd offers
Mode A and the UI says so).

## 4. Byte-exact ownership-proof verification (confirmed from the reference verifier, not prose)

From the `/paylink` bundle's `schnorrVerify` and message builder:

- **Message** = Blake2b-512 (64-byte digest) over a length-prefixed chunk stream, where every chunk
  is `[u64 LE byte-length, bytes]`:
  1. the domain string `com.tari.paylink.ownership_proof.v1.v1` — the builder composes
     `${domain}.v${version}.${variant}` with `version = 1` and `variant = "v1"`, so the doubled
     suffix is real and must be reproduced exactly;
  2. one byte: the Ootle network byte;
  3. the resource address bytes (hex-decoded);
  4. the substate id bytes (hex-decoded);
  5. the challenge bytes (UTF-8).
  The wallet-ownership variant (`com.tari.paylink.wallet_ownership_proof.v1.v1`) chains
  `[network, walletAddressBytes, challenge]` instead — no output involved.
- **Signature** = standard Tari Schnorr over that message with domain
  `com.tari.schnorr_signature.v1.challenge`, hashed over `[nonce_bytes, key_bytes, message]`:
  `u·G == R + H(R, P, m)·P`, all scalars reduced mod the Ristretto group order.
- **Verification key**: the on-chain `output.auth.Key` from `tari_getSubstate` — fetched by the
  verifier, never taken from the page's `{ publicKey }` field, which anyone can self-report.

Implemented in `crates/ghost-gate-bridge/src/credential.rs` with the framing as a named constant
block, so a future wallet that changes the domain string fails our vectors rather than silently
verifying nothing.

---

## 5. The missing provider method (Mode A through browsers), specified

If wallets gain one narrow operation, Mode A becomes reachable without any of the §2 problems,
because the wallet would build the statement it also signs:

```ts
// tari_createTransactionRequest, new kind:
{
  kind: "ghostGateProveAccess",
  gateAddress: string,            // component_… ; registered by the site's bridge
  resourceAddress: string,        // the gate's resource; the wallet qualifies inputs against it
  minimumValuePromise: string,    // the gate's threshold (raw units, decimal string)
  challenge: {                    // the ABI Challenge, opaque to the wallet, bound by the gate
    gate: string, resource: string, threshold: string, network: number,
    nonce: string, expiresEpoch: string, relyingSite: string, sessionCommitment: string,
  },
  followUpInstructions: [],       // none needed; the wallet appends the prove_access call itself
  relatedComponents: string[],    // [gateAddress]
  maxFee?: string,
  feeType?: "private" | "transparent", enforceFeeType?: boolean,
}
```

Request contract: identical validation duties the wallet already performs for `redeemStealthOutputAndExecute`
(qualify inputs under `resourceAddress`, decrypt-check ownership), plus — and this is the part that
makes it sound — the wallet **builds** the `StealthTransferStatement` (real input commitment, real
`minimum_value_promise` it has already validated against the output's value), **calls**
`gate.prove_access(challenge, statement)` inside the same transaction, and only then signs. No
statement crosses the boundary, so nothing can be forged.

Response contract:

```ts
{ transactionId: string, attestedMinimum?: string, inputCount?: number }
// capability flag: ghostGateProveAccess: boolean
```

That is a wallet-side change, not a protocol change — the daemon path
(`accounts.create_stealth_transfer_statement` + `transactions.submit`) is the proof this shape works.

---

## 6. Tari Universe Web's Minotari L1 wallet — no dApp surface, confirmed from source

Audited `chironbuilds/tari-l1-wallet-ui` (branch `master`) end to end:

- **(a) L1 challenge/message signing via `window.tari`: NO.** The only `tari_sign*` methods route to
  the Ootle account (`DappFrame.tsx:267,281` → `account.signOwnershipProof` /
  `account.signWalletOwnership`). L1 Schnorr exists but only inside the wallet's own dev tools panel
  (`ToolsPanel.tsx:119`), not on any bridge path.
- **(b) L1 transaction build/sign for a page: NO.** `WasmTxBuilder` is used only by the wallet's own
  send and burn panels; the bridge's signing method maps to Ootle `account.execute`.
- **(c) L1 balance/UTXO read: NO.** `tari_getBalances` returns `s.l2.balances`; L1 UTXO state lives in
  the wallet's internal store and is never exposed.
- **(d) Any L1-specific method: NO.** `BridgeMethod` (`dappBridge.ts:32-60`) is the complete typed
  union; unknown methods reject with `4200`.

Consequences for our native-XTM route:

- The L1 wallet-local signing that would power a burn-free native-XTM threshold proof exists inside
  the wallet but is **unreachable from any dApp**. Route A (access-time L1 self-transfer) stays
  blocked on an upstream provider method, on top of the wallet-gRPC blocker already recorded in
  `docs/XTM_RESEARCH.md`.
- The bridge is an **Ootle surface end to end**; L1 proof support therefore remains **experimental
  and unimplemented**, exactly as required. Nothing here requests or exports seed phrases or private
  keys, and no L1 path was built.
- One operational trap confirmed in source and honored in our adapter: `tari_getNetwork` returns the
  **Ootle** network ("esmeralda") even though the wallet's L1 side defaults to MainNet — network
  verification for a gate must compare the Ootle byte, never an L1 network name.
- Embedding: the provider is only reachable **inside the wallet's iframe**; in a plain tab
  `window.tari.isEmbedded` is false and every call rejects. Our UI detects and explains that state
  instead of polling forever.

---

## 7. Capability detection, not wallet detection — what the adapters actually branch on

The shared contract is `tari_getCapabilities`. Two divergences were found in source and handled by
*capability*, not identity:

- Sapient's capability set includes fields the shared spec does not list (`shieldFunds`, `privateScan`,
  `confidentialDeposit`, `supportsPrivateFees`). The adapter reads the shared fields it needs and
  treats extras as opaque; nothing keys on wallet identity.
- The `accountsChanged` event arrives twice over in Sapient (CustomEvent `tari#accountsChanged` **and**
  `window.tari.on("accountsChanged")`); the connector script also publishes sugar
  (`proveFunds`/`verifyFunds`) on Universe. The adapter listens for both delivery paths and never
  assumes either exists.
- Daemon-relayed accounts inside Sapient fail stealth operations (`stealthWithdraw`,
  `stealthRedeem`, `minimumValuePromise`, `ownershipProof` all false) — which is exactly why the
  matrix keys on the per-account capabilities rather than "Sapient = yes".

The public pages load the official
`https://universe.tari.mw/tari-connector.js` connector. It stands aside when an extension owns
`window.tari` and supplies the iframe provider under Universe. The declaration URL above is a
documentation contract only; it is neither executed nor imported by the build or tests.

---

## 8. What was actually tested

- **Bridge credential-mode verifier (Rust, real):** 14 unit tests over the new
  `credential.rs` — byte-exact message framing, Schnorr verify against the on-chain key, substate
  shape/resource/unspent/threshold checks, challenge binding, replay, and the forge-shaped failures
  (bad key, spent output, sub-threshold promise, wrong resource, forged key). The signature vectors
  are generated in-test with the same Ristretto/Schnorr primitives the wallets use, so they test the
  *verifier*; they are not wallet recordings.
- **Provider adapters (TypeScript-shaped ES modules, mock-based):** the capability→mode mapping, the
  three adapters' discovery, network verification, and the Mode B sequence are tested with
  `node --test` against mocks that mirror the documented contract — including the two divergences
  above and the 4200/4100/4001 error codes.
- **Live Sapient / live Universe: NOT tested** — no browser or extension in this environment. The
  manual flow with each wallet remains unperformed and is listed as such in `MANUAL_TEST.md`;
  nothing here broadcasts a live transaction or claims otherwise.
- **All existing regressions preserved:** workspace suite, engine `access_rules` (48), patch
  verification, Gate 3 integration checks — re-run and green (counts in the commit message).

---

## 9. Blockers, stated plainly

| Blocker | Mode | Owner of the fix |
| --- | --- | --- |
| No provider method returns wallet-built statements, and `Literal` args are unsigned data | A via browsers | wallets (§5) — or an upstream engine change letting templates read engine-validated statements |
| Daemon-relayed Sapient accounts refuse every stealth operation and any nonzero promise | A and B via Sapient-daemon | wallets (or users run local accounts) |
| No L1 dApp surface in Tari Universe Web | native XTM (experimental) | wallets |
| Zero-transaction XTM proof still blocked on Minotari wallet gRPC (`SignMessage` is node-identity-only) | native XTM | upstream Minotari wallet |
| Live browser testing impossible in this environment | everything browser-side | operator with a browser and the wallets installed |
