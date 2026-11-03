# Esmeralda Ootle 0.49.2 live readiness reconnaissance

Status timestamp: 2026-11-02 23:42 PST / 2026-11-03 07:42 UTC
Ghost Gate commit: `8aab476754ec0a7ecd4a3c16db9abc8f58bd72a5`
Target: Tari Ootle tag `v0.49.2`, commit
`aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90`
Scope: read-only network, repository, public-site, and CI reconnaissance. No transaction, faucet
claim, publication, component/resource creation, deployment, service mutation, credential reset, or
secret access was performed.

## Executive result

The Ghost Gate Rust migration is green, the two official indexers agree on Esmeralda network byte
38, and their current REST responses have the JSON-envelope/base64-CBOR shape used by the migrated
reader. The reset native resource and built-in faucet component are present at version zero with
proofs that each indexer reports as verified.

Live bootstrap is nevertheless **blocked**:

1. both official public indexers self-report Ootle `0.49.1`, not the required exact `0.49.2` cohort;
2. the public API does not expose a reliable global genesis/sidechain identity: `/info.sidechain_id`
   is `null`, and the public checkpoint route supplies no independently usable reset-chain anchor;
3. no real Sapient or embedded Web Tari Universe provider could be exercised in this environment,
   so connection, network, capability, wallet-ownership signing, MVP output creation, and ownership
   signing remain unproved against the reset.

The first two conditions are explicit fail-closed conditions for this stage. Healthy peers and a
compatible-looking REST shape do not override a release or genesis-identity mismatch.

## 1. Exact network identity

### Official target evidence

| Value | Evidence | Result |
|---|---|---|
| Network name | `crates/ootle_network/src/lib.rs` at tag `v0.49.2`; live `GET /network` | `esmeralda` |
| Network byte | `Network::Esmeralda = 0x26`; both live endpoints return `network_byte: 38` | `0x26` / decimal **38** |
| Target release | local reference is exact tag `v0.49.2` at `aa7b0c817...`; the official wallet guide currently offers `tari_ootle_walletd-0.49.2-aa7b0c8-*` | **0.49.2 required** |
| Epoch oracle | `applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml` | hybrid oracle; base node `https://grpc.esmeralda.tari.com`; birthday height `669506`; configured base time `2026-02-23T13:08:42Z` |
| Configured validators | same v0.49.2 preset | four validators, full shard group 1–256, registration epoch 8367 |
| Live epoch | both `GET /network` responses | **12824** at observation time |
| Live validator height | `GET /network/stats` | four running validators, epoch 12824, observed heights 159–164; no current probe error; shard group phase `Streaming`; last checkpoint epoch 12823 |

The official current exchange-integration guide names these public endpoints and the same Esmeralda
base-node gRPC endpoint:

- `https://esme-indexer-a.ootle.tari.com/`
- `https://esme-indexer-b.ootle.tari.com/`
- `https://grpc.esmeralda.tari.com`

The older alias `https://ootle-indexer-a.tari.com/` also answered as Esmeralda/38/epoch 12824, but it
is not selected over the two endpoints in the current v0.49.2 preset and documentation.

### Live endpoint agreement and release mismatch

| Endpoint | Ready | Network / byte | Epoch | `/info.version` | Proof service | Classification |
|---|---:|---|---:|---|---:|---|
| indexer A | yes | esmeralda / 38 | 12824 | **0.49.1** | `verify_substate_proofs: true` | **INCOMPATIBLE** with exact target |
| indexer B | yes | esmeralda / 38 | 12824 | **0.49.1** | `verify_substate_proofs: true` | **INCOMPATIBLE** with exact target |

Both endpoints returned HTTP 200 from `/wait-until-ready`, twelve network connections in the first
probe, four running validators, no excluded peer, and no probe error. They agree with each other,
but agreement on `0.49.1` is still a target-cohort failure. Stage 3B must not submit to these
endpoints until they report `0.49.2` or an authoritative Tari release statement changes the target
and a separate migration review approves it. This stage does not follow development.

## 2. Genesis evidence

Ootle uses sharded state roots; the target source does not define one human-facing global genesis
hash in the Esmeralda preset. The exact v0.49.2 source does pin four version-zero, epoch-zero genesis
resource substate hashes in
`applications/tari_ootle_app_utilities/src/genesis_resources.rs`:

| Genesis resource | v0.49.2 pinned hash |
|---|---|
| public identity | `047cd7d24d968b1406a56bc059f167325c9d4c523cc88cec8663b677dcccc265` |
| native stealth tTARI | `e26c4af38b0ef0f897aa73f93efd47c823d7524b117ec2977b88b182e71459e1` |
| faucet claim receipt | `fc9ce6405c8b3389bdce7f6d267ed93ceabcf464a9dde35ac005c70f3dfdc499` |
| NFT faucet | `1ef457c8d757984f5fbab3773160ce134ec24cc80bba35b3876270daf0025498` |

Live evidence is consistent but not sufficient for a complete identity assertion:

- both endpoints returned the native resource at version 0, `state.up`, `verified: true`, with a
  proof whose `value_hash_epoch` is 0;
- both returned identical decoded native-resource bytes (SHA-256
  `5550842484d8e5f32715bf9abd1c3636bc24155638229ad058c03bd5ba98b4ee`);
- both returned the built-in faucet component at version 0 with identical base64-CBOR and
  `verified: true`;
- each endpoint anchored those leaves in a later current-epoch proof. Different later block/root
  anchors are expected and are not a genesis mismatch;
- `/info.sidechain_id` was `null` on both endpoints;
- `/epoch-checkpoints/latest?shard=0&include_committees=true` returned 404, “This indexer holds no
  epoch checkpoint”, and bounded checkpoint queries returned no public records.

Therefore the reset's native genesis leaf is strongly corroborated, but an authoritative complete
genesis/sidechain identity cannot be established from the public API. Classification: **UNKNOWN / NOT
READY**, and, by the requested fail-closed rule, a bootstrap blocker. Resolve it with an official
signed reset/genesis manifest or a reviewed current validator-set/bootstrap anchor that can be
checked independently against both endpoints; do not reuse the old epoch-12634 roots.

## 3. Endpoint inventory

| Service | Current supported value | Readiness |
|---|---|---|
| Public indexer A | `https://esme-indexer-a.ootle.tari.com/` | reachable, wrong self-reported release |
| Public indexer B | `https://esme-indexer-b.ootle.tari.com/` | reachable, wrong self-reported release |
| Esmeralda base-node gRPC | `https://grpc.esmeralda.tari.com` | official preset; not needed by Ghost Gate's normal indexer reader |
| walletd JSON-RPC/UI | local `127.0.0.1:5100` by default; operator may choose another loopback port | no public wallet endpoint should be exposed |
| Ghost Gate public dApp | `https://ghostgate.boo/` and SPA path `/lab/` | HTTP 200 |
| Universe connector asset | `https://universe.tari.mw/tari-connector.js` (served locally as `/vendor/tari-connector.js` by the dApp deployment) | public asset HTTP 200; provider not exercised |

The public Ghost Gate read-only endpoints reported:

- `/health`: registry-backed, one `Crypt` gate, credential reader configured, no live challenges;
- `/wallet/status`: local walletd intentionally not configured/reachable; browser wallet required;
- `/lab/gates`: Crypt, native tTARI, threshold 100000000, divisibility 6, network 38,
  credential mode, `https://ghostgate.boo`, policy label `v3`, historical digest
  `13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f`.

Those GETs prove what is currently configured, not that the old policy publication, chain evidence,
or browser proof is valid after reset.

### Repeatable wait-state monitor

Run the repository's non-mutating monitor from its root:

```powershell
.\scripts\check-esmeralda-0492-readiness.ps1
```

The script performs GET requests only. It checks both official `/info`, `/network`, readiness,
native-tTARI substate, built-in-faucet substate, and latest-checkpoint endpoints. It requires
Esmeralda byte 38, exact Ootle `0.49.2`, agreement between both indexers, proof-bearing verified
native/faucet state, and a common nonempty genesis/sidechain identity exposed by the APIs. It prints
a compact per-indexer result and exits nonzero while any Stage 3B network gate is blocked.

The expected current result is `STAGE 3B NETWORK GATE: BLOCKED` while the indexers report `0.49.1`
or no authoritative genesis/sidechain identity. Do not override that exit code merely because HTTP
requests succeed. The target version and network are fixed in the script; only the bounded
`-TimeoutSec` diagnostic parameter is configurable.

The Stage 3A.3 validation run on 2026-11-03 observed both endpoints at epoch 12825, Esmeralda/38,
version `0.49.1`, with the native and faucet checks passing and no genesis/sidechain identity. The
script printed `STAGE 3B NETWORK GATE: BLOCKED` and exited 1 as required.

## 4. Indexer readiness

| Check | Evidence | Classification |
|---|---|---|
| Reachability/readiness | A and B: HTTP 200 `/network`, `/info`, `/wait-until-ready` | **PASS** |
| Network identity | both return Esmeralda byte 38, same epoch | **PASS** |
| Exact release | both return `0.49.1`; target is exact `0.49.2` | **INCOMPATIBLE** |
| Content type | REST envelopes are `application/json`; encoded substate/UTXO values inside them are base64-CBOR | **PASS** |
| Single substate | native resource and faucet component return version/state/encoded value/verified/proof | **PASS** |
| Batch substate | `POST /substates/fetch` returns `substates` values plus `proofs` and `commit_proofs` in the v0.49.2 shape | **PASS** for observed request |
| UTXO route | `POST /utxos/fetch` accepts `tag_and_nonce_pairs`, resource, `unspent_at`, and nullable cursor; empty query returned `utxos: []`, `spent: []` | **PASS** for route/empty shape |
| UTXO pagination | v0.49.2 source orders by UTXO id and uses request `cursor` / optional response `next_cursor`; the empty live query had no next cursor | **UNKNOWN** for a real multi-page live result |
| Verified/proof behavior | native and faucet responses were `verified: true` and carried proofs; server says proof verification enabled | **PASS** for sampled genesis substates |
| Consensus metadata | epoch 12824, four running validators, streaming shard group, checkpoint progress 12823 | **PASS** for health telemetry |
| Public checkpoint/bootstrap anchor | no latest checkpoint served for sampled shard; no global sidechain id | **UNKNOWN / NOT READY** |

`crates/ghost-gate-walletd/src/indexer.rs` uses the official `IndexerRestApiClient`, reads the
response `verified` flag, decodes `Encoded<SubstateValue>` from base64-CBOR, requires a UTXO, and
fails closed when verification/read/shape checks fail. That matches the observed value encoding.
The reader currently asks the indexer to verify and does not independently validate the returned
proof bytes; that is consistent only with Crypt's declared `operator-trusted-testnet` ceiling. The
legacy JSON reader in `esmeralda.rs` remains restricted to 0.47/0.48 and must not be selected.

## 5. Walletd and Ghost Gate tooling readiness

The official current wallet guide advertises the `0.49.2-aa7b0c8` walletd build and the command:

```text
./tari_ootle_walletd --network esme --listen-on 127.0.0.1:12345
```

The exact v0.49.2 preset selects the two official indexers above, defaults Esmeralda authentication
to WebAuthn, defaults `indexer_trust` to `trust`, and listens on loopback. Target behavior confirmed
from source:

- when no passkey is enrolled, startup creates a random one-time setup token in
  `<base_path>/setup_token`, with a one-hour TTL and Unix mode 0600, and prints a tokenized
  registration URL only to stdout;
- initial registration requires that token; successful use consumes it; restart creates a new token
  only when still unenrolled; `reset-passkeys` clears credentials and requires a restart;
- a configured WebAuthn RP host and explicit `allowed_hosts` are added to localhost/IP allowances;
  other Host values are rejected;
- `trust` accepts indexer statements; `verify` walks validator sets from a reviewed anchor and needs
  proof-serving indexers. Do not describe `trust` as independent consensus verification.

Ghost Gate's 0.49.2 path uses current required transaction fields, sr25519 transaction signatures,
and `MainSigner::SealSigner`. It uses no Tari `Proof` arguments, account `*_with_auth`, signer/owner
proof getter, or auth hook, so no `AuthorizeProof`/`DropProofAuthorization` window or auth-hook input
is required. GitHub Actions validated the minimum-value-promise patch, but the actual deployment
wallet binary must still be provenance-checked to ensure it includes that patch before it builds a
credential output.

Walletd readiness is **CONDITIONALLY READY at source level**, but live use is blocked by the public
indexer release/genesis gates. A fresh post-reset wallet base path/database is required for L2 chain
state. Preserve custody material only under the operator's existing protected recovery policy; do
not copy old scan cursors, pending locks, receipts, output state, setup tokens, or cookies into the
fresh database. Native Minotari base-node support is optional, isolated behind
`minotari-base-node`, and must remain disabled or fail closed unless separately configured and
verified.

## 6. Sapient compatibility

Repository and deployed-provider inspection agree on the intended contract:

1. `tari_requestAccounts` first (real Sapient may reject earlier capability reads with 4100);
2. `tari_getCapabilities` and `tari_getNetwork`;
3. connection diagnostic `tari_signWalletOwnershipChallenge`;
4. credential creation using `tari_createTransactionRequest` with `kind: "shield"`,
   `resourceAddress`, `amount`, `minimumValuePromise`, and `maxFee`;
5. bounded polling with `tari_getTransactionRequest`, then `tari_submitTransactionRequest`;
6. challenge ownership using `tari_signOwnershipChallenge` over resource, substate id, and challenge.

The adapter requires a locally controlled Sapient account with spend/MVP/ownership capabilities;
a daemon-relayed or transfer-only account is refused. The network result is mapped to byte 38 and
must match the gate. Transaction sr25519/MainSigner internals are wallet responsibilities and cannot
be certified from the JavaScript method names.

No browser/app surface could be initialized: the computer-use helper failed twice before app
enumeration with `failed to write kernel assets: The system cannot find the path specified`. Thus no
account request, signature, transaction request, secret, or wallet state was touched. There is no
real installed-build/version evidence or positive signature vector.

Classification: **UNKNOWN**, not `WALLET WORKS / GHOST GATE DEPLOYMENT MISSING` and not proven
`WALLET INCOMPATIBLE`. An operator must run the real provider matrix after the indexer/genesis gates
are resolved.

## 7. Web Tari Universe compatibility

`https://ghostgate.boo/`, `/lab/`, the deployed provider module, and the public connector asset all
returned HTTP 200. The page does not currently send `X-Frame-Options`, and the observed response had
no page CSP that would itself forbid embedding. The connector asset's CSP allows HTTPS frames and
includes the older Tari indexer alias. These are reachability observations, not proof that the
actual embedded dApp catalogue uses this build or provider cohort.

Ghost Gate correctly requires `window.tari.isTariWallet` and `isEmbedded === true`; a normal browser
tab is intentionally rejected. Because no actual Universe embedded surface was available, provider
presence, network byte, request/signing interface, connection handshake, iframe navigation, and
external-link behavior were not exercised.

Classification: **UNKNOWN**. A plain-tab GET is not a Universe wallet test. Record the actual
Universe build/connector version and run the same credential matrix in its real embedded frame.

## 8. Funding and faucet readiness

The supported v0.49.2 path is the walletd Web UI's built-in Esmeralda faucet flow documented in the
official wallet guide. The fixed component address is:

```text
component_0102030000000000000000000000000000000000000000000000000000000000
```

Both public indexers returned that component at version 0, `state.up`, with identical base64-CBOR,
a proof, and `verified: true`. The native resource remains
`resource_0101010101010101010101010101010101010101010101010101010101010101`; its sampled total
supply was `253458192757` raw units. This proves the builtin artifacts are indexed, not that a
particular wallet claim will succeed or that faucet policy/rate limits permit repeated claims.

No faucet request was necessary for reconnaissance, so none was made. Once the release/genesis
blockers are resolved, claim only the minimum needed in each isolated deployment/Sapient/Universe
test wallet, record the accepted transaction and balance/output delta, and do not retry an unknown
result blindly.

Funding classification: **AVAILABLE BY OFFICIAL PATH; CLAIM NOT YET PROVEN**.

## 9. Reset-invalidated Ghost Gate inventory

| Old value/category | Where used | Invalidated by reset? | New value required? | Regeneration stage |
|---|---|---:|---:|---|
| Published GhostGate/Faucet/OtherClasses template addresses and binary/metadata hashes | private receipts/env; no concrete published template address is present in tracked deployment evidence | yes, if those optional templates are used | yes | optional Stage 3B fixture branch |
| GhostGate components, test faucet components, custom resources/vaults/accounts | private env/bindings/receipts | yes | only for selected optional tests; not for public Crypt | optional Stage 3B fixture branch |
| Native tTARI address `resource_0101…0101` | registry, Worker tests, wallet tests, scripts, docs | address no; old balances/output state yes | retain address, revalidate version-zero state and create fresh funds/outputs | Stage 3A.2 evidence + Stage 3B wallet funding |
| Builtin faucet `component_010203…0000` | legacy live reader/test | address no; availability must be rechecked | retain verified constant | Stage 3A.2 evidence; claim in Stage 3B if needed |
| Old transaction ids, UTXO ids, receipts, balances, scan cursors, locks, pending/resume payloads | wallet DBs, operator logs, browser resume state, tests | yes | yes for live use | each Stage 3B mutation/acceptance case |
| Crypt digest `13af3169…0b74f` and policy label `v3` | live `/lab/gates`, `docs/ARCHITECTURE.md`, Worker tests | not automatically; hash changes only if a hashed field/publication changes, but old publication is not reset evidence | recompute/verify from actual reviewed snapshot; never assume | Stage 3B policy publication/reconciliation |
| Registry gate record, generation floor, grants, owner/admin records | registry/admin durable state | chain bindings require review; durable owner/audit/floor must be preserved | migrate to a strictly newer generation; do not recreate tenant casually | Stage 3B admin step-up |
| Worker public gate catalog | Cloudflare config and frontend | active but unverified against reset | rendered candidate from reviewed bindings, then controlled activation | Stage 3B/activation stage |
| VPS bridge/indexer/env configuration | protected service env | endpoint/release/chain evidence stale | exact approved endpoints and new policy/generation bindings | later controlled VPS stage |
| Telegram verifier/bot policy binding and outstanding claims | protected bot/bridge config and durable state | old authorizations/claims invalid; bot credential itself is not reset by chain | new reviewed policy/generation; retain replay/audit data | later Telegram activation/test stage |
| Admin policy/catalog data | registry/admin DB | chain-derived binding requires review; owner credentials/audit records preserved | new immutable policy publication only after reconciliation | Stage 3B |
| v0.47 sidecar epoch 12634, preset `e9b9badf…d3df3`, roots `dc393597…956` and `23b6a682…7f`, committees/checkpoints | `tools/ghost-gate-v047-verifier`, evidence/docs | yes for current Esmeralda | no for operator-trusted Crypt; new anchor only if independent verification is chosen | separate verifier project, not minimum bootstrap |
| `scripts/dev.ps1` Ootle 0.47/default gate values | developer launcher | yes/stale | parameterize before any live use | Stage 3B reproducibility work |
| historical localnet components/resources in `docs/GATE3_RESULTS.md` and localnet UTXO `a66c77…54b407` | docs and explicit localnet tests | not caused by Esmeralda reset, but not live Esmeralda evidence | fresh isolated target fixtures when rerun | test stage |
| mock UTXOs `5ad331…be8c6f` / `abcdef…` and repeated `aa` addresses | CDP/unit/demo fixtures | no; synthetic | no live replacement in fixture; clearly label synthetic | test maintenance |
| indexer roots/checkpoints/derived verifier anchors | old evidence and sidecar | yes | authoritative reset-chain anchor if verification is required | blocker resolution / separate verifier stage |
| cached browser sessions/challenges/Telegram links | browser/server durable state | yes by generation/reset policy | new challenges/sessions only | controlled activation and acceptance |

Policy-hash note: the current v2 canonical input order includes application id, gate id, policy
version, owner credential, topology, network, genesis hash, production flag, TTLs, resource,
threshold, divisibility, symbol/name, proof mode, site, enabled/test lane, ordered grants, optional
component, and use mode. Generation and trust tier are not serialized hash fields. For credential
Crypt, the component is absent and the native resource address is stable. A reset alone therefore
does not mathematically force a hash change, but establishing a new genesis field or publishing a
new immutable version does. Recompute from the actual snapshot; never bless the old digest by
coincidence.

## 10. Minimum required bootstrap inventory

### Required for current public Crypt

- a release-consistent Esmeralda/indexer cohort and authoritative reset-chain identity;
- native tTARI at the fixed genesis resource address, not a custom replacement;
- fresh post-reset wallet state and the minimum faucet funding/fee headroom needed for acceptance;
- a real Sapient or embedded Universe account exposing private spend, nonzero MVP, transaction
  request, and ownership-signature capabilities;
- existing application/owner/audit state reconciled, a strictly newer durable generation, and a
  reviewed immutable Crypt policy binding site `https://ghostgate.boo`, network 38, native tTARI,
  threshold 100000000, divisibility 6, credential mode, TTL 604800, trust ceiling
  `operator-trusted-testnet`, use `both`, production `false`;
- consistent registry, bridge, Worker catalog, Telegram, and Protocol Inspector bindings before
  activation.

Confirmed architectural fact: credential mode verifies a wallet-created native tTARI output and
off-chain ownership challenge. It has no `componentAddress` and does **not** require publishing the
GhostGate template or instantiating an on-chain GhostGate component.

### Required only for test coverage

- `ghost_gate` template plus a freshly instantiated Locked GhostGate component for Mode A engine/live
  tests;
- `ghost_gate_faucet` plus a custom test resource/faucet component for controlled mint/resource
  isolation tests;
- `ghost_gate_other_classes` resources/components for public-fungible, confidential-class, and NFT
  rejection tests.

### Optional demo resource

Any fresh custom demo resource/faucet is optional and must never be substituted for native tTARI in
Crypt. It is useful only for isolated resource/cross-class demonstrations.

### Legacy / not needed

The v0.42/v0.47 compatibility sidecars, old epoch-12634 roots, old Esmeralda addresses/UTXOs, and an
on-chain admin or policy-registry component are not part of minimum public Crypt bootstrap. Registry
and admin state are off-chain services.

## 11. Stage 3B go/no-go gates

Stage 3B remains blocked unless **every** row is PASS at the same decision point. A later failure or
disagreement immediately returns the system to BLOCKED. No healthy subset, manual override, or
successful HTTP status compensates for a failed row.

| Gate | PASS condition | Current state |
|---|---|---|
| 1. Official indexer network agreement | A and B both report `esmeralda`, byte 38, and the same current epoch | PASS at the Stage 3A.2 observation; must be rechecked |
| 2. Release agreement and compatibility | A and B agree on a release compatible with the chosen exact target | **BLOCKED** |
| 3. 0.49.1/0.49.2 mismatch resolved | Both official endpoints report `0.49.2`; `0.49.1` is not accepted | **BLOCKED** |
| 4. Required state/proof APIs | Both endpoints are ready and return proof-bearing, `verified: true`, up-state native tTARI and built-in faucet substates; target batch/UTXO shapes remain usable | PASS for sampled state, but must be rechecked after the release change |
| 5. Sapient basic provider/signing | Operator checklist records account connection, Esmeralda/38, capabilities, site-scoped wallet-ownership approval, and successful response | **UNKNOWN / BLOCKED** |
| 6. Web Tari Universe basic provider/signing | Operator checklist records a real embedded provider, Esmeralda/38, connection, site-scoped wallet-ownership signature, and correct external navigation | **UNKNOWN / BLOCKED** |
| 7. Genesis/network identity | An authoritative reset genesis/sidechain identity or reviewed validator-set bootstrap anchor is available and agrees across both endpoints | **BLOCKED** |

The automated network portion is checked with
`scripts/check-esmeralda-0492-readiness.ps1`. The two wallet portions are recorded with
`docs/ESMERALDA_0492_BROWSER_WALLET_CHECKLIST.md`. Both tools are evidence collectors, not authority
to transact or deploy. The browser checklist stops before the final Crypt credential flow; the
funded MVP/output-specific ownership tests remain mandatory later acceptance gates before public
activation.

## 12. Concrete blockers and stop conditions

1. **Indexer cohort:** wait for both official endpoints to report `0.49.2`; re-run `/network`,
   `/info`, readiness, validator health, native/faucet proof, batch substate, and nonempty paginated
   UTXO checks. Stop if versions or network identities differ.
2. **Genesis identity:** obtain authoritative current reset/genesis/sidechain evidence or a reviewed
   validator-set bootstrap anchor. Stop if it cannot be checked against both endpoints. Do not reuse
   epoch-12634 evidence.
3. **Sapient:** with a recorded current build and local account, prove requestAccounts, Esmeralda/38,
   required capabilities, and a site-scoped wallet-ownership signature using the manual checklist.
   Stop on a missing method, wrong network, unexpected transaction request, or daemon-relayed account
   limitation. The funded MVP and output-specific ownership tests follow only in the authorized
   acceptance stage.
4. **Web Tari Universe:** repeat the basic provider/signing checks inside the real embedded frame and
   verify navigation/external links. Stop if only a plain-tab provider is available. The final Crypt
   credential flow is not part of this wait-state stage.
5. **Deployment wallet:** if Ghost Gate uses the patched walletd rather than an external wallet,
   verify the exact `0.49.2-aa7b0c8` source/binary plus `wallet-mvp-0492.patch`, new base path,
   WebAuthn/Host policy, and intended indexer trust. Never record the setup token.

## 13. Exact Stage 3B transaction/deployment order

No Stage 3B mutation begins until blockers 1–2 are resolved and at least one browser-wallet positive
connection/signature vector exists.

### Minimum public Crypt path

1. **Read-only preflight:** pin Ghost Gate commit, Ootle tag/commit, wallet binary/patch hashes,
   endpoints, release, network/genesis evidence, epoch, registry owner/application/gate ids, current
   generation floor, and current immutable policy snapshot. Any mismatch stops the run.
2. **Fresh wallet runtime:** create a new post-reset wallet base path/database (or isolated fresh
   browser-wallet state) while preserving only approved custody identity/recovery material. Complete
   WebAuthn enrollment locally if walletd is used; never copy or log the setup token.
3. **Faucet funding transaction:** claim the minimum practical tTARI for the deployment/test wallet,
   then separately for Sapient/Universe only if needed. Record the original transaction id and wait
   for accepted/finalized output and fee/balance deltas. Unknown/pending is not safe to repeat.
4. **Provider connection diagnostic:** request account, network/capabilities, and a wallet-ownership
   signature. This signs no transaction and creates no Ghost Gate chain object. Stop on wrong byte or
   unsupported capability.
5. **Off-chain generation migration:** under authenticated admin step-up, advance the existing
   application to one strictly higher durable generation. Re-read state; do not increment again if
   the intended migration already landed.
6. **Off-chain immutable Crypt policy publication:** publish/reconcile the exact reviewed values,
   recompute the policy hash with repository code, export bindings, and render a candidate catalog.
   Keep public authorization halted until every service agrees.
7. **Controlled service configuration/activation:** in separately authorized stages, update bridge,
   Worker, Telegram, and inspector bindings without lowering replay/fail-closed controls. This is not
   an Ootle chain transaction.
8. **Credential acceptance transaction:** the wallet creates the first fresh shield/self-transfer
   output with MVP 100000000 (plus separate fee headroom), waits for finalization, signs a fresh
   server challenge, and completes the negative/positive acceptance matrix. This is the first
   Ghost-Gate-related chain mutation in the minimum path; it creates a proof artifact, not a
   GhostGate component.

There is **no template publication, custom resource creation, or GhostGate component instantiation
in the minimum public Crypt path**.

### Optional full fixture branch, only after public Crypt is safe

Each item is a separate journaled transaction; reconcile its original id before retrying:

1. publish `ghost_gate` (`ghost_gate_template.wasm`);
2. publish `ghost_gate_faucet` (`ghost_gate_faucet.wasm`);
3. publish `ghost_gate_other_classes` (`ghost_gate_other_classes.wasm`);
4. call `GhostGateFaucet::new_resource` to create one minimal test resource/faucet/vault;
5. build a wallet statement for the returned resource and call `mint` once for controlled outputs;
6. allocate and instantiate a Locked `GhostGate` over the selected supported resource with explicit
   site/session/network bindings;
7. create minimal public-fungible, confidential-class, and NFT fixtures from OtherClasses and prove
   their expected rejection paths;
8. run Mode A proof/event tests and cross-resource/adversarial cases; never register optional
   fixtures as public Crypt.

Accepted create/publish/mint transactions have no chain rollback. On an erroneous accepted result,
exclude the artifact from the registry, retain the audit record, and create a reviewed replacement
only with new authorization. Fee effects may exist on rejected execution. Timeouts require querying
the original transaction and wallet locks; never infer non-submission from an indexer 404 alone.

## Sources

- Tari Ootle wallet setup: <https://ootle.tari.com/guides/setup-a-wallet/>
- Tari Ootle exchange/indexer setup: <https://ootle.tari.com/guides/exchange-integration/>
- Tari Ootle releases: <https://github.com/tari-project/tari-ootle/releases>
- exact local reference: `C:\Users\pdark\Documents\Codex\tari-ootle-v0.49.2-reference`
- GitHub Actions exact-commit run:
  <https://github.com/GSXRspartan/Ghost-Gate/actions/runs/41568842642>
- repository migration records: `docs/OOTLE_0492_MIGRATION_AUDIT.md`,
  `docs/OOTLE_0492_IMPLEMENTATION.md`, `docs/OOTLE_0492_RUST_VALIDATION.md`, and
  `docs/ESMERALDA_0492_BOOTSTRAP_PLAN.md`.

STAGE 3A.3 STATUS: WAITING ON NETWORK
