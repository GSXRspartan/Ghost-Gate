# Esmeralda live readiness — Ootle 0.49.1 servers with v0.49.2 Ghost Gate source

Date: 2026-11-03
Branch: `upgrade/ootle-live-0.49.1`
Preserved future checkpoint: `future/ootle-0.49.2` at
`821daa6e54526481707251f8e26a663b0bbb98ee`

## Current result

The public network gate now passes. A read-only run of
`scripts/check-esmeralda-live-readiness.ps1` observed both official indexers at epoch 12830. Both
reported Ootle `0.49.1`, Esmeralda byte 38, ready status, and verified proof-bearing native tTARI
and built-in faucet substates. The indexers agreed on every hard network gate.

Overall live bootstrap remains **blocked** until the two browser-wallet flows pass and the operator
supplies verified provenance for the registry's existing genesis binding. No transaction or
deployment should be attempted merely because the network monitor passes.

## Evidence-based version rule

Expected live server version: **0.49.1**.

Tested Ghost Gate client/source version: **0.49.2**.

Compatibility justification: the exact upstream v0.49.1-to-v0.49.2 diff changes only release
metadata, lockfile workspace versions, and the `tari_logging` metrics feature spelling needed to
build release binaries. It changes no protocol, engine, transaction, wallet, walletd, indexer,
CBOR, template, resource-proof, stealth, authorization, or WebAuthn implementation. See
`docs/OOTLE_0491_LIVE_COMPATIBILITY.md`.

This is an exact compatibility rule, not a wildcard or ignored mismatch. Any server version other
than `0.49.1` makes the current monitor fail until it receives a new source review.

## Repeatable network gate

Run from the repository root:

```powershell
.\scripts\check-esmeralda-live-readiness.ps1
```

The script performs GET requests only, requires no secret, and submits no transaction. It checks:

- official indexers A and B `/info`, `/network`, and `/wait-until-ready`;
- exact Esmeralda network name and byte 38;
- identical epoch/network/version observations from both indexers;
- exact compatible live version `0.49.1`;
- proof-bearing `verified: true` state for native tTARI and the built-in faucet; and
- any genesis/sidechain field exposed by `/info`, `/network`, or the public checkpoint route as a
  diagnostic.

It exits zero only when the hard network gates pass. The observed 2026-11-03 summary was:

```text
A: network=esmeralda/38 epoch=12830 version=0.49.1 native=PASS faucet=PASS identity=none
B: network=esmeralda/38 epoch=12830 version=0.49.1 native=PASS faucet=PASS identity=none
agreement=PASS expected-network=PASS compatible-live-version=PASS required-state=PASS api-identity-diagnostic=NOT_EXPOSED
LIVE NETWORK GATE: PASS
```

## Identity boundary

Two different identity concepts must not be conflated.

### Security-required

`Application.genesis_hash` / `GG_GENESIS_HASH` is mandatory Ghost Gate policy state. It is validated
as hex, included in the v1/v2 canonical policy digest, copied into registry snapshots, and required
by `binding_from_snapshot`. The bridge fails closed on an empty value. The operator must recover
the existing value from the protected registry/configuration and verify its documented provenance,
or obtain an authoritative replacement before publishing the reset generation. Do not substitute
an Ootle tag commit, epoch/root hash, random value, or an unreviewed native-resource hash.

The reset must also advance the registry's positive, monotonic `chain_generation`; it is the
explicit security dimension that distinguishes L2 resets when the network byte, L1 genesis, and
native resource address remain unchanged.

### Diagnostic only for the current credential path

The optional indexer `/info.sidechain_id` and a public checkpoint/genesis field are not consumed by
the credential reader. The reader requires the configured official indexer, a verified response,
base64-CBOR `SubstateValue::Utxo`, correct resource/output, and current gate/session/challenge
bindings. `ExpectedIdentity.sidechain_id` is optional, and an absent observed value is
`Inconclusive`; the reset guard uses reports only in the safe direction to latch a halt.

Therefore absence of an API-exposed `sidechain_id` is recorded as `NOT_EXPOSED` but no longer
causes the network monitor to fail. This does not remove or weaken the registry genesis and chain
generation boundaries above.

## Browser-wallet acceptance against live 0.49.1

Use an isolated test wallet/profile. Never record a seed, private key, setup token, cookie, API
token, full challenge, or signature bytes. Stop if an ostensibly basic connection test presents a
transaction, fee, transfer, faucet claim, or output-creation approval.

### Sapient

1. Record the Sapient build/provider version and select Ootle Esmeralda.
2. Open `https://ghostgate.boo/` in a top-level HTTPS tab and select Crypt/Sapient.
3. Connect through `tari_requestAccounts`; approve only the site connection.
4. Require the provider network to resolve to Esmeralda byte 38 and capabilities to load after
   approval. A pre-approval 4100 is acceptable; a post-approval 4100 is not.
5. Request only the basic `tari_signWalletOwnershipChallenge` diagnostic. Require a site-scoped
   approval UI and a successful response.
6. Stop before Prove access or any transaction request. Record exact method/shape errors and confirm
   no v0.47/v0.48 provider assumption appears.

Required record: wallet version, network, provider discovery, site connection, capabilities,
signature approval UI, signature response, obsolete-API check, and overall PASS/FAIL.

### Web Tari Universe

1. Record the actual Universe and connector/provider versions; a plain browser tab is not a test.
2. Select Ootle Esmeralda and load Ghost Gate inside Universe's supported embedded dApp frame.
3. Require the embedded Tari provider (`isEmbedded === true`), successful connection/capability
   handshake, and network byte 38.
4. Request only the basic wallet-ownership signature and require a site-scoped approval plus a
   successful response.
5. Confirm the Telegram/external-link control opens outside the iframe without joining a chat or
   sending a message, then confirm the embedded dApp remains intact.
6. Stop before Prove access or credential creation. Record exact provider, iframe, CSP, navigation,
   or response-shape errors.

Required record: app/provider version, network, embedded page/provider, handshake, signature UI,
signature response, external-link behavior, obsolete-API check, and overall PASS/FAIL.

## Live bootstrap gates

| Gate | Current result | Stop condition |
|---|---|---|
| Both official indexers reachable and ready | PASS | Either endpoint fails |
| Both agree on Esmeralda byte 38 and current epoch | PASS at epoch 12830 | Any disagreement |
| Both report reviewed compatible server version 0.49.1 | PASS | Any other version before review |
| Verified native tTARI and faucet state | PASS | Missing, unverified, or proofless state |
| Registry genesis provenance | **BLOCKED / operator evidence required** | Missing, fabricated, or unverified binding |
| Positive next chain generation and migration plan | Planned, not executed | Zero/reused generation or missing protected registry inventory |
| Patched walletd runtime provenance | Source/test green; live binary not yet attested | Binary not built from the reviewed patched cohort |
| Sapient basic provider/signing | **UNKNOWN** | Anything other than recorded PASS |
| Web Tari Universe provider/signing/navigation | **UNKNOWN** | Anything other than recorded PASS |
| Deployment authorization | Not granted | Any attempt in this stage |

The missing public `sidechain_id` is a diagnostic and is not a separate stop condition. The
security-required registry genesis value remains a stop condition until its provenance is checked.

## What changed and what did not

Changed on the live branch:

- renamed and retargeted the read-only readiness monitor to the exact live v0.49.1 server cohort;
- replaced the version-string-only rejection with the reviewed compatibility rule;
- made API-exposed sidechain/genesis identity diagnostic while preserving registry identity
  requirements; and
- added the exact comparison and live operator readiness documents.

Not changed: Rust source, Cargo manifests/lockfiles, template source, authorization behavior,
transaction construction, deployment manifests, Cloudflare, VPS, production configuration, chain
addresses, or GitHub Actions. Because no dependency or Rust source changed, the existing Linux
engine validation remains applicable to the identical code commit; no new Linux workflow path was
needed for this documentation/tooling retarget.

## Local validation

The live branch was validated after the retarget. All commands completed successfully:

| Command | Result |
|---|---|
| `cargo check --workspace --locked` | PASS |
| `cargo test --workspace --exclude ghost-gate-tests --locked` | PASS; 397 passed, 5 intentional live-indexer/localnet skips, 0 failed |
| documented nightly `rustfmt --check` over migration-touched Ghost Gate-owned sources | PASS |
| `cargo check --target wasm32-unknown-unknown --locked` in each of the three template workspaces | PASS / PASS / PASS |
| wallet SDK `minimum_value_promise` filtered tests against the patched cohort | PASS; 3 passed, 0 failed |
| live readiness monitor against both official indexers | PASS |

The existing GitHub Actions Linux engine run covers the same Rust/dependency tree. This retarget
changes only documentation and the read-only PowerShell monitor.

## Bootstrap decision

Network compatibility is ready. Live mutation remains blocked pending operator-controlled genesis
provenance, patched wallet runtime provenance, and recorded PASS results for both browser wallets.

LIVE READINESS STATUS: BLOCKED
