# GGBP-1 Phase 2 Experimental Integration

**Status: feature-disabled synthetic experiment. It has no production authorization route, no
wallet attachment, no Telegram integration, and no live Esmeralda claim.**

## Components

- `crates/ghost-gate-minotari/src/ggbp1.rs` is the low-level Tari-primitive proof format and
  verifier. It now has a bounded canonical response encoding, a generator fingerprint derived
  from the actual default Tari extended-Pedersen factory, gate configuration binding, and an
  authenticated subject binding in a domain distinct from both Tari script checks and the GGBP-1
  output-authority domain.
- `crates/ghost-gate-minotari/src/ggbp1_experiment.rs` is an in-memory experimental verifier. A
  success has the explicit status `VerifiedNotAuthorized`; no type from this module can create a
  session, bridge grant, or Telegram grant.
- `crates/ghost-gate-minotari/src/ggbp1_chain_view.rs` is a read-only adapter for an explicitly
  operator-controlled Minotari base node. It is available only with `experimental-ggbp1`.
- `SyntheticWalletProver` is a synthetic-only wallet-owned API shape. It accepts a complete
  challenge and emits a bounded public response. It offers no raw signing, secret export,
  transaction creation, network call, or existing-wallet constructor.
- `ggbp1_wallet_adapter.rs` is the next, still synthetic-only wallet-core boundary. It binds
  network and genesis, filters deterministic confirmed/mature/unspent standard fixtures, obtains
  explicit approval over the exact origin/gate/threshold/output references, and returns only the
  same bounded public response. It is not connected to `OutputManagerHandle`, key-manager APIs,
  wallet files, WASM, or any authorization surface.

## Protocol hardening

The response encoding starts with `GGBP1R` and protocol version 1. It has one fixed grammar and
strictly limits outputs to 16 and the aggregate minimum proof to 8 KiB. It includes network,
genesis, origin, gate identifier, gate configuration version, subject identifier, subject public
key, threshold, nonce, expiry, and a fingerprint of Tari's actual default commitment generators.
Output hashes must be strictly ascending and unique.

Each supported synthetic output has the exact `PushPubKey` script form. Its script key produces a
GGBP-1 output-authority signature over the complete canonical challenge and ordered outputs. The
authenticated subject independently signs the same message in
`com.ghost-gate.ggbp1.subject_binding/v1`. Neither signature uses Tari's script-signing domain;
the test suite reconstructs the first signature under `CheckSigHashDomain` and proves that it
does not verify there.

The response verifier reconstitutes canonical Ristretto points and scalars using Tari's parsers,
recomputes the aggregate public commitment, and checks the real Bulletproofs+ statement against
that recomputed commitment. It does not receive values, masks, script private keys, or the
subject private key.

## Read-only ChainView

The pinned official source is `minotari_app_grpc-6.0.1-pre.2/proto/base_node.proto` and
`transaction.proto`:

- `GetTipInfo`, `GetVersion`, and a height-zero `GetBlocks` request bind a snapshot to the node's
  network, genesis hash, tip hash, height, timestamp, and sync/checkpoint state.
- `SearchUtxos` is called with the proof's public commitment. The returned current-chain
  `HistoricalBlock` must contain the exact output hash and commitment, supplying inclusion height,
  block hash, confirmations, script, script key, maturity, output version/type, and range-proof
  type.
- `FetchMatchingUtxos` is called with the output hash afterward. Presence means it remains in the
  current UTXO set; absence after verified historical inclusion is treated as spent, not as an
  acceptable proof.

The RPC has no portable MMR inclusion proof or authenticated third-party response envelope.
Consequently this adapter is valid only as evidence from a trusted locally controlled, fully
synced node. A public RPC endpoint is intentionally not an eligible `Ggbp1EvidenceSource`.
Before and after output queries, the verifier checks an unchanged fresh tip; any change rejects
the attempt. Later rechecks revoke the experiment's audit record if an output is spent or leaves
the best chain.

## Experimental server state machine

The verifier mints a random single-use server nonce after checking chain freshness. It stores the
complete challenge, including its server-held threshold. Submission is bounded before decoding,
then atomically changes the challenge from `Active` to `Redeeming`. Only the holder that reserved
it can complete public proof and chain checks; concurrent attempts fail rather than creating two
results. A successful response permanently registers every output hash against the challenge and
records `VerifiedNotAuthorized`. A later recheck can only change that audit record to `Revoked`.

Malformed responses, expiry, an origin/gate/configuration/subject mismatch, stale or unsynced
chain evidence, changed output fields, insufficient confirmation, immaturity, unsupported output
format, spent outputs, reorganization, duplicate output use, and invalid proof material all fail
closed. Invalid responses restore an in-flight challenge to `Active`; expiry consumes it.

## Synthetic end-to-end result

The isolated test fixture performs:

```text
server-issued challenge
  -> SyntheticWalletProver
  -> canonical public response
  -> independent Tari crypto verification
  -> synthetic ChainView eligibility check
  -> VerifiedNotAuthorized audit record
  -> spend observation
  -> Revoked audit record
```

The three Phase 2 adversarial fixtures additionally cover oversized responses, expiry, concurrent
redemption, an immature output, an output leaving the best chain, a forged aggregate proof, and a
substituted gate binding. This is a test fixture, not a `TransactionOutput`, a base-node
observation, an Esmeralda result, or a production authorization.

## Web Universe and mobile boundary

The published [`window.tari` integration surface](https://universe.tari.mw/integration/) is an
Ootle provider interface. Its documented ownership proof is a different output/substate scheme
and domain, and its documented private-spend operations are wallet-managed transactions. The
public page does not advertise a Minotari-L1 API that can enumerate confirmed standard outputs,
obtain their openings internally, or issue the GGBP-1 aggregate proof. The L1 page itself exposes
only a WASM loading surface publicly. No JavaScript was injected, no browser storage was read, and
no live wallet was contacted.

An implementation-ready upstream addition for Web Universe, Android, and iOS is therefore a
wallet-core operation, not a browser RPC wrapper:

1. Parse and validate the fixed GGBP-1 request inside the wallet against an approved HTTPS origin.
2. Ask for explicit user approval naming the relying origin, gate, threshold, output count, and
   expiry.
3. Select only eligible standard `PushPubKey` outputs and retain their masks and spending/script
   authorities internally.
4. Build the dedicated-domain output and subject signatures plus the one-aggregate-commitment
   Bulletproofs+ witness internally.
5. Return only the bounded canonical public response and never a raw signing endpoint, opening,
   spending key, view key, or seed phrase.

The Rust core request/response format can be shared by Android and iOS. Platform UI should be
limited to approval, HTTPS transport, cancellation, and response display; it must not reproduce
the cryptographic or key-access operation separately.

## Verdict

| Claim | Result |
| --- | --- |
| Synthetic Tari cryptography | Verified by the isolated harness. |
| Synthetic ChainView/server lifecycle | Verified by an isolated fixture. |
| Locally trusted base-node evidence | Adapter implemented; requires a separately run, controlled synced node. |
| Genuine Esmeralda tXTM output | Not verified. No live node or wallet was contacted. |
| Web Universe proof generation | Not ready; public surface lacks the required L1 wallet-core operation. |
| Production authorization | Not implemented or reviewed. |
