# M14 — real mainnet TARI output verification

Builds on M13’s release-derived validator-set anchor and signed checkpoint verifier.

## What was implemented

`tools/m13-mainnet-verifier/src/bin/output.rs`:

- Walks signed handovers from epoch 38362 to current mainnet epoch using the official v0.55.0 light client.
- Fetches a real native TARI stealth output and its authenticated substate proof.
- Decodes `SubstateValue::Utxo` and checks:
  - resource address equals `STEALTH_TARI_RESOURCE_ADDRESS`;
  - network is mainnet (`0x00`) via the trusted checkpoint chain;
  - `minimum_value_promise >= 1_000_000 µTARI`;
  - `is_frozen == false`;
  - key-path spend authorization is present;
  - the canonical commitment matches the `utxo_…` substate id;
  - the authenticated proof anchor is within two epochs of current;
  - `/substates/versions` still reports the same version (liveness hint only);
  - a fresh unversioned read still returns Up (newer state invalidates older evidence).
- Reproduces Ghost Gate’s ownership-proof message domain and signature verification, and proves a substituted challenge fails.
- Refuses a known spent output because the indexer supplies only an exclusion proof with no authenticated down proof.

## Run

```powershell
$env:CARGO_TARGET_DIR='D:\pb-target\m13'
cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin output -j 1
```

## Result

```text
checkpoint walk: 912 handovers, trusted epoch Epoch(39274)
adversarial: wrong resource, frozen, insufficient promise, stale age, withheld checkpoints fail closed
ownership binding: valid challenge verifies, substituted challenge fails
spent fixture: refused (no authenticated down proof)
verified evidence: {"gate_id":"Crypt","network":0,"policy_hash":"13af…0b74f","output_id":"utxo_0101…a664f","commitment_hex":"a8cbdc65…e52a664f","minimum_value_promise":11000000,"frozen":false,"state":"Up","anchor_epoch":39274,"anchor_height":21,"evidence_age_epochs":0,"relying_origin":"https://ghostgate.boo"}
RESULT: real mainnet TARI output authentic Up state verified; no authorization issued
```

## Protocol finding — current unspent

A verified `Up` state at a recent quorum-signed anchor is the protocol’s positive evidence that the output was in the committed state tree at that finalized block. Freshness is a separate policy check.

A missing `down_proof` on an `Up` answer is normal. A `Down` answer with no `down_proof` is only an exclusion proof and does **not** prove the output was ever Up; it must not be treated as authenticated spent evidence. Across a large sample of spent native TARI outputs, none had a `down_proof`, so authenticated spent-state rejection remains a protocol/deployment evidence gap.

## Remaining blockers

- No authenticated down proof available for spent outputs from the public indexers.
- No real Sapient ownership signature over a Ghost Gate challenge; the binding logic is tested with a generated key only.
- No base-layer epoch cross-check for stronger liveness/freshness.
- No connection to Ghost Gate production trust tiers or session issuance.
- M12 H-01/H-02 Telegram security items remain outstanding.

**M14 status: standalone non-authorizing verifier GO; Ghost Gate backend integration NO-GO pending review.**
