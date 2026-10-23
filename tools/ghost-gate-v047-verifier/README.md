# Ghost Gate Tari Ootle v0.47 consensus adapter

This independent Cargo workspace uses the official Tari Ootle source at tag `v0.47.0`, commit
`9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`. It is intentionally not a member of the root Ghost
Gate workspace, which remains pinned to the incompatible v0.42 cohort for the legacy local bridge.

It requires a read-only checkout at `../../.tari-v047-reference`. Bootstrap it explicitly (never
as part of a browser or Worker start):

```powershell
git clone --depth 1 --branch v0.47.0 https://github.com/tari-project/tari-dan.git .tari-v047-reference
cargo test --manifest-path tools/ghost-gate-v047-verifier/Cargo.toml
```

`PinnedConsensusVerifier` has no TOFU or re-anchor operation. Production configuration must supply
an independently authenticated validator-set hash, epoch, network and walk-shard. Indexer committee,
checkpoint and proof responses remain untrusted until the upstream v0.47 verifier validates them.

This adapter verifies consensus inclusion only. It does not convert a browser wallet connection,
ownership signature, claimed balance, or stale evidence into Ghost Gate eligibility. The hosted
verifier remains fail-closed until this adapter is exposed through an authenticated service with a
configured anchor and the verified output is connected to the credential verifier.
