# Web Universe / Esmeralda tXTM GGBP-1 Assessment

**Status: source-audited integration assessment; no Web Universe site, storage, seed, wallet, or network account was accessed. No live proof was generated.**

## Product separation

The chironbuilds Web Tari Universe implementation is a browser Minotari L1 wallet and is distinct from both official Tari Universe desktop and Sapient's Ootle provider. The community announcement says it supports Esmeralda L1 and L1-to-L2 burn/claim; that is not evidence of a GGBP-1 interface.

This assessment examined the public repository [`chironbuilds/tari-l1-wallet-ui` at `f8fcedc`](https://github.com/chironbuilds/tari-l1-wallet-ui/tree/f8fcedc79b8272c952c15627c1fba10f6bcec969), not a running wallet. Its package identifies the vendored L1 dependency as `@chironbuilder/tari-l1-wasm` `5.6.0-pre.7`, pointing at Tari's `base_layer/tari_l1_wasm`. This is a different, older prerelease cohort than this repository's `6.0.1-pre.2` audit target, so API and proof compatibility are unverified.

## Confirmed public WASM capabilities

The declaration file at the pinned source commit exposes:

- `WasmWallet.importScannedOutput`, which internally decrypts/verifies scanned output material and yields a spendable output;
- `WasmWalletOutput` `chainOutputHash`, `commitmentHex`, and `valueMicro` to the Web Universe app;
- `WasmTxBuilder` and `WasmBurnBuilder` for fully signed L1 transactions, including range proofs;
- low-level `commitValue` / `openValue` helpers and generic `WasmSchnorrSignature.sign`;
- `WasmWallet.getBackupHex`, `WasmKeyPair.secretKeyHex`, and address key fields.

The last group is a hard boundary: it is public application/WASM surface, not a safe third-party dApp API. Ghost Gate must never invoke or request those secret/raw-signing interfaces. The public declarations do not show a wallet-approved, output-specific `BalanceProofDomain` signer, an aggregate-sum proof builder, proof-response callback, or authenticated external L1 dApp contract. Likewise, Web Universe's Ootle `window.tari` dApp material must remain rejected for an L1 gate.

## Integration decision

| Option | Result |
| --- | --- |
| A. Use the existing Web Universe API directly | **Not possible safely.** No dedicated L1 proof-provider API is declared. |
| B. Add a reviewed GGBP-1 WASM module | **Possible only after upstream cryptographic/API review.** It needs a non-exporting wallet-internal boundary and compatible Tari dependency verification. |
| C. Cooperate with chironbuilds on an opt-in protocol | **Smallest credible future path.** Build B inside Web Universe with explicit approval and the common GGBP-1 response format. |

No existing output opening, generic signature, or local `valueMicro` field is sufficient evidence for Ghost Gate. An aggregate over selected commitments additionally requires masks and a reviewed aggregate-sum minimum proof; neither may leave the wallet.

## Minimum Web Universe changes

Keep all key material within the WASM/Rust wallet and add one high-level operation:

```text
requestBalanceProof(canonicalRequest) -> approval preview -> user approval -> canonical response
```

It must accept only the bounded canonical GGBP-1 request, independently verify Esmeralda network/genesis and an HTTPS same-origin callback allowlist, query/authenticate required chain data, select eligible current outputs, and return only output references, authority proofs, aggregate proof, and observed-tip evidence. It must refuse arbitrary messages, raw keys, masks, scripts, callbacks, and background requests. A confirmation screen must display origin, threshold, output-reference disclosure, expiry, and cancellation. Expected proof size is intentionally **TBD** until the reviewed aggregate encoding is defined; it must be capped before implementation.

The work can remain within Web Universe only after the core aggregate proof primitive and evidence contract are independently reviewed. It should not reuse Web Universe's generic raw signing method.

## Chain data and synthetic status

The source shows scanning/import of full L1 output fields and local transaction construction, which is promising for a future wallet adapter. This review did not establish a tamper-resistant, independently authenticated current-UTXO query path suitable for Ghost Gate; that must be specified and tested against Esmeralda separately.

A lower-level synthetic Rust proof is now verified separately; it shows that a wallet holding all openings can construct a single minimum proof over an aggregate commitment. It does not validate Web Universe: the audited browser-wallet surface still lacks the reviewed, wallet-internal authority and aggregate-proof API required to use that construction safely. No synthetic result is represented as an Esmeralda proof; see [GGBP1_CRYPTOGRAPHIC_SPIKE.md](GGBP1_CRYPTOGRAPHIC_SPIKE.md).

## Future authorized test procedure

After independent review and an implemented capability, a user may opt in to a testnet-only test:

1. Confirm Web Universe version, source/build hash, Esmeralda network and genesis in its own UI.
2. Open a Ghost Gate test-only L1 gate and obtain a short-lived HTTPS challenge; inspect origin, threshold, expiry, and disclosure in the wallet.
3. Approve only the dedicated balance-proof operation; verify it says no send, lock, burn, claim, or key export.
4. Submit the returned proof to the fixed HTTPS origin and have the independent verifier fetch chain evidence and report either a bounded test result or an explicit failure state.
5. Do not enable production authorization from that result. Retain no seed, private key, mask, or unlocked wallet data in Ghost Gate.

Until then, the correct result for an existing funded tXTM wallet is `UnavailableUpstreamProofApi`, not a failed balance assertion and not a request to unlock or export the wallet.

## Concise proposal for chironbuilds

“Please consider a reviewed, opt-in `GGBP-1` capability in the L1 WASM wallet: it receives only a canonical, bounded challenge; shows origin/network/genesis/threshold/output-reference disclosure; and after explicit approval returns an output-specific, domain-separated authority proof plus a reviewed aggregate-commitment minimum proof and synchronized chain evidence. It must not expose seeds, keys, masks, raw signing, arbitrary scripts, or callbacks. A shared Rust test-vector suite should verify Esmeralda fixtures before any live-wallet test.”
