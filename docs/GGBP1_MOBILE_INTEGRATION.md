# GGBP-1 Mobile and Deep-Link Integration Draft

**Status: interface proposal only. No Android, iOS, desktop, or browser wallet is modified.**

## Request / response envelope

The transport carries a versioned binary payload (for example canonical CBOR) whose hash is shown to the user and signed by the wallet-built `BalanceProofDomain` operation. JSON is diagnostic only and must not be signed directly.

```text
BalanceProofRequestV1 {
  version, network, genesis_hash, origin, gate_id, subject_id,
  threshold_micro_xtm, nonce_32, issued_at, expires_at,
  callback_origin, callback_path, tip_anchor, max_outputs
}

BalanceProofResponseV1 {
  version, request_hash, ordered_output_hashes, per_output_authority,
  aggregate_commitment, aggregate_minimum_proof, observed_tip, wallet_capabilities
}
```

The response deliberately contains no seed, spend key, view key, mask, decrypted output export, or arbitrary signature. The precise proof fields remain unassigned until the upstream aggregate proof format is cryptographically reviewed.

## Proposed entry points

Same-device requests may use:

```text
tari://<network>/proofs/balance?request=<base64url-canonical-request>
```

The URI is a proposal, not a registered interface. The wallet must require HTTPS-backed request retrieval or embedded data whose hash matches a user-visible, HTTPS-origin challenge. It must reject nonmatching `network`/genesis and non-HTTPS callbacks. The callback is restricted to the exact authenticated origin and registered path; no open redirects, custom arbitrary schemes, fragments containing proof data, or cross-origin redirects.

For cross-device operation Ghost Gate displays the same canonical request and its SHA-256 digest as a QR code. The mobile wallet fetches/verifies the HTTPS challenge independently, displays it, and sends the result only to the fixed HTTPS response endpoint after approval. Scanning a QR code is never approval.

## Mandatory wallet experience

Before producing anything, the wallet displays:

- requester origin, network/genesis, gate and subject binding;
- threshold, expiry, proof purpose, and maximum number of selected outputs;
- output-reference and linkage disclosure warning;
- explicit cancellation and no-background-approval behavior.

The operation can select only currently eligible outputs after it has checked local authority. It does not transfer, lock, burn, claim, submit, or construct a transaction. The wallet must refuse when its synchronized chain view is unavailable or when it lacks the reviewed GGBP-1 capability.

## Platform adapter rules

Android JNI and iOS Swift bindings must call a common native Rust implementation; neither platform may reimplement proof arithmetic, message encoding, or signing domain in Kotlin/JavaScript/Swift. The FFI accepts a bounded canonical request and returns either a bounded response or explicit capability/error state. It never offers raw-key export, arbitrary message signing, arbitrary script signing, or raw commitment-opening access to an app/dApp.

Desktop Universe and Ledger adapters are optional and separate. A Ledger integration requires a device-reviewed application command, secure display of the complete request, and a demonstrated ability to access the required output witness without exporting it. A generic Ledger signature is not enough.

## Readiness

No currently audited Android/iOS wallet exposes the required aggregate proof plus output-authority operation. The mobile flow is therefore implementation-ready only as an API and UX specification; it is not ready to authenticate an Esmeralda or mainnet gate.
