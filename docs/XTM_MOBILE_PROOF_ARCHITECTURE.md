# XTM mobile proof architecture

This is a design for a future Minotari L1 proof adapter. It is **not implemented** by the Android/iOS wallets audited on 2026-10-23, and it must not be approximated with a wallet-wide message signature or an unblinded-output export.

## What exists today

RFC-0154 defines a payment intent: `tari://{network}/transactions/send?tariAddress=…&amount=…&note=…`. Android validates its URI authority against the selected network before navigating to the send form; iOS accepts `tari:` then presents its send flow. That is valuable payment UX, but neither interface returns a signed result to the requesting app or attests an owned, unspent output. See [RFC-0154](https://rfc.tari.com/RFC-0154_DeepLinksConvencion), [Android parser](https://github.com/tari-project/wallet-android/blob/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b/app/src/main/java/com/tari/android/wallet/application/deeplinks/DeeplinkParser.kt), and [iOS handler](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/Common/Deep%20Links/DeeplinkHandler.swift).

The project now has `inspectMinotariSendDeepLink` in `web/js/ghost/capabilities.js`. It only syntactically inspects synthetic RFC-0154 send intents and always returns `canAuthorizeGate: false`; it does not open the URI, request a wallet, build a transaction, or transmit data.

## Required proof protocol

```text
Relying party                 Mobile wallet                 verifier / Minotari node
      | issue short-lived, origin-bound challenge |
      |------------------------------------------>|
      |      wallet shows disclosure + output      |
      |      derives/proves eligible output locally|
      |<--- proof package, only after approval ----|
      |----------------------------------------------> verify inclusion + unspent at pinned tip
      |<----------------- signed verdict / failure --|
```

### Challenge fields

The challenge must include a version, RP origin/app identity, network identifier/genesis binding, nonce, issued/expiry time, requested threshold in microTari, protocol/domain tag, and a verifier key or callback binding. Reject a reused nonce, wrong network, stale tip, wrong origin, unknown version, or response not bound to all fields.

### Privacy-preserving proof package

Preferred package:

1. Output commitment (or a verifier-safe output reference), network and chain-tip hash/height.
2. A proof that the referenced output is included and unspent at that tip, verified independently by the RP or a pinned node service.
3. A zero-knowledge/range proof that its value is at least the requested threshold, or a protocol-defined equivalent that reveals only the approved threshold relation.
4. An output-spend-key (or output-specific authorized-key) signature over the canonical challenge and output reference.
5. Wallet/app version and capability version—not a wallet brand assertion.

The verifier must not accept raw unblinded-output JSON, a commitment mask, script private key, view key, seed, screen image, wallet balance, transaction status, or a transaction hash in place of those proofs. The v6.2.0 release removed unsafe UTXO private-key export; that reinforces this boundary. [Console warning](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/applications/minotari_console_wallet/README.md).

## Minimal upstream API proposal

Add a versioned, opt-in `prove_output_threshold` operation to native wallet SDKs/FFI, not a browser-injected API:

```text
request:
  protocol_version, challenge_bytes, required_value_micro,
  network_genesis, verifier_policy, expiry
response:
  protocol_version, output_ref, ownership_signature,
  amount_relation_proof, inclusion_or_sync_anchor, disclosure_summary
```

Properties:

- The wallet selects an eligible output; the RP cannot enumerate a wallet’s UTXOs.
- The app renders a human-readable approval screen: site/app, network, expiry, threshold, data released, and linkability warning.
- Signing uses a domain-separated output-authority key and a device/user approval, never `wallet_sign_message`’s node identity key.
- The returned proof contains no spend key, mask, script key, seed, or broad balance.
- The interface distinguishes `unsupported`, `user_rejected`, `locked`, `wrong_network`, `not_synced`, `no_eligible_output`, `proof_expired`, and `verification_failed`.
- Chain verification occurs against a stated tip with reorg/finality policy; a local wallet cache alone is insufficient.

## Transport choices

1. **Native app callback (recommended for mobile):** an app/universal link starts approval and a registered callback returns an encrypted/signed proof package. Bind callback URI and RP key in the challenge; do not put proofs in a URL query.
2. **Local paired bridge (desktop/console):** mutually authenticated localhost IPC after visible pairing. Default deny and show the RP identity on every proof request. Never silently expose the wallet gRPC port to web content.
3. **QR exchange:** a compact request QR and encrypted response QR are appropriate when a callback cannot be trusted. They still require the same nonce, network, expiry, and verifier checks.

RFC-0154 send links can remain an optional “fund a dedicated output” UX step, but must be separate from the proof request and must not be automatically opened by Ghost Gate.

## Current bugs/risk decisions

- Android’s source performs selected-network URI matching before send navigation. Preserve that property in any new proof link.
- The iOS `DeepLinkFormatter.model` reads a host but, in the audited code, does not compare it to `NetworkManager.shared.selectedNetwork`; its test called `invalid_network` only exercises a URL whose host is invalid. File an upstream issue and add a positive test for a syntactically valid *different* network before accepting a proof link. [Formatter](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/Common/Deep%20Links/Data%20Handling/DeepLinkFormatter.swift).
- Do not reuse the `paper_wallet` deep-link mechanism for proofs. It carries recovery material and belongs to recovery/backup flows only.

## Deployment gates

Enable an L1 proof adapter only after independent crypto review, mobile UX review, testnet interoperability across Android/iOS/desktop, release-version allowlisting, chain-tip/reorg tests, callback-origin tests, and a documented revocation/upgrade policy. Until then the correct product state is “L1 wallet recognized, proof method unavailable”—not a fallback to Ootle `window.tari` and not a request to move funds.
