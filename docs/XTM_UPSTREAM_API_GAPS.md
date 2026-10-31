# XTM upstream API gaps and recommended next steps

## Executive decision

There is no audited public Android, iOS, Universe, console, Ledger, or browser interface that currently provides a user-approved, challenge-bound proof that a Minotari L1 output is both controlled by the user and currently meets an XTM threshold. This is an API/protocol gap, not a reason to reinterpret Ootle `window.tari` as L1 evidence.

## Findings ranked by priority

| Priority | Gap | Evidence | Recommended owner/action |
|---|---|---|---|
| P0 | Unsafe output-secret export must not be a proof workaround | v6.2.0 removed private-key UTXO export; console docs warn older exports expose a spend key. | Core/mobile maintainers: remove stale wrappers, upgrade/pin tested archives, add CI header-surface checks. |
| P0 | No output-specific ownership proof API | `wallet_sign_message` signs the wallet node identity, not an output-specific key. | Core wallet/FFI: design domain-separated `prove_output_threshold`; crypto review before implementation. |
| P0 | No verifier-grade current unspent/inclusion witness | Wallet UTXO APIs describe local state; a RP needs a chain-tip-bound independent witness. | Core/node: define proof format plus base-node verification endpoint and reorg policy. |
| P0 | No privacy-preserving amount relation | Existing UTXO/display data is not a minimal threshold proof. | Protocol/core: specify range/threshold proof and disclosure semantics. |
| P1 | Mobile callback/consent contract absent | RFC-0154 is a payment-intent convention, not a proof callback protocol. | Mobile teams: registered callback/QR response with RP binding and explicit approval UI. |
| P1 | iOS does not visibly compare URI host to selected network | Audited formatter only requires a non-nil URL host; handler accepts `tari:`. | iOS: reject mismatch and add a valid-but-wrong-network regression test. |
| P1 | Desktop/local APIs are not an RP contract | Universe is a Tauri desktop app with internal wallet/IPC, not an externally consented proof bridge. | Universe: only consider a mutually authenticated local pairing API after P0 proof format is stable. |
| P1 | Release skew/security posture | Android/iOS source pins 6.1.0; Universe pins v6.0.1-pre.2; Tari release is v6.2.0. | Release managers: compatibility matrix, upgrade plan, binary provenance, migration notice. |
| P2 | Hardware-wallet proof semantics absent | Ledger has device-reviewed transaction/key-manager commands but no RP-output proof protocol. | Ledger/core: add a new reviewed APDU only after the host/verifier protocol is specified. |
| P2 | Browser provider boundary is ambiguous to integrators | `window.tari` belongs to Ootle provider flows. | Dapp docs: explicitly namespace L1/L2 APIs and make L1 proof capability discovery fail closed. |

## Evidence details

- Core [`wallet_sign_message`](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/base_layer/wallet_ffi/src/lib.rs#L7198) uses the node identity secret. It can prove control of that public identity only when a verifier knows/accepts it; it does not establish that a particular output is unspent or valuable.
- Core [`wallet_get_utxos`](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/base_layer/wallet_ffi/src/lib.rs#L6658) is a wallet-local output query. Android/iOS wrappers make it unsuitable to expose as a web-proof API, especially given the export incident.
- Android maps an RFC-0154 send link to a normal send-screen navigation, not a background payment or a proof. [Source](https://github.com/tari-project/wallet-android/blob/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b/app/src/main/java/com/tari/android/wallet/application/deeplinks/DeeplinkManager.kt).
- iOS maps a send link to `presentSendTransaction`, also a normal review path. [Source](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/Common/Deep%20Links/DeepLinkDefaultActionsHandler.swift).
- The Ledger application has transaction/key-manager signing handlers with review behaviour, but this is not itself an output-value attestation protocol. [Source](https://github.com/tari-project/tari/tree/059491ce35fbe0b45abefb32332cf372cd4a8f1c/applications/minotari_ledger_wallet).

## Secure API shape (proposal, not a claim of support)

```text
WalletCapabilitiesV1 {
  minotari_output_threshold_proof: false | true,
  networks: [genesis-bound ids],
  proof_versions: [...],
  transport: native_callback | paired_local | qr
}

prove_output_threshold(request) ->
  Unsupported | UserRejected | Locked | WrongNetwork | NotSynced |
  NoEligibleOutput | Proof { version, response, verifier_binding }
```

The wallet must present the RP identity, amount threshold, network, proof lifetime, exact disclosure, and a linkability warning. The request/response must be canonical bytes with test vectors. The verifier must resolve/verify the chain witness independently; it must not trust a wallet-claimed balance.

## Changes made in Ghost Gate

The existing L2-provider guard remains untouched: a `minotari_xtm`/`xtm` gate rejects browser `window.tari` before connecting or requesting a challenge. This audit adds a tested `inspectMinotariSendDeepLink` helper that diagnoses only the RFC-0154 send-intent syntax and hard-codes `canAuthorizeGate: false`. It does not generate/open links, call a wallet, or submit a transaction.

That is intentionally small: broad integration would be unsafe until the P0 upstream gaps are closed.
