# XTM L1 wallet compatibility matrix

Audit date: 2026-10-23. Scope is **Minotari L1/XTM**, not Tari Ootle resources. “Supports” below means that the audited public interface supplies the stated primitive; it does not mean Ghost Gate may use it as authorization.

## Sources pinned for this audit

| Surface | Source/release examined | Network/build evidence | Licence/status |
|---|---|---|---|
| Android Tari Wallet | [`wallet-android` `0d4c15c`](https://github.com/tari-project/wallet-android/tree/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b) | App source sets libwallet `v6.1.0`; manifest handles `mainnet`, `nextnet`, `stagenet`, `esmeralda`. | BSD-3-Clause source; active repository. |
| iOS Aurora/Tari Wallet | [`wallet-ios` `e01cc1e`](https://github.com/tari-project/wallet-ios/tree/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04) | `dependencies.env`: mainnet FFI `6.1.0`, nextnet `1.18.0-rc.0`; `tari` URL scheme. | BSD-3-Clause source; active repository. |
| Tari Universe | [`universe` `e9b8d25`](https://github.com/tari-project/universe/tree/e9b8d25773631344a5c996ab459a0fa7d8ce687b) / v1.6.15 source metadata | Tauri desktop; Cargo pins Minotari components to `v6.0.1-pre.2` and Ootle SDK to `v0.44.0`. | CPAL-1.0; active desktop product. |
| Core/console/FFI/Ledger | [`tari` `059491c`](https://github.com/tari-project/tari/tree/059491ce35fbe0b45abefb32332cf372cd4a8f1c) and [v6.2.0 release](https://github.com/tari-project/tari/releases/tag/v6.2.0) | Current release is v6.2.0; the release ships FFI archives and Ledger artifacts. | BSD-3-Clause source; active. |
| Browser `window.tari` | [Sapient Ootle wallet](https://github.com/chironbuilds/tari-wallet/tree/3b3dcac630e55a61756be576349914eca6187442) | Ootle provider contract, not a Minotari L1 wallet API. | Separate L2 implementation. |
| Legacy/community | [`tari-wallet` archived snapshot](https://github.com/tari-project/tari-wallet/tree/33e5d438cbed859b528eaebbb846bbb5d7583f40) | Not a current integration target. | Historical/community only; no security qualification. |

The app-store/release binary is not reproducibly derived here. Version claims are therefore **source configuration claims**, not a claim that a particular installed phone binary contains that FFI.

## Capability matrix

Legend: **Yes** = public surface seen; **Partial** = primitive exists but lacks the proof binding; **No API** = not observed in the audited public integration surface; **Do not use** = deliberately excluded from Ghost Gate authorization.

| Wallet family | Direct signing | Address/identity proof | Output/UTXO access | Threshold proof | Tx build/status | RFC-0154 link | Local bridge | Ghost Gate verdict |
|---|---|---|---|---|---|---|---|---|
| Android official | Partial: `wallet_sign_message` via JNI | Partial: node-identity signature only | Source wrapper asks for all UTXOs and unblinded-output JSON | No challenge-bound output proof | Yes, normal wallet send/sync | Yes; URI is network-checked then opens send UI | JNI in-app only | **Not eligible** until a versioned, consented L1 proof API exists. |
| iOS official | Partial: `wallet_sign_message` | Partial: node-identity signature only | `utxos()` and `unspentOutputs()` wrappers | No challenge-bound output proof | Yes, normal wallet send/sync | Yes; send screen prefill | Swift ↔ XCFramework in-app only | **Not eligible**; additionally fix network validation before relying on deep links. |
| Universe desktop | L1 transaction signing exists internally | No external relying-party proof endpoint found | Internal wallet/config and Minotari client, not a stable RP API | No | Yes | Generates paper-wallet URI; no audited arbitrary RP callback | Tauri IPC is app-local | **Not eligible** without explicit local pairing/RP API. |
| Console wallet + gRPC | Partial: core FFI can sign node identity | Partial | Current FFI has UTXO metadata API | No public threshold/ownership attestation | Yes; TUI, commands, gRPC | No audited mobile deep-link receiver | Local gRPC is possible but must be explicit/user-owned | **Potential future adapter**, not a browser default. |
| Ledger application | Transaction/key-manager signatures with device review | Partial: key/signature primitives are not a RP ownership protocol | Device is not a chain indexer | No | Yes with host wallet | No | USB host protocol only | **Potential future adapter** after a dedicated APDU/protocol, not now. |
| Browser Ootle providers | Ootle-only | Ootle-only | No Minotari L1 output proof API | No | Ootle transactions only | No L1 evidence path | Browser provider | **Do not use** for `minotari_xtm` (guard retained). |
| Archived/community wallet | Unverified | Unverified | Unverified | Unverified | Unverified | Unverified | Unverified | **Do not use**. |

### Source-to-implementation traces

**Android:** URI intent filter → [`DeeplinkParser`](https://github.com/tari-project/wallet-android/blob/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b/app/src/main/java/com/tari/android/wallet/application/deeplinks/DeeplinkParser.kt) checks `authority` against the selected network → [`DeeplinkManager`](https://github.com/tari-project/wallet-android/blob/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b/app/src/main/java/com/tari/android/wallet/application/deeplinks/DeeplinkManager.kt) navigates to `TxSend.Send` → Kotlin [`FFIWallet`](https://github.com/tari-project/wallet-android/blob/0d4c15c94bfdf44df9e4b3721374fa82fdf4d21b/app/src/main/java/com/tari/android/wallet/ffi/FFIWallet.kt) → JNI → `libminotari_wallet_ffi`. `signMessage` signs the wallet/node identity, while `getUnbindedOutputs` serialises local unblinded outputs; neither binds an output to an RP nonce nor proves current chain state.

**iOS:** [`AppDelegate`](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/AppDelegate.swift) accepts `tari:` → [`DeeplinkHandler`](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/Common/Deep%20Links/DeeplinkHandler.swift) → send `PaymentInfo` → Swift [`FFIWalletHandler`](https://github.com/tari-project/wallet-ios/blob/e01cc1e9f14eaaf04c93202ac7a53bcf82d40b04/MobileWallet/Libraries/TariLib/Core/FFIWalletHandler.swift) → XCFramework. `sign(message:)`, `utxos()`, and `unspentOutputs()` are local wallet APIs, not a relying-party protocol.

**Core:** [`wallet_sign_message`](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/base_layer/wallet_ffi/src/lib.rs#L7198) uses the wallet **node identity** secret, not an output spend key. [`wallet_get_utxos`](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/base_layer/wallet_ffi/src/lib.rs#L6658) returns wallet-maintained output metadata. They are useful ingredients, but not evidence of unspentness at a verifier-chosen chain tip.

## Security and release compatibility finding — high

The current v6.2.0 release removed private-key UTXO export because an exported mask/script private key could expose a spend key. The console-wallet documentation says an older `wallet_get_unspent_outputs` export permanently contains the wallet spend key and instructs users to move to a new wallet if it was used. The Android and iOS source snapshots still configure/use 6.1.0 and wrappers named `getUnbindedOutputs`/`unspentOutputs`. Treat those APIs as **sensitive migration hazards**, never as a proof transport, and do not ask users to export them. See the [v6.2.0 release](https://github.com/tari-project/tari/releases/tag/v6.2.0) and [current console-wallet warning](https://github.com/tari-project/tari/blob/059491ce35fbe0b45abefb32332cf372cd4a8f1c/applications/minotari_console_wallet/README.md).

Universe's pinned Minotari dependency (`v6.0.1-pre.2`) also predates v6.2.0. This is a release-engineering/security review item, not evidence that an individual Universe installation leaked keys.

## Compatibility decision

Ghost Gate should keep the existing L2-provider rejection for native XTM gates. It should offer no L1 wallet as an authorization route until it can verify all of: user consent; exact network; challenge domain and expiry; an output-specific ownership signature; a current chain inclusion/unspent proof; and an amount relation without secret export. A generic wallet signature, a displayed balance, a transaction identifier, or a URI-open event is not sufficient.
