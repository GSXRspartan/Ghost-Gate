//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Chain reads from indexer cohorts the pinned v0.42 client cannot parse.
//!
//! Public Esmeralda runs indexer **0.53.2** (verified live:
//! `GET https://ootle-indexer-a.tari.com/health` → `version 0.53.2`, epoch 13020+;
//! `GET https://esme-indexer-a.ootle.tari.com/health` → same instance). The REST API
//! renamed the substate payload at v0.47 and changed it again at v0.53.2 (PRs #3100–#3110):
//! `GET /substates/{id}` now serves `state.up.substate` as a **base64-encoded CBOR blob**
//! (the committee-committed bytes) rather than a JSON projection. This module accepts all three
//! known shapes:
//!
//! ```text
//! 0.42:   { "substate": { "Utxo": { "output": {...}, "is_frozen": false } }, "verified": bool }
//! 0.47:   { "state":   { "up": { "substate": { "Utxo": {...} } } },
//!           "verified": bool, "proof": { ... commit/value proofs ... } }
//! 0.53.2: { "state":   { "up": { "substate": "<base64-cbor>" } }, "verified": bool }
//!           (committed CBOR bytes: `SubstateValue::Utxo`, the derived positional-array encoding)
//! ```
//!
//! Everything the verifier needs is read exactly as before — the floor
//! (`minimum_value_promise`), the spend-authorisation key (`auth.Key`), the frozen flag, and
//! the unspent fact. A burnt output (no output body) refuses here: the engine itself refuses
//! to spend one, and the reader has nothing else to report about it. What is deliberately NOT
//! here: any balance read, any wallet-scoped query, any view-key use.
//! The `verified` flag is carried through untouched and a `false` refuses at the verifier —
//! this module never disables verification to make a read succeed.

use ghost_gate_bridge::credential::{ChainReader, CredentialRefusal, UtxoOnChain};
use serde_json::Value;
use tari_template_lib_types::UtxoAddress;

/// Reads UTXOs from an indexer over raw REST JSON/CBOR, accepting the 0.42 `substate` shape,
/// the 0.47 `state` shape, and the 0.53.2 `state.up.substate` base64-CBOR shape.
pub struct JsonChainReader {
    endpoint: String,
    client: reqwest::Client,
}

impl JsonChainReader {
    pub fn connect(
        endpoint: &str,
    ) -> Result<Self, CredentialRefusal> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .user_agent("ghost-gate-verifier/0.1")
            .build()
            .map_err(|e| {
                CredentialRefusal::Chain(format!("cannot build an HTTP client for {endpoint}: {e}"))
            })?;
        Ok(Self { endpoint, client })
    }

    /// The cohort version the indexer reports, for the compatibility matrix in the logs.
    pub async fn health(&self) -> Result<Value, String> {
        let url = format!("{}/health", self.endpoint);
        let r = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        r.json().await.map_err(|e| e.to_string())
    }
}

impl ChainReader for JsonChainReader {
    async fn utxo(&self, address: &UtxoAddress) -> Result<UtxoOnChain, String> {
        let url = format!("{}/substates/{}", self.endpoint, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("indexer unreachable at {url}: {e}"))?;

        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| format!("unreadable body: {e}"))?;

        // ---- locate the UTXO payload, tolerating all known indexer shapes:
        //   0.42:   { "substate": { "Utxo": {...} }, "verified": bool }
        //   0.47:   { "state": { "up": { "substate": { "Utxo": {...} } } }, "verified": bool }
        //   0.53.2: { "state": { "up": { "substate": "<base64-cbor>" } }, "verified": bool }
        //           and a SPENT output answers 200 with state.down (changelog #2968).

        // v0.53.2: state.up.substate is a base64-encoded CBOR string, not a JSON object.
        if let Some(cbor_blob) = body.pointer("/state/up/substate").and_then(|v| v.as_str()) {
            let verified = body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            return read_utxo_cbor(cbor_blob, address, verified);
        }

        let v047_up = body
            .pointer("/state/up/substate/Utxo")
            .filter(|v| v.is_object());
        let v042_substate = body
            .get("substate")
            .filter(|s| s.get("Utxo").is_some())
            .and_then(|s| s.get("Utxo"));
        // Only treat `state` as a v0.47 shape marker when it carries the up/down envelope —
        // in the 0.42 shape `state` does not exist at the top level, so this is unambiguous.
        let is_v047_shape = v047_up.is_some() || body.get("substate").is_none();

        let down = body.pointer("/state/down").filter(|d| d.is_object());
        if v047_up.is_none() && is_v047_shape {
            // 0.47 and 0.53.2 answer a SPENT output as 200 with a down proof (changelog #2968);
            // 0.42 answered 404. Both are "no longer unspent" and must refuse.
            if down.is_some() {
                return Err(format!("{address} is DOWN on the indexer (spent or destroyed)"));
            }
            if status.as_u16() == 404 {
                return Err(format!("{address} is not known to this indexer"));
            }
            return Err(format!(
                "{address}: unexpected indexer response (HTTP {status}): {}",
                truncated(&body)
            ));
        }

        let utxo = v047_up
            .or(v042_substate)
            .ok_or_else(|| format!("{address}: not a UTXO substate: {}", truncated(&body)))?;

        // verified: both cohorts carry the indexer's own merkle statement at the top level.
        // Fail closed: absent = unverified = refuses at the verifier.
        let verified = body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);

        let output = utxo
            .get("output")
            .ok_or_else(|| format!("{address}: UTXO has no output body"))?;
        // The floor lives inside the output's own output body in both cohorts.
        let promise = output
            .get("output")
            .and_then(|o| o.get("minimum_value_promise"))
            .or_else(|| output.get("minimum_value_promise"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{address}: no readable minimum_value_promise"))?;

        // The spend-authorisation key: `auth.Key` as a hex string in the JSON shapes.
        let auth_key = output
            .get("auth")
            .and_then(|a| a.get("Key"))
            .and_then(|k| k.as_str())
            .and_then(|s| {
                let mut out = [0u8; 32];
                hex::decode_to_slice(s.trim_start_matches("0x"), &mut out).ok()?;
                Some(out)
            });

        // The frozen flag is a serde field of the Utxo struct in both cohorts; an older cohort
        // that did not yet have it simply omits it, which reads as `false` — the flag did not
        // exist for the substate that cohort could hold.
        let is_frozen = utxo
            .get("is_frozen")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(UtxoOnChain {
            minimum_value_promise: promise,
            verified,
            auth_key,
            is_frozen,
        })
    }
}

fn truncated(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 220 {
        format!("{}…", &s[..220])
    } else {
        s
    }
}

/// Decode a v0.53.2 CBOR substate blob and extract the UTXO fields needed for credential
/// verification. The blob is the base64-encoded committee-committed `SubstateValue` bytes: the
/// derived `minicbor` positional-array encoding, not a JSON projection.
///
/// The byte-exact shape, verified live against indexer 0.53.2 (two unspent Esmeralda UTXOs,
/// decoded field by field) and against the upstream derive rules:
///
/// ```text
/// SubstateValue::Utxo:  array(2) [ uint(8),                   // variant index 8 = Utxo
///                                  array(1) [ <Utxo> ] ]      // wrapper: one field
/// Utxo:                 array(2) [ <UtxoOutput>, bool ]       // burnt: array(1) [ bool ] —
///                                                             //   a nil Option is skipped
/// UtxoOutput:           array(3) [ <OutputBody>, <SpendAuthorization>, uint(tag) ]
/// OutputBody:           array(3)|array(4) [ bytes(32) nonce,        // RistrettoPublicKeyBytes
///                                            bytes(80..=335) enc,   // EncryptedData bounds
///                                            uint mvp,
///                                            [viewable_balance] ]   // only when Some:
///                                                                   //   array(2)[bytes(32),
///                                                                   //             bytes(32)]
/// SpendAuthorization:   array(2) [ 0, array(1) [bytes(32)] ]        // Key(spend_key)
///                       array(2) [ 1, array(1) [bytes(32)] ]        // Script(condition_root)
///                       array(2) [ 2, array(2) [bytes(32), bytes(32)] ] // KeyAndScript
/// ```
///
/// Fail-closed choices this decoder makes, each mapped to the engine's own semantics:
/// - **Burnt** (`output: None`, the first `Utxo` field nil so the array shrinks to 1) refuses
///   here: the engine refuses to spend it, and there is no output body to read a floor or key
///   from.
/// - **Frozen** decodes and is carried in `UtxoOnChain::is_frozen` for the verifier to refuse —
///   the fact is real and readable, the RULE lives in the verifier.
/// - **Unknown `SpendAuthorization` variant** refuses outright: a shape this version does not
///   recognise is not an authorisation this version can interpret, and silently reading it as
///   "no key" would hide the anomaly.
/// - Leaf sizes are exact: 32-byte keys and nonce, 80..=335-byte encrypted data, tag within
///   u32 (a `UtxoTag` cannot exceed it), and the tag and any viewable balance are validated
///   even though the verifier never uses them — a blob that does not round-trip the engine
///   schema is not a UTXO this gate should stand on.
fn read_utxo_cbor(blob: &str, address: &UtxoAddress, verified: bool) -> Result<UtxoOnChain, String> {
    use ghost_gate_cbor::{CborValue, decode_committed_base64, Limits};

    let bad = |what: String| format!("{address}: not a 0.53.2 Utxo substate: {what}");
    let committed = decode_committed_base64(blob, Limits::default())
        .map_err(|e| format!("{address}: CBOR decode failed: {e}"))?;
    let val = committed.value();

    // ---- SubstateValue: array(2) [variant index, fields wrapper].
    // A map here is the v0.53.1-and-earlier idea of an enum encoding; this cohort is arrays.
    let top = val.as_array().map_err(|e| bad(format!("top level: {e}")))?;
    if top.len() != 2 {
        return Err(bad(format!(
            "expected [variant, payload], got an array of {}",
            top.len()
        )));
    }
    let variant = top[0]
        .as_u64()
        .map_err(|e| bad(format!("variant index: {e}")))?;
    if variant != 8 {
        return Err(bad(format!("substate variant {variant}, expected 8 (Utxo)")));
    }
    let wrapper = top[1].as_array().map_err(|e| bad(format!("variant payload: {e}")))?;
    if wrapper.len() != 1 {
        return Err(bad(format!(
            "variant payload wraps {} field(s), expected 1",
            wrapper.len()
        )));
    }

    // ---- Utxo: array(1..=2) [Option<UtxoOutput>, is_frozen]. A nil Option is skipped by the
    // derive, so burnt (output = None) reads as array(1) [is_frozen].
    let utxo = wrapper[0]
        .as_array()
        .map_err(|e| bad(format!("Utxo struct: {e}")))?;
    let is_frozen = match utxo.len() {
        1 => {
            // The frozen flag is still the last element; nothing else to read.
            return Err(format!(
                "{address} is burnt on chain: the engine removed its output body"
            ));
        }
        2 => utxo[1]
            .as_bool()
            .map_err(|e| bad(format!("is_frozen: {e}")))?,
        n => return Err(bad(format!("Utxo struct has {n} field(s), expected 1 or 2"))),
    };
    let output = &utxo[0];

    // ---- UtxoOutput: array(3) [OutputBody, auth, tag].
    let out = output
        .as_array()
        .map_err(|e| bad(format!("UtxoOutput: {e}")))?;
    if out.len() != 3 {
        return Err(bad(format!(
            "UtxoOutput has {} field(s), expected 3",
            out.len()
        )));
    }

    // ---- OutputBody: array(3|4) [nonce, encrypted_data, minimum_value_promise, [viewable]].
    let body = out[0]
        .as_array()
        .map_err(|e| bad(format!("OutputBody: {e}")))?;
    if body.len() < 3 || body.len() > 4 {
        return Err(bad(format!(
            "OutputBody has {} field(s), expected 3 or 4",
            body.len()
        )));
    }
    let nonce = body[0].as_bytes().map_err(|e| bad(format!("public_nonce: {e}")))?;
    if nonce.len() != 32 {
        return Err(bad(format!(
            "public_nonce is {} byte(s), expected 32",
            nonce.len()
        )));
    }
    let encrypted = body[1].as_bytes().map_err(|e| bad(format!("encrypted_data: {e}")))?;
    if encrypted.len() < 80 || encrypted.len() > 335 {
        return Err(bad(format!(
            "encrypted_data is {} byte(s), outside EncryptedData's 80..=335",
            encrypted.len()
        )));
    }
    let promise = body[2]
        .as_u64()
        .map_err(|e| bad(format!("minimum_value_promise: {e}")))?;
    if body.len() == 4 {
        // ElgamalVerifiableBalanceBytes { encrypted, public_nonce } — two 32-byte keys. Never
        // used by the gate, but a malformed one means the blob is not an engine value.
        let viewable = body[3]
            .as_array()
            .map_err(|e| bad(format!("viewable_balance: {e}")))?;
        if viewable.len() != 2 {
            return Err(bad(format!(
                "viewable_balance has {} field(s), expected 2",
                viewable.len()
            )));
        }
        for (name, item) in [("encrypted", &viewable[0]), ("public_nonce", &viewable[1])] {
            let b = item
                .as_bytes()
                .map_err(|e| bad(format!("viewable_balance.{name}: {e}")))?;
            if b.len() != 32 {
                return Err(bad(format!(
                    "viewable_balance.{name} is {} byte(s), expected 32",
                    b.len()
                )));
            }
        }
    }

    // ---- SpendAuthorization: array(2) [variant index, fields wrapper].
    let auth = out[1]
        .as_array()
        .map_err(|e| bad(format!("SpendAuthorization: {e}")))?;
    if auth.len() != 2 {
        return Err(bad(format!(
            "SpendAuthorization has {} field(s), expected 2",
            auth.len()
        )));
    }
    let auth_variant = auth[0]
        .as_u64()
        .map_err(|e| bad(format!("SpendAuthorization variant: {e}")))?;
    let fields = auth[1]
        .as_array()
        .map_err(|e| bad(format!("SpendAuthorization fields: {e}")))?;
    let key32 = |item: &CborValue, name: &'static str| -> Result<[u8; 32], String> {
        let b = item.as_bytes().map_err(|e| bad(format!("{name}: {e}")))?;
        let mut out = [0u8; 32];
        if b.len() != out.len() {
            return Err(bad(format!("{name} is {} byte(s), expected 32", b.len())));
        }
        out.copy_from_slice(b);
        Ok(out)
    };
    let auth_key = match (auth_variant, fields.len()) {
        (0, 1) => Some(key32(&fields[0], "spend_key")?),
        // Script: a condition root, no spend key. Ownership cannot be proven against it; the
        // verifier refuses `auth_key: None` as NotKeySpendable, exactly as the JSON path does.
        (1, 1) => {
            let _condition_root = key32(&fields[0], "condition_root")?;
            None
        }
        (2, 2) => {
            let spend_key = key32(&fields[0], "spend_key")?;
            let _condition_root = key32(&fields[1], "condition_root")?;
            Some(spend_key)
        }
        (v, n) => {
            return Err(bad(format!(
                "SpendAuthorization variant {v} with {n} field(s) is not one this version reads"
            )));
        }
    };

    // ---- UtxoTag: a transparent u32, encoded as a bare uint. Bound it: a larger uint is not
    // a tag this engine version can produce.
    let tag = out[2]
        .as_u64()
        .map_err(|e| bad(format!("tag: {e}")))?;
    if tag > u32::MAX as u64 {
        return Err(bad(format!(
            "tag {tag} exceeds u32::MAX; not a UtxoTag this version encodes"
        )));
    }

    Ok(UtxoOnChain { minimum_value_promise: promise, verified, auth_key, is_frozen })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn reader() -> JsonChainReader {
        JsonChainReader::connect("http://127.0.0.1:1").expect("reader builds")
    }

    /// The real Esmeralda indexer (0.53.2 at time of testing): health returns `version` and `status`
    /// at epoch 13020+. Both `ootle-indexer-a.tari.com` and `esme-indexer-a.ootle.tari.com` resolve
    /// to the same instance; `state.up.substate` is a base64-encoded CBOR blob in this version.
    ///
    /// Version is NOT asserted exactly: the semantic contract is that the indexer's minor version
    /// is >= 47 (which selects the CBOR/JSON `state` envelope path). An exact patch pin would cause
    /// a spurious failure after any maintenance release.
    #[tokio::test]
    #[ignore = "needs the public Esmeralda indexer"]
    async fn esmeralda_indexer_reports_v047_or_later() {
        let r = JsonChainReader::connect("https://ootle-indexer-a.tari.com").expect("reader");
        let h = r.health().await.expect("health");
        assert_eq!(h["status"], "ok");
        let version = h["version"].as_str().expect("version is a string");
        // Parse major.minor.patch and confirm minor >= 47 (the CBOR-substate format threshold).
        let parts: Vec<u32> = version
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let minor = parts.get(1).copied().unwrap_or(0);
        assert!(
            minor >= 47,
            "indexer minor version must be >= 47 to serve the CBOR substate format; got {version}"
        );
    }

    #[tokio::test]
    #[ignore = "needs the public Esmeralda indexer"]
    async fn a_v047_component_substate_parses_through_the_state_shape() {
        let url = "https://ootle-indexer-a.tari.com/substates/component_0102030000000000000000000000000000000000000000000000000000000000";
        let body: Value = reqwest::get(url).await.expect("fetch").json().await.expect("json");
        assert!(body.get("state").and_then(|s| s.get("up")).is_some(), "v0.47 shape");
        assert_eq!(body["verified"], true);
        // `proof` is served when the indexer attaches commit/value proofs to this anchor; not
        // every response carries one, so only the shape and the verified flag are asserted.
    }

    // -------------------------------------------------------------------------
    // CBOR regression fixtures — no live indexer required
    // -------------------------------------------------------------------------
    // These tests exercise `read_utxo_cbor` against the byte-exact derived CBOR
    // the 0.53.2 indexer serves (positional-array encoding, not a JSON map):
    //
    //   [8, [ [ output, auth, tag, ] ... ] ]  per the schema in `read_utxo_cbor`'s docs.
    //
    // Two blocks: REAL substates captured live from the public Esmeralda indexer
    // (v0.53.2, epoch 13024+, transaction
    // 4f66d904bbf867cca98f908df8760c286068fb36b49f12ad3c31dfcc24bf4bc0), and
    // hand-crafted blobs for shapes a legit indexer would not serve. Intentionally
    // NOT #[ignore]: CI runs them on every commit that touches the CBOR path.

    /// A real Esmeralda UTXO served by the public 0.53.2 indexer: 335-byte encrypted data
    /// (the maximum), `Key` authorisation, zero floor, not frozen. Its commitment is
    /// cc5dfe4e308ef729b0fc3414e9ad9ab116d7a7b183f83a1a76645f55f438c943.
    const REAL_UTXO_BLOB_MAX_ENCRYPTED: &str = "ggiBgoODWCAEti+WgqP7DfkmFKkI9nwMAR1qo41kk7T1w6c6YiIMKlkBTxfs9hXnAtJ4BYiIJ3gDr66vzXUcKH6GP7UWhN1Z1F8nugfEMM/LtRNXKdygw0tUcyg8wylkmRk2R/3Oyp7jIUx+luEqxv3TtqO3ouQedrUkJrdGXs73dqjILQEy8sEAnDIDqFA/ERN9xDbJemV7FOjmn7QUip0Padhn5INUf2HGjIjJSsbT2SR+yXLoNprzD8b4waneHWEs6oV6RD7qUl9kuBWnV/VwBAR7bFikftxX0zJxGTScANgwv/vyo9TVq7mEmLyfzH6YObUUvBJf+eSX7yhHsrAQ5fMrCDFcEEceFUY2jsba/3SuzYtkXQQzPR36w0RO7XdHjnWjkm8Y6V5gfNjJMTYccofHH0ycOkYMdaQMBRF4733qX9sZyIxJhPQ/EITi3w2E6Vx6qIqr/MbcOwnvgRMYj1H7WC0OrPaXIvbi6aH8eE4udS3yEsZuAIIAgVggGtQJ7I3dYTIv5XCQsd00T7K2a5jiyY6/4xqVStHj7XIakW6ERPQ=";

    /// A real Esmeralda UTXO served by the public 0.53.2 indexer: 80-byte encrypted data
    /// (the minimum), `Key` authorisation, zero floor, not frozen. Its commitment is
    /// 3ca09fcc59fedb81c1fb55d09a36a9c149de6a89e4c3dff5a2269988bee02546.
    const REAL_UTXO_BLOB_MIN_ENCRYPTED: &str = "ggiBgoODWCCGQA4kTzQd+rry3IkvdASas8AOryH1HRNFQoCeww2QQ1hQaB+bs3ueEmw1IeyNxht/FXgSEXRk7ly2pk9LFhE4c9CEdm396GzPZ1vVq5CEsLdKAY02T/t2wHQwFN5ZuI7lkWvraJDHI88NucxymELjN04AggCBWCCS0preHMGtcu/jpv7rniqDmWRD77rTSRKyXchkk7YRTxqQxeSZ9A==";

    /// The real substate address REAL_UTXO_BLOB_MAX_ENCRYPTED was served for.
    const REAL_UTXO_ADDR_MAX: &str =
        "utxo_0101010101010101010101010101010101010101010101010101010101010101\
         _cc5dfe4e308ef729b0fc3414e9ad9ab116d7a7b183f83a1a76645f55f438c943";

    fn real_addr(id_hex: &str) -> UtxoAddress {
        let full = format!(
            "utxo_0101010101010101010101010101010101010101010101010101010101010101_{id_hex}"
        );
        UtxoAddress::from_str(&full).expect("valid utxo address")
    }

    /// Byte offsets into `utxo_cbor_bytes_with_enc` output, asserted by the tests that patch
    /// single bytes. Keeping them named makes a fixture drift a named failure, not a mystery.
    ///
    /// The offsets hold only while `minimum_value_promise` encodes in ONE byte (mvp <= 23):
    /// a wider uint widens the blob and shifts every later offset. The patch tests therefore
    /// all build with mvp = 1, and the big-mvp round-trip is covered separately without
    /// offset patches.
    mod layout {
        pub const BODY_ARRAY: usize = 5;      // OutputBody array(3) header
        pub const ENC_LEN_BYTE: usize = 41;   // length byte of the bytes(80) header (0x50)
        pub const AUTH_VARIANT: usize = 124;  // 0 = Key, 1 = Script, 2 = KeyAndScript
        pub const AUTH_WRAPPER: usize = 125;  // fields wrapper array(1)
        pub const TAG: usize = 160;           // bare uint tag (0x1a + 4 bytes)
        pub const FROZEN: usize = 165;        // is_frozen bool, final byte
        pub const TOTAL: usize = 166;
    }

    /// A minimal well-formed `SubstateValue::Utxo` blob: `Key` authorisation, an 80-byte
    /// encrypted body (the minimum size), no viewable balance, not frozen.
    fn utxo_cbor_bytes(mvp: u64, auth_key: [u8; 32]) -> Vec<u8> {
        utxo_cbor_bytes_with_enc(mvp, auth_key, 80)
    }

    /// The same blob with a chosen encrypted-data length (79 and 336 produce refusals;
    /// 80 and 335 are the real bounds, seen in the live fixtures).
    fn utxo_cbor_bytes_with_enc(mvp: u64, auth_key: [u8; 32], enc_len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        // SubstateValue::Utxo: [8, [Utxo]]
        cbor_array(&mut v, 2);
        v.push(0x08);
        cbor_array(&mut v, 1);
        // Utxo: [Some(output), is_frozen=false]
        cbor_array(&mut v, 2);
        // UtxoOutput: [body, auth, tag]
        cbor_array(&mut v, 3);
        // OutputBody: [nonce(32), encrypted_data(enc_len), minimum_value_promise]
        cbor_array(&mut v, 3);
        v.push(0x58); v.push(32u8); v.extend_from_slice(&[0u8; 32]); // nonce
        cbor_bytes_hdr(&mut v, enc_len); v.extend(std::iter::repeat(0u8).take(enc_len));
        cbor_uint(&mut v, mvp);
        // auth: Key = [0, [spend_key]]
        cbor_array(&mut v, 2);
        v.push(0x00);
        cbor_array(&mut v, 1);
        v.push(0x58); v.push(32u8); v.extend_from_slice(&auth_key);
        // tag: a bare uint (transparent UtxoTag)
        cbor_uint(&mut v, 24_399_391_40);
        // is_frozen: false
        v.push(0xf4);
        v
    }

    fn cbor_bytes_hdr(v: &mut Vec<u8>, len: usize) {
        if len <= 23 { v.push(0x40 | len as u8); }
        else if len <= 0xff { v.push(0x58); v.push(len as u8); }
        else { v.push(0x59); v.extend_from_slice(&(len as u16).to_be_bytes()); }
    }

    fn cbor_array(v: &mut Vec<u8>, n: u8) {
        v.push(0x80 | n);
    }

    fn cbor_uint(v: &mut Vec<u8>, n: u64) {
        if n <= 23 { v.push(n as u8); }
        else if n <= 0xff { v.push(0x18); v.push(n as u8); }
        else if n <= 0xffff { v.push(0x19); v.extend_from_slice(&(n as u16).to_be_bytes()); }
        else if n <= 0xffff_ffff { v.push(0x1a); v.extend_from_slice(&(n as u32).to_be_bytes()); }
        else { v.push(0x1b); v.extend_from_slice(&n.to_be_bytes()); }
    }

    fn to_b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn test_addr() -> UtxoAddress {
        UtxoAddress::from_str(
            "utxo_0101010101010101010101010101010101010101010101010101010101010101\
             _a66c77cfed68833788b9d91dbece3e506cdbc590953d5c8f75ada7043f54b407",
        ).expect("valid utxo address")
    }

    /// The live fixtures are the regression ground truth: if the engine's encoding ever
    /// changes, these two blobs fail first and say so in engine terms, not test terms.
    #[test]
    fn cbor_real_indexer_blob_max_encrypted_data_decodes() {
        let addr = UtxoAddress::from_str(REAL_UTXO_ADDR_MAX).expect("address");
        let r = read_utxo_cbor(REAL_UTXO_BLOB_MAX_ENCRYPTED, &addr, true).expect("real blob decodes");
        assert_eq!(r.minimum_value_promise, 0);
        assert!(r.verified);
        assert!(!r.is_frozen);
        assert_eq!(
            r.auth_key,
            Some([
                0x1a, 0xd4, 0x09, 0xec, 0x8d, 0xdd, 0x61, 0x32, 0x2f, 0xe5, 0x70, 0x90, 0xb1,
                0xdd, 0x34, 0x4f, 0xb2, 0xb6, 0x6b, 0x98, 0xe2, 0xc9, 0x8e, 0xbf, 0xe3, 0x1a,
                0x95, 0x4a, 0xd1, 0xe3, 0xed, 0x72,
            ])
        );
    }

    #[test]
    fn cbor_real_indexer_blob_min_encrypted_data_decodes() {
        let addr = real_addr("3ca09fcc59fedb81c1fb55d09a36a9c149de6a89e4c3dff5a2269988bee02546");
        let r = read_utxo_cbor(REAL_UTXO_BLOB_MIN_ENCRYPTED, &addr, true).expect("real blob decodes");
        assert_eq!(r.minimum_value_promise, 0);
        assert!(r.verified);
        assert!(!r.is_frozen);
        assert_eq!(
            r.auth_key,
            Some([
                0x92, 0xd2, 0x9a, 0xde, 0x1c, 0xc1, 0xad, 0x72, 0xef, 0xe3, 0xa6, 0xfe, 0xeb,
                0x9e, 0x2a, 0x83, 0x99, 0x64, 0x43, 0xef, 0xba, 0xd3, 0x49, 0x12, 0xb2, 0x5d,
                0xc8, 0x64, 0x93, 0xb6, 0x11, 0x4f,
            ])
        );
    }

    /// The crafted fixture's layout matches `layout`: patching tests anchor on these asserts,
    /// so a builder change that shifts a byte is caught by the first test that patches it.
    #[test]
    fn cbor_crafted_fixture_layout_matches_expectations() {
        let v = utxo_cbor_bytes(1, [0u8; 32]);
        assert_eq!(v.len(), layout::TOTAL, "total length");
        assert_eq!(v[layout::BODY_ARRAY], 0x83, "OutputBody array(3)");
        assert_eq!(v[layout::ENC_LEN_BYTE], 0x50, "encrypted data is bytes(80)");
        assert_eq!(v[layout::AUTH_VARIANT], 0x00, "Key variant");
        assert_eq!(v[layout::AUTH_WRAPPER], 0x81, "fields wrapper array(1)");
        assert_eq!(v[layout::FROZEN], 0xf4, "is_frozen=false last");
    }

    #[test]
    fn cbor_valid_blob_extracts_mvp_and_auth_key() {
        let auth = [0x01u8; 32];
        let blob = to_b64(&utxo_cbor_bytes(100_000_000, auth));
        let result = read_utxo_cbor(&blob, &test_addr(), true).expect("valid blob decodes");
        assert_eq!(result.minimum_value_promise, 100_000_000);
        assert!(result.verified);
        assert!(!result.is_frozen);
        assert_eq!(result.auth_key, Some(auth));
    }

    #[test]
    fn cbor_verified_flag_carried_through_unmodified() {
        let blob = to_b64(&utxo_cbor_bytes(50_000_000, [0x02u8; 32]));
        // verified comes from the outer JSON, not the CBOR blob; the CBOR path must not override it.
        let result = read_utxo_cbor(&blob, &test_addr(), false).expect("decodes");
        assert!(!result.verified, "verified=false must survive the CBOR path");
        assert_eq!(result.minimum_value_promise, 50_000_000);
    }

    #[test]
    fn cbor_above_threshold_accepted_below_refused_server_side() {
        // Server-side enforcement is in CredentialVerifier, not here, but the raw amount must
        // survive decode faithfully for that check to work.
        let below = to_b64(&utxo_cbor_bytes(99_999_999, [0x03u8; 32]));
        let r = read_utxo_cbor(&below, &test_addr(), true).expect("decodes");
        assert_eq!(r.minimum_value_promise, 99_999_999);

        let above = to_b64(&utxo_cbor_bytes(100_000_001, [0x04u8; 32]));
        let r = read_utxo_cbor(&above, &test_addr(), true).expect("decodes");
        assert_eq!(r.minimum_value_promise, 100_000_001);
    }

    #[test]
    fn cbor_frozen_flag_is_carried_not_refused_here() {
        // Frozen is a fact the reader carries; refusing it is the verifier's rule. Set the
        // final bool to true and assert it decodes with is_frozen=true.
        let mut bytes = utxo_cbor_bytes(1, [0x05u8; 32]);
        bytes[layout::FROZEN] = 0xf5; // true
        let r = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).expect("frozen blob decodes");
        assert!(r.is_frozen, "the frozen flag must reach the verifier's input");
        assert_eq!(r.auth_key, Some([0x05u8; 32]));
    }

    #[test]
    fn cbor_script_authorisation_decodes_with_no_key() {
        // SpendAuthorization::Script = [1, [condition_root]]: no spend key exists, so
        // ownership cannot be proven — the reader reports None and the verifier refuses.
        let mut v = utxo_cbor_bytes(1, [0x06u8; 32]);
        v[layout::AUTH_VARIANT] = 0x01;
        let r = read_utxo_cbor(&to_b64(&v), &test_addr(), true).expect("script auth decodes");
        assert_eq!(r.auth_key, None, "script-only auth has no spend key");
        assert_eq!(r.minimum_value_promise, 1);
    }

    #[test]
    fn cbor_key_and_script_authorisation_yields_the_spend_key() {
        // SpendAuthorization::KeyAndScript = [2, [spend_key, condition_root]].
        let mut v = utxo_cbor_bytes(1, [0x07u8; 32]);
        v[layout::AUTH_VARIANT] = 0x02;
        v[layout::AUTH_WRAPPER] = 0x82;
        // Insert the condition root right after the spend key payload.
        let mut out = v[..layout::TAG].to_vec();
        out.extend_from_slice(b"\x58\x20");
        out.extend_from_slice(&[0x0bu8; 32]);
        out.extend_from_slice(&v[layout::TAG..]);
        let r = read_utxo_cbor(&to_b64(&out), &test_addr(), true).expect("key+script decodes");
        assert_eq!(r.auth_key, Some([0x07u8; 32]), "the spend key is the ownership key");
    }

    #[test]
    fn cbor_viewable_balance_present_decodes() {
        // OutputBody with a viewable balance: array(4), the ElgamalVerifiableBalanceBytes pair
        // appended after minimum_value_promise.
        let mut v = utxo_cbor_bytes(1, [0x08u8; 32]);
        v[layout::BODY_ARRAY] = 0x84;
        let mut out = v[..layout::AUTH_VARIANT - 1].to_vec();
        out.extend_from_slice(b"\x82\x58\x20");
        out.extend_from_slice(&[0x0cu8; 32]);
        out.extend_from_slice(b"\x58\x20");
        out.extend_from_slice(&[0x0du8; 32]);
        out.extend_from_slice(&v[layout::AUTH_VARIANT - 1..]);
        let r = read_utxo_cbor(&to_b64(&out), &test_addr(), true).expect("viewable decodes");
        assert_eq!(r.minimum_value_promise, 1);
        assert_eq!(r.auth_key, Some([0x08u8; 32]));
    }

    #[test]
    fn cbor_burnt_utxo_is_refused_here() {
        // Utxo with output=None: the Option nil is skipped, so the struct is array(1)[frozen].
        let mut b = Vec::new();
        cbor_array(&mut b, 2);
        b.push(0x08);
        cbor_array(&mut b, 1);
        cbor_array(&mut b, 1); // Utxo: array(1) — output nil, skipped
        b.push(0xf4);          // is_frozen=false
        let err = read_utxo_cbor(&to_b64(&b), &test_addr(), true).unwrap_err();
        assert!(err.contains("burnt"), "got: {err}");
    }

    #[test]
    fn cbor_wrong_variant_is_refused() {
        // [9, [...]] — variant 9 is ConfidentialOutput, not Utxo.
        let mut bytes = utxo_cbor_bytes(1, [0x0au8; 32]);
        bytes[1] = 0x09;
        let err = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).unwrap_err();
        assert!(err.contains("variant 9, expected 8"), "got: {err}");
    }

    #[test]
    fn cbor_map_form_top_level_is_refused() {
        // A map-shaped enum {"Utxo": ...} is the pre-0.53 idea of the encoding; refuse it
        // rather than guessing.
        let mut bytes = Vec::new();
        bytes.push(0xa1); // map(1)
        bytes.extend_from_slice(b"\x64Utxo");
        bytes.push(0xf6); // true (payload, whatever it is — never reached)
        let err = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).unwrap_err();
        assert!(err.contains("top level"), "got: {err}");
    }

    #[test]
    fn cbor_unknown_spend_authorisation_variant_is_refused() {
        // variant 3 with one field: not Key, Script or KeyAndScript.
        let mut v = utxo_cbor_bytes(1, [0x0bu8; 32]);
        v[layout::AUTH_VARIANT] = 0x03;
        let err = read_utxo_cbor(&to_b64(&v), &test_addr(), true).unwrap_err();
        assert!(err.contains("SpendAuthorization variant 3"), "got: {err}");
    }

    #[test]
    fn cbor_encrypted_data_below_minimum_is_refused() {
        // 79-byte encrypted data: below EncryptedData's 80-byte floor.
        let bytes = utxo_cbor_bytes_with_enc(1, [0x0cu8; 32], 79);
        let err = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).unwrap_err();
        assert!(err.contains("outside EncryptedData's 80..=335"), "got: {err}");
    }

    #[test]
    fn cbor_encrypted_data_above_maximum_is_refused() {
        // 336-byte encrypted data: above EncryptedData's 335-byte ceiling.
        let bytes = utxo_cbor_bytes_with_enc(1, [0x11u8; 32], 336);
        let err = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).unwrap_err();
        assert!(err.contains("outside EncryptedData's 80..=335"), "got: {err}");
    }

    #[test]
    fn cbor_encrypted_data_at_exact_maximum_decodes() {
        // 335-byte encrypted data: the ceiling, as the real indexer fixture shows.
        let bytes = utxo_cbor_bytes_with_enc(1, [0x0fu8; 32], 335);
        let r = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).expect("max-size blob decodes");
        assert_eq!(r.auth_key, Some([0x0fu8; 32]));
    }

    #[test]
    fn cbor_trailing_bytes_are_refused() {
        let mut bytes = utxo_cbor_bytes(1, [0x0du8; 32]);
        bytes.push(0x00); // one stray byte after a complete value
        let err = read_utxo_cbor(&to_b64(&bytes), &test_addr(), true).unwrap_err();
        assert!(err.contains("trailing"), "got: {err}");
    }

    #[test]
    fn cbor_bad_base64_is_refused() {
        let err = read_utxo_cbor("not!valid!base64@@@", &test_addr(), true).unwrap_err();
        assert!(err.contains("CBOR decode failed"), "got: {err}");
    }

    #[test]
    fn cbor_truncated_cbor_is_refused() {
        // array(2) header, then nothing — truncated CBOR
        let err = read_utxo_cbor(&to_b64(&[0x82]), &test_addr(), true).unwrap_err();
        assert!(err.contains("CBOR decode failed"), "got: {err}");
    }

    #[test]
    fn cbor_absent_auth_key_still_gives_none_not_error() {
        // A UTXO may legitimately have no spend-authorisation key (a Script-only auth path).
        // The function must return Ok with auth_key=None, not Err.
        let mut v = utxo_cbor_bytes(1, [0x0eu8; 32]);
        v[layout::AUTH_VARIANT] = 0x01; // Script
        let r = read_utxo_cbor(&to_b64(&v), &test_addr(), true)
            .expect("script auth should decode, not error");
        assert_eq!(r.minimum_value_promise, 1);
        assert_eq!(r.auth_key, None, "script auth must be None");
    }

    #[tokio::test]
    #[ignore = "needs the shared localnet indexer"]
    async fn a_v042_utxo_substate_parses_through_the_substate_shape() {
        // The localnet's indexer stays 0.42: the SAME reader must keep parsing it, which is the
        // whole point of the dual-shape reduction. Uses the real Swap Alice output.
        let r = JsonChainReader::connect("http://127.0.0.1:12007").expect("reader");
        let addr = UtxoAddress::from_str(
            "utxo_0101010101010101010101010101010101010101010101010101010101010101_a66c77cfed68833788b9d91dbece3e506cdbc590953d5c8f75ada7043f54b407",
        ).expect("utxo id");
        let on_chain = r.utxo(&addr).await.expect("the output is on chain");
        assert!(on_chain.verified);
        assert_eq!(on_chain.minimum_value_promise, 0, "faucet-minted, no promise");
        assert!(on_chain.auth_key.is_some());
    }
}
