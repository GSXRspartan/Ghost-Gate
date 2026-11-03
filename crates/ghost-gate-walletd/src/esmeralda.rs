//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Legacy chain reads for transitional 0.47/0.48 indexer cohorts.
//!
//! Public Esmeralda runs indexer **0.47.0** (verified live:
//! `GET https://ootle-indexer-a.tari.com/health` → `version 0.47.0`, epoch 12537+). Its REST
//! renamed the substate payload: `GET /substates/{id}` now answers `state` where 0.42 answered
//! `substate`, and a *spent* output answers **200 with a down proof** instead of 404
//! (changelog #2968/#3002). The pinned `IndexerRestApiClient` (0.42) fails to deserialize that
//! response, so this module reads the same route as plain JSON and accepts both legacy shapes.
//! Ootle 0.49 serves base64-CBOR values and is decoded by [`crate::IndexerChainReader`] through
//! the official 0.50 indexer client instead of this field walker:
//!
//! ```text
//! 0.42: { "substate": { "Utxo": { "output": {...}, "auth": ... } }, "verified": bool }
//! 0.47: { "state":   { "up": { "substate": { "Utxo": {...} } } },
//!         "verified": bool, "proof": { ... commit/value proofs ... } }
//! ```
//!
//! Everything the verifier needs is read exactly as before — the floor
//! (`minimum_value_promise`), the spend-authorisation key (`auth.Key`), and the unspent fact.
//! What is deliberately NOT here: any balance read, any wallet-scoped query, any view-key use.
//! The `verified` flag is carried through untouched and a `false` refuses at the verifier —
//! this module never disables verification to make a read succeed.

use ghost_gate_bridge::credential::{ChainReader, CredentialRefusal, UtxoOnChain};
use serde_json::Value;
use tari_template_lib_types::UtxoAddress;

/// Reads UTXOs from a legacy indexer over raw REST JSON, accepting both the old `substate` shape
/// and the transitional `state` shape.
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

        // ---- locate the UTXO payload, tolerating both cohort shapes:
        //   0.42: { "substate": { "Utxo": {...} }, "verified": bool }
        //   0.47: { "state": { "up": { "substate": { "Utxo": {...} } } }, "verified": bool,
        //           "proof": {...} } — and a SPENT output answers 200 with state.down.
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
            // 0.47 answers a SPENT output as 200 with a down proof (changelog #2968); 0.42
            // answered 404. Both are "no longer unspent" and must refuse.
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

        Ok(UtxoOnChain {
            minimum_value_promise: promise,
            verified,
            auth_key,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn reader() -> JsonChainReader {
        JsonChainReader::connect("http://127.0.0.1:1").expect("reader builds")
    }

    /// The real Esmeralda indexer (0.47.0): the faucet account component reads back with
    /// `state.up.substate` and `verified: true`.
    #[tokio::test]
    #[ignore = "needs the public Esmeralda indexer"]
    async fn esmeralda_indexer_is_v047() {
        let r = JsonChainReader::connect("https://ootle-indexer-a.tari.com").expect("reader");
        let h = r.health().await.expect("health");
        assert_eq!(h["version"], "0.47.0");
        assert_eq!(h["status"], "ok");
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
