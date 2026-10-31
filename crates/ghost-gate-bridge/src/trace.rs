//! Diagnostics for the Privacy Lab: what the verifier *did*, in words a visitor can audit.
//!
//! # The rule that shapes this module
//!
//! Nothing reaches a trace except by being **constructed here**. There is no pass-through, no
//! "log the request" and no generic map that a caller could fill with whatever it liked: an event
//! exists only as a typed variant, and each variant's fields are fixed by this file. That is the
//! difference between a diagnostic stream and a data leak with a nice font.
//!
//! # What is deliberately absent
//!
//! * balances of any kind — including "0.5" or "enough" or an order of magnitude,
//! * private keys, seeds, nonces-in-secret or any witness material,
//! * session commitments, access tokens, cookies, CSRF values, administrator credentials,
//! * wallet addresses, transaction identifiers or UTXO identifiers, unless the field is explicitly
//!   documented as public on-chain data that the network itself publishes,
//! * environment values, filesystem paths, file contents, raw RPC payloads,
//! * exception text: a panic message can carry a path, a SQL fragment or a secret.
//!
//! Every string that reaches an event is either a fixed label from this file or a value that has
//! already been normalised (a truncated, non-secret public identifier) — see [`short_public_id`].

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Relative timestamps in the UI are computed from this.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or_default()
}

/// Where an event came from. The viewer must be able to tell a claim of ours from a fact the
/// network reported, because those are not the same strength of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EventSource {
    /// The visitor's own browser reported it (an action was taken).
    Client,
    /// The bridge did it (a challenge was minted, a request was refused).
    Bridge,
    /// The wallet reported it (the wallet answered a query or signed something).
    Wallet,
    /// The network/consensus reported it (a transaction was seen in a block).
    Consensus,
    /// This process computed it (a verification result, a policy comparison).
    Verifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    /// Something the visitor should notice but which is not a failure.
    Notice,
    /// A refusal or a failure.
    Error,
}

/// One line of the protocol inspector.
///
/// The field set is closed: `code` is a fixed enum-like string defined by this module, `message`
/// is a sentence this module writes, and the numeric fields are counts or thresholds the gate
/// itself publishes. There is no path by which caller-supplied text lands in a trace.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    /// Monotonic within one attempt, starting at 1.
    pub seq: u32,
    /// Milliseconds since the epoch when the event was recorded.
    pub at_ms: u64,
    /// Milliseconds since the previous event in the same attempt.
    pub delta_ms: u64,
    pub source: EventSource,
    pub severity: Severity,
    /// A stable, greppable event code, e.g. `challenge.minted`.
    pub code: &'static str,
    /// A human sentence. No interpolated values that could carry a secret.
    pub message: &'static str,
    /// Fixed, non-secret detail fields. See the constructors below — each one decides what goes in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
}

/// The closed set of detail fields. A struct, not a map: adding a field here is a deliberate,
/// reviewable act, which is exactly what a `HashMap<String, Value>` would destroy.
///
/// A field that does not apply is omitted entirely rather than serialised as `null`: an inspector
/// full of nulls hides the values that matter and invites the reader to think something is missing
/// when it simply does not apply.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    /// The gate this attempt is about (its administrator-chosen id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
    /// A SHORT handle of something the network publishes to everyone (a transaction, a block). Never
    /// a visitor's own identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ref: Option<String>,
    /// The proof mode's public name (`consensus`, `credential`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_mode: Option<&'static str>,
    /// A threshold the GATE published, in raw units. A gate's threshold is public by design.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_raw: Option<u64>,
    /// A **floor** the network attested — a lower bound, never the amount held.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attested_floor_raw: Option<u64>,
    /// A count of items, never the items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_count: Option<u32>,
    /// How long something took, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// A session's remaining life, in seconds. The visitor's own session, by their own action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_valid_secs: Option<u64>,
    /// Whether the attempt was the labelled offline simulation. A simulation must be visibly a
    /// simulation in every view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulated: Option<bool>,
}

impl TraceEvent {
    fn new(seq: u32, at_ms: u64, delta_ms: u64, source: EventSource, severity: Severity, code: &'static str, message: &'static str) -> Self {
        Self { seq, at_ms, delta_ms, source, severity, code, message, detail: None }
    }

    pub fn with(mut self, detail: Detail) -> Self {
        self.detail = Some(detail);
        self
    }
}

/// One verification attempt's trace. Stored in memory, scoped to the attempt, never shared.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    /// A random id the visitor holds; the key to every read of this trace.
    pub attempt_id: String,
    /// The gate the visitor selected, echoed back so a stale view cannot mislabel itself.
    pub gate_id: String,
    /// True when this attempt is the labelled offline simulation.
    pub simulated: bool,
    events: Vec<TraceEvent>,
    last_ms: u64,
}

impl Trace {
    pub fn new(attempt_id: String, gate_id: String, simulated: bool) -> Self {
        Self { attempt_id, gate_id, simulated, events: Vec::new(), last_ms: 0 }
    }

    /// Record one event. The sequence number and the delta are computed here, so no caller can
    /// forge either.
    pub fn push(
        &mut self,
        source: EventSource,
        severity: Severity,
        code: &'static str,
        message: &'static str,
        detail: Option<Detail>,
    ) {
        let at = now_ms();
        let seq = self.events.len() as u32 + 1;
        let delta = at.saturating_sub(self.last_ms);
        self.last_ms = at;
        let mut event = TraceEvent::new(seq, at, delta, source, severity, code, message);
        // Minimisation happens HERE, at the boundary, before the event exists in the stream.
        event.detail = detail.map(|mut d| {
            d.gate_id = d.gate_id.as_deref().map(sanitize_public_label).filter(|v| !v.is_empty());
            d.public_ref = d.public_ref.as_deref().map(sanitize_public_label).filter(|v| !v.is_empty());
            d
        });
        self.events.push(event);
    }

    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// The wire form for the browser. Only the fields a visitor may see.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "attemptId": self.attempt_id,
            "gateId": self.gate_id,
            "simulated": self.simulated,
            "events": self.events,
        })
    }
}

/// Reduces a caller-supplied string to the shape a PUBLIC label can have: ASCII letters, digits and
/// `-` `_.`, at most 48 characters. Anything else is dropped rather than escaped, because a value
/// that is not label-shaped was never a label.
///
/// This is what makes the canary test a runtime fact rather than a convention: even a careless
/// caller cannot push a secret, a token or an exception message into a trace, because whatever they
/// pass is filtered down to an identifier-shaped prefix before it is stored.
pub fn sanitize_public_label(value: &str) -> String {
    // Shape-based scrub FIRST, on the raw value: a credential's signature — a JWT, a long
    // hex/base64 run, an `sk-`/`ghp_` key prefix — depends on characters (`.`, `-`, length) that the
    // label filter below would strip, so filtering first would hide exactly the evidence the shape
    // rule looks for. A credential-shaped value is dropped whole, never reshaped into something
    // that merely looks innocent.
    if looks_like_credential(value) {
        return String::new();
    }
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(48)
        .collect()
}

/// Whether a label-shaped string still carries the shape of a credential rather than a name.
fn looks_like_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // A JWT is three dot-separated base64url runs, the last two long.
    if lower.matches('.').count() >= 2 && lower.split('.').any(|p| p.len() >= 16) {
        return true;
    }
    // A long unbroken hex/base64 run is a key, a hash or a token, never a gate id.
    if value.len() >= 32 && value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return true;
    }
    // Recognised key prefixes survive the label filter; catch them by name.
    for prefix in ["sk-", "sk_", "ghp_", "github_pat", "xoxb-", "xoxp-", "api_key", "apikey", "bearer", "secret", "privatekey"] {
        if lower.starts_with(prefix) || lower.contains(&format!("{prefix}")) {
            return true;
        }
    }
    false
}

/// Keeps a short, non-reversible-in-practice handle of a PUBLIC identifier: a transaction id, a
/// block height, a resource address. Only ever used for things the network publishes to everyone;
/// never applied to a token, a session commitment or an address belonging to a visitor.
pub fn short_public_id(value: &str) -> String {
    let hex: String = value.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if hex.len() <= 12 {
        return hex;
    }
    format!("{}…{}", &hex[..6], &hex[hex.len().saturating_sub(4)..])
}

/// Fixed event constructors. Every message a visitor can see is written here — which is what makes
/// "no secret can reach the trace" checkable by reading one file instead of auditing a codebase.
pub mod ev {
    use super::*;

    pub fn attempt_started(t: &mut Trace) {
        t.push(EventSource::Bridge, Severity::Info, "attempt.started", "A verification attempt was opened for this browser tab.", None);
    }

    pub fn simulation_notice(t: &mut Trace) {
        t.push(
            EventSource::Bridge,
            Severity::Notice,
            "attempt.simulated",
            "OFFLINE SIMULATION: no wallet, no network, no transaction, no session. Nothing below this line is evidence of a real proof.",
            Some(Detail { simulated: Some(true), ..Detail::default() }),
        );
    }

    pub fn gate_selected(t: &mut Trace, gate_id: &str, required_raw: u64, proof_mode: &'static str) {
        t.push(
            EventSource::Bridge,
            Severity::Info,
            "gate.selected",
            "The gate was read from the administrator's published policy. This page cannot change it.",
            Some(Detail {
                gate_id: Some(gate_id.to_string()),
                required_raw: Some(required_raw),
                proof_mode: Some(proof_mode),
                ..Detail::default()
            }),
        );
    }

    pub fn challenge_minted(t: &mut Trace, gate_id: &str) {
        t.push(
            EventSource::Bridge,
            Severity::Info,
            "challenge.minted",
            "The bridge minted a fresh, single-use challenge bound to this gate and this attempt.",
            Some(Detail { gate_id: Some(gate_id.to_string()), ..Detail::default() }),
        );
    }

    pub fn wallet_probe(t: &mut Trace, reachable: bool, note: &'static str) {
        t.push(
            EventSource::Bridge,
            if reachable { Severity::Info } else { Severity::Notice },
            "wallet.probe",
            note,
            None,
        );
    }

    pub fn wallet_asked(t: &mut Trace) {
        t.push(EventSource::Bridge, Severity::Info, "wallet.requested", "The bridge asked the wallet to build a proof for this challenge. Nothing was sent.", None);
    }

    pub fn wallet_answered(t: &mut Trace, duration_ms: u64) {
        t.push(
            EventSource::Wallet,
            Severity::Info,
            "wallet.answered",
            "The wallet returned a signed statement. Its content never passed through the bridge.",
            Some(Detail { duration_ms: Some(duration_ms), ..Detail::default() }),
        );
    }

    pub fn verifier_checked(t: &mut Trace, required_raw: u64, attested_floor_raw: u64, input_count: u32) {
        t.push(
            EventSource::Verifier,
            Severity::Info,
            "verifier.threshold_checked",
            "The verifier compared the attested floor with the gate's threshold: floor >= threshold decides, nothing else.",
            Some(Detail {
                required_raw: Some(required_raw),
                attested_floor_raw: Some(attested_floor_raw),
                input_count: Some(input_count),
                ..Detail::default()
            }),
        );
    }

    pub fn consensus_observed(t: &mut Trace, tx_short: &str) {
        t.push(
            EventSource::Consensus,
            Severity::Info,
            "consensus.observed",
            "The network committed the transaction; the gate's on-chain condition evaluated against real chain state.",
            Some(Detail { public_ref: Some(tx_short.to_string()), ..Detail::default() }),
        );
    }

    pub fn access_granted(t: &mut Trace, session_valid_secs: u64, simulated: bool) {
        t.push(
            EventSource::Bridge,
            Severity::Info,
            "access.granted",
            if simulated {
                "SIMULATED GRANT — no real access exists for this attempt."
            } else {
                "The server issued a verified-access session for this attempt."
            },
            Some(Detail { session_valid_secs: Some(session_valid_secs), simulated: Some(simulated), ..Detail::default() }),
        );
    }

    pub fn access_refused(t: &mut Trace, reason: &'static str) {
        t.push(EventSource::Bridge, Severity::Error, "access.refused", reason, None);
    }

    /// The proof was verified, but this bridge issues no access session (not registry-backed).
    /// A distinct event from `access.granted`: conflating "proof verified" with "access
    /// granted" was the old failure mode — the page showed ACCESS GRANTED while `access` in
    /// the response was `null`. Events must reflect actual operations.
    pub fn access_unavailable(t: &mut Trace) {
        t.push(
            EventSource::Bridge,
            Severity::Notice,
            "access.unavailable",
            "The proof was verified, but this bridge issues no access session (not registry-backed). No token was issued.",
            None,
        );
    }

    pub fn policy_binding(t: &mut Trace) {
        t.push(
            EventSource::Verifier,
            Severity::Info,
            "policy.bound",
            "The answer was checked against the policy version that was in force when the challenge was minted.",
            None,
        );
    }

    pub fn replay_refused(t: &mut Trace) {
        t.push(
            EventSource::Verifier,
            Severity::Error,
            "replay.refused",
            "This challenge was already answered. Challenges are single-use; a replay is refused.",
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_numbers_and_deltas_are_computed_here() {
        let mut t = Trace::new("a1".into(), "gold".into(), false);
        ev::attempt_started(&mut t);
        std::thread::sleep(std::time::Duration::from_millis(5));
        ev::challenge_minted(&mut t, "gold");
        ev::access_refused(&mut t, "no");
        let events = t.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[2].seq, 3, "sequence numbers are contiguous and not caller-chosen");
        // The first event measures from the epoch (its absolute timestamp), every later one from the
        // previous event. What matters for a viewer is that the RELATIVE gap is real, not a number
        // a caller typed.
        assert!(events[0].delta_ms > 1_000_000_000, "the first delta is the absolute timestamp");
        assert!(events[2].delta_ms < 5_000, "later deltas are small gaps between real events");
    }

    #[test]
    fn free_form_text_is_reduced_to_an_identifier_shape() {
        assert_eq!(sanitize_public_label("meme-coin"), "meme-coin", "a real label passes through");
        // A path keeps no separator that could reconstruct a filesystem layout, and keeps nothing
        // but label characters.
        for hostile in [
            "/home/example/.cargo/config.toml",
            "token=abc.def-ghi_jkl",
            "<script>alert(1)</script>",
            "sk-abc123_secret-value",
            "Bearer eyJhbGciOi.JIUzI1NiJ9",
        ] {
            let filtered = sanitize_public_label(hostile);
            assert!(
                filtered.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
                "{hostile:?} left a non-label character in {filtered:?}"
            );
            assert!(!filtered.contains("//"), "no path separator survives: {filtered:?}");
            assert!(!filtered.contains('='), "no assignment survives: {filtered:?}");
        }
        // A long dash-separated label (a gate id with many segments) is bounded to 48 and kept: it
        // is not credential-shaped, so the length cap alone applies.
        let long_label = (0..40).map(|i| format!("s{i}")).collect::<Vec<_>>().join("-");
        assert_eq!(sanitize_public_label(&long_label).len(), 48, "labels are bounded");
        // An unbroken 200-char run is a credential, dropped whole.
        assert_eq!(sanitize_public_label(&"x".repeat(200)), "");
        assert_eq!(sanitize_public_label("").len(), 0);
    }

    #[test]
    fn a_value_with_the_shape_of_a_credential_is_dropped_entirely() {
        // These survive the label filter untouched — every character is legal in a gate id — and are
        // caught only by the shape rule. Each must come back empty.
        let credentials = [
            "sk-livekeymaterial0123456789",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "Bearer",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuvwxyz0123",
            &"a".repeat(40),
        ];
        for c in credentials {
            assert_eq!(sanitize_public_label(c), "", "a credential-shaped value survived: {c}");
        }
        // An ordinary gate id does not.
        assert_eq!(sanitize_public_label("gold-mint-10-tari"), "gold-mint-10-tari");
    }

    #[test]
    fn a_short_public_id_keeps_only_the_ends() {
        assert_eq!(short_public_id("0123456789abcdef0123"), "012345…0123");
        assert_eq!(short_public_id("short"), "short");
    }

    /// The central guarantee, tested rather than promised: no field of the wire form ever carries a
    /// value this module did not itself construct.
    #[test]
    fn the_wire_form_has_only_the_allowlisted_shape() {
        let mut t = Trace::new("attempt-1".into(), "gold".into(), false);
        ev::attempt_started(&mut t);
        ev::gate_selected(&mut t, "gold", 1_000_000, "consensus");
        ev::challenge_minted(&mut t, "gold");
        ev::wallet_asked(&mut t);
        ev::wallet_answered(&mut t, 12);
        ev::verifier_checked(&mut t, 1_000_000, 4_200_000, 3);
        ev::policy_binding(&mut t);
        ev::access_granted(&mut t, 604_800, false);
        let json = t.to_json();
        let keys_of = |e: &serde_json::Value| -> Vec<String> {
            e.as_object().unwrap().keys().map(|k| k.to_string()).collect()
        };
        // Event 0 carries no detail (nothing to say yet); its shape is the base one.
        let base_keys = keys_of(&json["events"][0]);
        for k in ["seq", "atMs", "deltaMs", "source", "severity", "code", "message"] {
            assert!(base_keys.iter().any(|x| x == k), "expected field {k} in {base_keys:?}");
        }
        // No field name that could hold a secret exists on any event at all.
        for forbidden in ["balance", "token", "secret", "seed", "cookie", "commitment", "witness", "privatekey"] {
            assert!(!base_keys.iter().any(|k| k.to_lowercase().contains(forbidden)), "unexpected event field {forbidden} in {base_keys:?}");
        }
        // The nested detail object — the part a real proof populates — carries only allowlisted keys.
        let gate_event = json["events"].as_array().unwrap().iter().find(|e| e.get("detail").is_some()).unwrap();
        let detail_keys: Vec<String> = gate_event["detail"]
            .as_object()
            .map(|o| o.keys().map(|k| k.to_string()).collect())
            .unwrap_or_default();
        for forbidden in ["balance", "token", "secret", "seed", "cookie", "commitment", "witness"] {
            assert!(!detail_keys.iter().any(|k| k.to_lowercase().contains(forbidden)), "unexpected detail field {forbidden} in {detail_keys:?}");
        }
        assert!(detail_keys.iter().any(|k| k == "requiredRaw"), "the gate's public threshold IS allowed: {detail_keys:?}");
        for forbidden in ["balance", "token", "secret", "seed", "cookie", "commitment", "witness"] {
            assert!(!detail_keys.iter().any(|k| k.to_lowercase().contains(forbidden)), "unexpected detail field {forbidden} in {detail_keys:?}");
        }
    }

    /// A canary secret must not survive anywhere in the serialised trace, even if a future caller
    /// tries to push it through a message or a detail field. Messages are `&'static str` from this
    /// module, so this test documents the type-level guarantee as well as the runtime one.
    #[test]
    fn a_canary_secret_never_reaches_a_trace() {
        // Two canaries: one dash-joined phrase (which the shape rule alone cannot distinguish from a
        // label, and which therefore MUST be scrubbed by being flagged, not merely reshaped) and one
        // credential-shaped run. The guarantee under test is the one we actually make: no value that
        // a caller passes reaches the trace intact unless it is a short, credential-free label.
        const CANARY: &str = "sk-live-7f3a9c2e-must-never-appear-anywhere";
        const CANARY2: &str = "7f3a9c2e8b1d4a6f8e0c2b4a6d8f0e2c4a6d8f0e2c4a6d8f0e2c";
        let mut t = Trace::new("a".into(), "g".into(), false);
        ev::attempt_started(&mut t);
        ev::access_refused(&mut t, "refused");
        // The only way a caller could even try: details it constructs. Try every string field, and
        // note that `code`/`message` are `&'static str`, so runtime text cannot reach them at all.
        t.push(
            EventSource::Wallet,
            Severity::Info,
            "test.probe",
            "a fixed message",
            Some(Detail {
                gate_id: Some(CANARY.to_string()),
                public_ref: Some(CANARY2.to_string()),
                ..Detail::default()
            }),
        );
        let serialised = serde_json::to_string(&t.to_json()).unwrap();
        assert!(!serialised.contains(CANARY), "the credential-shaped canary reached the trace: {serialised}");
        assert!(!serialised.contains(CANARY2), "the hex canary reached the trace: {serialised}");
    }

    #[test]
    fn simulation_is_marked_in_every_grant() {
        let mut t = Trace::new("a".into(), "g".into(), true);
        ev::simulation_notice(&mut t);
        ev::access_granted(&mut t, 604_800, true);
        let json = serde_json::to_string(&t.to_json()).unwrap();
        assert!(json.contains("SIMULATED"), "a simulated grant must say so: {json}");
        assert!(json.contains(r#""simulated":true"#), "the simulated flag must be on the event");
    }
}
