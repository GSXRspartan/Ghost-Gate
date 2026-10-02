//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Ghost Gate — a private threshold access proof.
//!
//! Your balance stays in the shadows.
//!
//! Prove you control enough without revealing exactly how much.
//!
//! A prover calls [`GhostGate::prove_access`] with a challenge the relying site issued and a
//! `StealthTransferStatement` built by their own wallet. The gate checks the statement's shape and
//! then hands it to the engine's stealth transfer machinery, which does the part that actually
//! carries the weight: it verifies every input is live and authorised by the key path, verifies the
//! balance proof, and verifies the bulletproof that pins the qualifying output's hidden value to
//! `[minimum_value_promise, 2^64)`.
//!
//! What a success means, precisely: at the moment this transaction committed, its signer controlled
//! enough private Tari to cover the gate threshold, and did so without publishing an amount.
//!
//! What a success does not mean: anything about the prover's total balance, their identity, whether
//! they are human, or what they hold afterwards.

use tari_template_lib::prelude::*;

use ghost_gate_core::{
    Challenge, GateContext, GateError, GatePolicy, MARK, NETWORK_BYTE, ProofReceipt, qualify,
};

/// The Ghost Gate component.
#[template]
mod template {
    use super::*;

    /// A private threshold access gate.
    pub struct GhostGate {
        /// Immutable policy: which resource, what threshold, and the relying site this gate serves.
        policy: GatePolicy,
        /// Opaque identifier of the relying site this gate serves. A challenge naming a different
        /// site is refused, so a proof cannot be redeemed elsewhere.
        relying_site: MaxBytes<64>,
        /// Opaque browser-session commitment. A proof cannot be lifted into another session.
        session_commitment: MaxBytes<64>,
        /// Nonces already burnt, each with the epoch at which it was burnt.
        ///
        /// This is the single-use state. Burning the nonce on chain is what stops a copied
        /// transaction from minting a second session: replaying it finds its nonce already gone.
        burnt_nonces: BTreeMap<Hash32, u64>,
        /// How many proofs this gate has accepted.
        proofs_accepted: u64,
    }

    impl GhostGate {
        /// Creates a gate for `resource` requiring at least `threshold` of its hidden value.
        ///
        /// `relying_site` and `session_commitment` are opaque to the gate: it only compares them.
        /// They exist so a challenge is bound to one site and one browser session.
        pub fn new(
            resource: ResourceAddress,
            threshold: u64,
            relying_site: MaxBytes<64>,
            session_commitment: MaxBytes<64>,
        ) -> Component<Self> {
            if threshold == 0 {
                panic!("GG: threshold must be positive");
            }
            Component::new(Self {
                policy: GatePolicy {
                    resource,
                    threshold,
                    open: true,
                },
                relying_site,
                session_commitment,
                burnt_nonces: BTreeMap::new(),
                proofs_accepted: 0,
            })
            .with_access_rules(AccessRules::allow_all())
            .create()
        }

        /// Proves control of at least the gate threshold of the gate's resource, without revealing
        /// the amount.
        ///
        /// The statement must:
        /// - spend at least one live stealth input, each authorised by the key path;
        /// - reveal no input amount and create no revealed output;
        /// - create exactly one stealth output, so "the qualifying output" is unambiguous;
        /// - create it key-spendable, so the funds stay under a key rather than in a condition tree;
        /// - promise at least the gate threshold as that output's `minimum_value_promise`.
        ///
        /// Then, and only then, the statement goes to the engine. Any failure below is a panic,
        /// which aborts the whole transaction — a failed Ghost Gate proof leaves nothing committed.
        pub fn prove_access(
            &mut self,
            challenge: Challenge,
            statement: StealthTransferStatement,
        ) -> ProofReceipt {
            let epoch = Consensus::current_epoch();

            let already_used = self.burnt_nonces.contains_key(&challenge.nonce);

            let receipt = qualify(
                &self.policy,
                &challenge,
                &statement,
                &GateContext {
                    self_address: CallerContext::current_component_address(),
                    current_epoch: epoch,
                    // A template has no host call that reports the network, so the transaction's own
                    // network byte is the only value available. The relying site pins it to the
                    // cohort it deployed against; see docs/V042_SOURCE_TRACE.md finding 31.
                    current_network: NETWORK_BYTE,
                    relying_site: self.relying_site.as_slice(),
                    session_commitment: self.session_commitment.as_slice(),
                },
                already_used,
            )
            .unwrap_or_else(|e| panic!("{e}"));

            // Hand the statement to the engine. From here the engine owns the verdict: input
            // liveness, key-path authorisation, balance proof and range proof. A template check
            // passing is necessary, never sufficient.
            let manager = ResourceManager::get(self.policy.resource);
            let revealed = manager.stealth_transfer(statement);
            // `revealed_output` was required to be absent above, so this must be `None`. A `Some`
            // here would mean the engine produced a bucket the gate did not ask for.
            assert!(
                revealed.is_none(),
                "GG: a qualifying proof must not produce a revealed bucket"
            );

            self.burnt_nonces.insert(challenge.nonce, epoch);
            self.proofs_accepted = self.proofs_accepted.saturating_add(1);

            emit_event(
                MARK,
                Metadata {
                    key: b"ghost_gate_proof",
                    value: MetadataValue::Binary(receipt.to_vec()),
                },
            );

            receipt
        }

        /// Opens or closes the gate. Closing is an operator action; it does not invalidate proofs
        /// already committed.
        pub fn set_open(&mut self, open: bool) {
            self.policy.open = open;
        }

        /// The gate's threshold, in the resource's smallest unit.
        pub fn threshold(&self) -> u64 {
            self.policy.threshold
        }

        /// The resource the threshold is denominated in.
        pub fn resource(&self) -> ResourceAddress {
            self.policy.resource
        }

        /// How many proofs this gate has accepted.
        pub fn proofs_accepted(&self) -> u64 {
            self.proofs_accepted
        }

        /// Whether a nonce has already been burnt.
        pub fn is_nonce_used(&self, nonce: &Hash32) -> bool {
            self.burnt_nonces.contains_key(nonce)
        }
    }

    impl From<GateError> for String {
        fn from(e: GateError) -> Self {
            e.reason().to_string()
        }
    }
}