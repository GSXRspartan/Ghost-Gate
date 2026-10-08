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
    Challenge, GateContext, GateParams, GatePolicy, MARK, ProofReceipt, ResourceClass, ResourceProfile,
    qualify,
};

/// The Ghost Gate component.
#[template]
mod template {
    use tari_template_abi::rust::collections::BTreeMap;

    use super::*;

    /// A private threshold access gate.
    pub struct GhostGate {
        /// Immutable policy: which resource, what threshold, and which chain this gate serves.
        policy: GatePolicy,
        /// Decimal places of the gate's resource. **Presentation only.** Stored so a relying site can
        /// render `1,000,000 GHOSTTEST` without a second lookup, and read by no rule: the
        /// consensus comparison is `attested_minimum >= threshold` on raw units, which is the same
        /// comparison whether the asset has 0 decimal places or 18.
        divisibility: u8,
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
        /// Creates a gate requiring at least `threshold` of `resource`'s hidden value.
        ///
        /// `resource` is any **stealth fungible** resource, named by address. Native tTARI is one
        /// such resource; a resource created by any user is another, and the gate cannot tell the
        /// difference because it never looks at a symbol or a name. The resource's own chain state
        /// decides whether it qualifies: a public fungible, a confidential fungible or an NFT is
        /// refused here, by name, because none of them has a per-output `minimum_value_promise` and
        /// so none of them has a proof for this gate to verify.
        ///
        /// `threshold` is a raw amount in the resource's own smallest unit. No floating point ever
        /// touches it.
        ///
        /// `allocation` is allocated by the caller. A component address derived inside the template
        /// collides across two deployments in the same transaction sequence, and a relying site
        /// running several gates needs distinct, predictable addresses anyway.
        ///
        /// `network` is the Ootle cohort this gate is deployed on, as its byte (see
        /// `ghost_gate_core::network`). It binds a challenge to one chain. It is a self-consistency
        /// check rather than an attestation: a template has no host call that reports the network.
        ///
        /// `relying_site` and `session_commitment` are opaque to the gate: it only compares them.
        /// They exist so a challenge is bound to one site and one browser session.
        pub fn new(
            allocation: ComponentAddressAllocation,
            resource: ResourceAddress,
            threshold: u64,
            relying_site: MaxBytes<64>,
            session_commitment: MaxBytes<64>,
            network: u8,
        ) -> Component<Self> {
            // Read the resource from chain before deciding anything about it. This is the only
            // place the gate looks at a resource: the address is the identity, and the chain's
            // record of that address is what says whether the class can carry a threshold proof.
            let info = ResourceManager::get(resource).resource_info();

            let policy = GateParams {
                resource,
                threshold,
                relying_site: relying_site.clone(),
                session_commitment: session_commitment.clone(),
                network,
            }
            .into_policy(&ResourceProfile {
                class: match info.resource_type {
                    ResourceType::Fungible => ResourceClass::PublicFungible,
                    ResourceType::Confidential => ResourceClass::ConfidentialFungible,
                    ResourceType::NonFungible => ResourceClass::NonFungible,
                    ResourceType::Stealth => ResourceClass::StealthFungible,
                },
                divisibility: info.divisibility,
            })
            .unwrap_or_else(|e| panic!("{e}"));

            Component::new(Self {
                policy,
                divisibility: info.divisibility,
                relying_site,
                session_commitment,
                burnt_nonces: BTreeMap::new(),
                proofs_accepted: 0,
            })
            .with_address_allocation(allocation)
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

            // The receipt is emitted as an event so an indexer or a relying site can observe that this gate
            // accepted a proof without reading component state. It carries a public lower bound and a
            // burnt nonce — no value, no address, no identity.
            let mut payload = Metadata::new();
            payload.insert("receipt", &receipt);
            emit_event(MARK, payload);

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
        ///
        /// The security identity of the asset. A relying site resolves display names from this
        /// address and must never from a symbol a caller supplied.
        pub fn resource(&self) -> ResourceAddress {
            self.policy.resource
        }

        /// Decimal places of the gate's resource, for rendering only.
        ///
        /// No rule reads this. It is exposed so a UI can format the threshold as a person would write
        /// it without a second chain round-trip, and so a *mismatch* between the site and the gate is
        /// detectable rather than silently rounding.
        pub fn divisibility(&self) -> u8 {
            self.divisibility
        }

        /// The Ootle cohort byte this gate is bound to.
        pub fn network(&self) -> u8 {
            self.policy.network
        }

        /// Whether the gate is currently accepting proofs.
        pub fn is_open(&self) -> bool {
            self.policy.open
        }

        /// How many proofs this gate has accepted.
        pub fn proofs_accepted(&self) -> u64 {
            self.proofs_accepted
        }

        /// Whether a nonce has already been burnt.
        ///
        /// Takes the nonce by value: the `#[template]` macro's type parser accepts only plain paths
        /// and tuples in a public signature, so a `&Hash32` parameter would not compile.
        pub fn is_nonce_used(&self, nonce: Hash32) -> bool {
            self.burnt_nonces.contains_key(&nonce)
        }
    }
}