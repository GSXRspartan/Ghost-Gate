//! Synthetic-only wallet-runtime boundary for GGBP-1 proof approval and output reservation.
//!
//! It is not a wallet service, RPC endpoint, WASM export, transaction builder, or generic signing
//! API. Its data is synthetic fixture material only. A real upstream integration must keep request
//! authentication, the foreground approval operation, opaque approvals, and a durable reservation
//! registry inside the wallet runtime.
//!
//! GGBP-1 reservations are deliberately separate from Tari transaction encumbrance. They are
//! short-lived coordination records that a real output manager must consult before spending; they
//! must not mutate normal transaction state or replace its crash-recovery machinery.

#![allow(dead_code)] // Feature-disabled contract; only its isolated fixture harness invokes it.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Mutex, MutexGuard},
};

use hmac::{Hmac, Mac};
use rand::{CryptoRng, Rng, RngExt};
use sha2::{Digest, Sha256};
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_utilities::ByteArray;
use thiserror::Error;

use crate::ggbp1::{
    GGBP1_MAX_OUTPUTS, Ggbp1Challenge, Ggbp1Error, Ggbp1WireProof, SyntheticOutputWitness,
    SyntheticSubjectWitness, expected_commitment_generator_fingerprint, prove_synthetic,
};

const MAX_ORIGIN_BYTES: usize = 253;
const DEFAULT_LEASE_SECONDS: u64 = 60;

/// Strict, canonical, displayable HTTPS origin. No path, query, fragment, user info, or IPv6
/// syntax is accepted by this intentionally small experimental parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1CanonicalHttpsOrigin(String);

impl Ggbp1CanonicalHttpsOrigin {
    pub fn parse(input: &str) -> Result<Self, Ggbp1WalletAdapterError> {
        let authority = input
            .strip_prefix("https://")
            .ok_or(Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin)?;
        if authority.is_empty()
            || authority.len() > MAX_ORIGIN_BYTES
            || authority
                .bytes()
                .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
        {
            return Err(Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin);
        }
        let (raw_host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                Some(
                    port.parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or(Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin)?,
                ),
            ),
            Some(_) => return Err(Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin),
            None => (authority, None),
        };
        let host = raw_host.to_ascii_lowercase();
        if host.is_empty()
            || host.ends_with('.')
            || host.bytes().any(|byte| {
                !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'.' && byte != b'-'
            })
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
        {
            return Err(Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin);
        }
        Ok(Self(match port {
            None | Some(443) => format!("https://{host}"),
            Some(port) => format!("https://{host}:{port}"),
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hash(&self) -> [u8; 32] {
        hash(b"com.ghost-gate.ggbp1.origin/v1", &[self.0.as_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticWalletChainContext {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub tip_height: u64,
    pub minimum_confirmations: u64,
}

/// Fixture equivalents of statuses excluded by the pinned wallet output manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntheticWalletOutputState {
    Available,
    PendingIncoming,
    PendingOutgoing,
    Encumbered,
    ShortTermEncumbered,
    Spent,
    Invalid,
}

/// Private fixture equivalent of a wallet output and its key-manager-derived opening.
#[derive(Clone)]
pub struct SyntheticWalletOutput {
    witness: SyntheticOutputWitness,
    confirmed_height: Option<u64>,
    maturity_height: u64,
    script_lock_height: Option<u64>,
    covenant_supported: bool,
    script_available: bool,
    state: SyntheticWalletOutputState,
}

impl SyntheticWalletOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn new_fixture(
        witness: SyntheticOutputWitness,
        confirmed_height: Option<u64>,
        maturity_height: u64,
        script_lock_height: Option<u64>,
        covenant_supported: bool,
        script_available: bool,
        state: SyntheticWalletOutputState,
    ) -> Self {
        Self {
            witness,
            confirmed_height,
            maturity_height,
            script_lock_height,
            covenant_supported,
            script_available,
            state,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticWalletReservationPolicy {
    pub maximum_lease_seconds: u64,
}

impl Default for SyntheticWalletReservationPolicy {
    fn default() -> Self {
        Self {
            maximum_lease_seconds: DEFAULT_LEASE_SECONDS,
        }
    }
}

/// Parsed request data. A future connector must construct this only after authenticating the
/// complete request envelope using an operator-pinned relying-party credential.
#[derive(Clone, Debug)]
pub struct Ggbp1WalletProofRequest {
    challenge: Ggbp1Challenge,
    relying_party_origin: Ggbp1CanonicalHttpsOrigin,
}

impl Ggbp1WalletProofRequest {
    pub fn new(challenge: Ggbp1Challenge, relying_party_origin: Ggbp1CanonicalHttpsOrigin) -> Self {
        Self {
            challenge,
            relying_party_origin,
        }
    }
}

/// Opaque output of wallet-internal request-envelope authentication. A caller cannot construct it.
#[derive(Clone)]
pub(crate) struct Ggbp1AuthenticatedWalletRequest {
    request: Ggbp1WalletProofRequest,
    authentication_tag: [u8; 32],
}

/// Exact prompt data required for wallet foreground approval. It contains no values, masks, seeds,
/// spending keys, view keys, arbitrary signing message, or transaction instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1WalletApprovalPrompt {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub relying_party_origin: Ggbp1CanonicalHttpsOrigin,
    pub gate_id: [u8; 16],
    pub gate_configuration_version: u64,
    pub subject_id: [u8; 16],
    pub subject_authentication_public_key: RistrettoPublicKey,
    pub threshold_micro_xtm: u64,
    pub expires_at_unix_seconds: u64,
    pub selected_output_hashes: Vec<[u8; 32]>,
    pub request_fingerprint: [u8; 32],
}

/// Opaque state returned to the wallet UI while it waits for a user. No mutex or DB transaction is
/// held across the wait; only the bounded reservation remains.
#[derive(Clone)]
pub struct Ggbp1PreparedWalletProof {
    reservation_id: [u8; 32],
    request_fingerprint: [u8; 32],
    prompt: Ggbp1WalletApprovalPrompt,
}

impl Ggbp1PreparedWalletProof {
    pub fn prompt(&self) -> &Ggbp1WalletApprovalPrompt {
        &self.prompt
    }
}

impl fmt::Debug for Ggbp1PreparedWalletProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ggbp1PreparedWalletProof")
            .field("prompt", &self.prompt)
            .field("reservation", &"<redacted>")
            .finish()
    }
}

/// Opaque affirmative decision generated by the wallet foreground operation only.
#[derive(Clone)]
pub struct Ggbp1WalletForegroundApproval {
    reservation_id: [u8; 32],
    request_fingerprint: [u8; 32],
    approval_tag: [u8; 32],
}

impl fmt::Debug for Ggbp1WalletForegroundApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ggbp1WalletForegroundApproval")
            .field("approval", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReservationLifecycle {
    AwaitingForegroundApproval,
    Proving,
}

#[derive(Clone)]
struct Reservation {
    challenge: Ggbp1Challenge,
    request_fingerprint: [u8; 32],
    output_hashes: Vec<[u8; 32]>,
    expires_at_unix_seconds: u64,
    lifecycle: ReservationLifecycle,
}

struct WalletState {
    outputs: BTreeMap<[u8; 32], SyntheticWalletOutput>,
    reservations: BTreeMap<[u8; 32], Reservation>,
    next_reservation_sequence: u64,
}

/// Process-local, synthetic wallet core. It generates private fixture capabilities internally and
/// exposes neither those capabilities nor a generic signing function.
pub struct SyntheticWalletGgbp1Prover {
    chain: SyntheticWalletChainContext,
    subject: SyntheticSubjectWitness,
    policy: SyntheticWalletReservationPolicy,
    request_authentication_key: [u8; 32],
    approval_key: [u8; 32],
    state: Mutex<WalletState>,
}

impl SyntheticWalletGgbp1Prover {
    pub fn new_fixture(
        chain: SyntheticWalletChainContext,
        subject: SyntheticSubjectWitness,
        outputs: Vec<SyntheticWalletOutput>,
    ) -> Result<Self, Ggbp1WalletAdapterError> {
        Self::new_fixture_with_policy(
            chain,
            subject,
            outputs,
            SyntheticWalletReservationPolicy::default(),
        )
    }

    pub fn new_fixture_with_policy(
        chain: SyntheticWalletChainContext,
        subject: SyntheticSubjectWitness,
        outputs: Vec<SyntheticWalletOutput>,
        policy: SyntheticWalletReservationPolicy,
    ) -> Result<Self, Ggbp1WalletAdapterError> {
        if policy.maximum_lease_seconds == 0 {
            return Err(Ggbp1WalletAdapterError::InvalidReservationPolicy);
        }
        let mut indexed = BTreeMap::new();
        for output in outputs {
            if indexed
                .insert(output.witness.public.output_hash, output)
                .is_some()
            {
                return Err(Ggbp1WalletAdapterError::DuplicateOutputIdentifier);
            }
        }
        let mut request_authentication_key = [0; 32];
        let mut approval_key = [0; 32];
        let mut internal_rng = rand::rng();
        internal_rng.fill(&mut request_authentication_key);
        internal_rng.fill(&mut approval_key);
        Ok(Self {
            chain,
            subject,
            policy,
            request_authentication_key,
            approval_key,
            state: Mutex::new(WalletState {
                outputs: indexed,
                reservations: BTreeMap::new(),
                next_reservation_sequence: 0,
            }),
        })
    }

    /// Atomically compare-selects and reserves eligible output records. It returns before any UI
    /// approval occurs, so no wallet mutex/transaction remains held while a person decides.
    pub(crate) fn prepare_authenticated_proof(
        &self,
        authenticated: &Ggbp1AuthenticatedWalletRequest,
        now: u64,
    ) -> Result<Ggbp1PreparedWalletProof, Ggbp1WalletAdapterError> {
        self.verify_authenticated_request(authenticated)?;
        let request = &authenticated.request;
        self.check_request_context(request, now)?;
        let expires_at = now
            .checked_add(self.policy.maximum_lease_seconds)
            .ok_or(Ggbp1WalletAdapterError::LeaseExpiryOverflow)?
            .min(request.challenge.expires_at_unix_seconds);
        if expires_at <= now {
            return Err(Ggbp1WalletAdapterError::ChallengeExpired);
        }
        let mut state = self.lock_state()?;
        Self::expire_reservations(&mut state, now);
        let (selected, hashes) = self.select_and_validate(&state, &request.challenge)?;
        let fingerprint = request_fingerprint(request, &hashes)?;
        let id = self.next_reservation_id(&mut state, fingerprint)?;
        state.reservations.insert(
            id,
            Reservation {
                challenge: request.challenge.clone(),
                request_fingerprint: fingerprint,
                output_hashes: hashes,
                expires_at_unix_seconds: expires_at,
                lifecycle: ReservationLifecycle::AwaitingForegroundApproval,
            },
        );
        Ok(Ggbp1PreparedWalletProof {
            reservation_id: id,
            request_fingerprint: fingerprint,
            prompt: approval_prompt(request, &selected, fingerprint),
        })
    }

    /// Wallet-runtime-only foreground operation. There is deliberately no public trait, callback,
    /// Boolean parameter, or raw signing/key export that an external caller can use to forge this.
    fn approve_from_wallet_foreground(
        &self,
        prepared: &Ggbp1PreparedWalletProof,
        now: u64,
    ) -> Result<Ggbp1WalletForegroundApproval, Ggbp1WalletAdapterError> {
        let mut state = self.lock_state()?;
        Self::expire_reservations(&mut state, now);
        let reservation = state
            .reservations
            .get(&prepared.reservation_id)
            .ok_or(Ggbp1WalletAdapterError::ReservationUnavailable)?;
        self.check_prepared(prepared, reservation, now)?;
        Ok(Ggbp1WalletForegroundApproval {
            reservation_id: prepared.reservation_id,
            request_fingerprint: prepared.request_fingerprint,
            approval_tag: self.approval_tag(prepared.reservation_id, prepared.request_fingerprint),
        })
    }

    pub(crate) fn cancel_prepared_proof(
        &self,
        prepared: &Ggbp1PreparedWalletProof,
        now: u64,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        let mut state = self.lock_state()?;
        Self::expire_reservations(&mut state, now);
        let reservation = state
            .reservations
            .get(&prepared.reservation_id)
            .ok_or(Ggbp1WalletAdapterError::ReservationUnavailable)?;
        self.check_prepared(prepared, reservation, now)?;
        state.reservations.remove(&prepared.reservation_id);
        Ok(())
    }

    /// Final validation happens after approval and immediately before proof creation. The lease is
    /// marked `Proving` under the mutex, blocking normal spend/proof selection until completion.
    pub fn prove_approved<R: Rng + CryptoRng>(
        &self,
        approval: &Ggbp1WalletForegroundApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Ggbp1WalletAdapterError> {
        let (reservation, witnesses) = {
            let mut state = self.lock_state()?;
            Self::expire_reservations(&mut state, now);
            let reservation = state
                .reservations
                .get(&approval.reservation_id)
                .cloned()
                .ok_or(Ggbp1WalletAdapterError::ReservationUnavailable)?;
            self.check_approval(approval, &reservation, now)?;
            let witnesses = self.revalidate_reservation(&state, &reservation)?;
            state
                .reservations
                .get_mut(&approval.reservation_id)
                .expect("reservation remains present while the wallet mutex is held")
                .lifecycle = ReservationLifecycle::Proving;
            (reservation, witnesses)
        };
        let result = prove_synthetic(&reservation.challenge, &self.subject, &witnesses, rng)
            .and_then(|proof| {
                Ggbp1WireProof {
                    challenge: reservation.challenge.clone(),
                    proof,
                }
                .to_bytes()
            });

        let mut state = self.lock_state()?;
        let final_result = match result {
            Err(error) => Err(Ggbp1WalletAdapterError::Proof(error)),
            Ok(bytes) => match state.reservations.get(&approval.reservation_id).cloned() {
                Some(current) => self.revalidate_reservation(&state, &current).map(|_| bytes),
                None => Err(Ggbp1WalletAdapterError::ReservationUnavailable),
            },
        };
        match &final_result {
            Ok(_)
            | Err(Ggbp1WalletAdapterError::ReservationNoLongerEligible)
            | Err(Ggbp1WalletAdapterError::InvalidStoredOpening) => {
                state.reservations.remove(&approval.reservation_id);
            }
            Err(_) => {
                if let Some(reservation) = state.reservations.get_mut(&approval.reservation_id) {
                    reservation.lifecycle = ReservationLifecycle::AwaitingForegroundApproval;
                }
            }
        }
        final_result
    }

    fn check_request_context(
        &self,
        request: &Ggbp1WalletProofRequest,
        now: u64,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        request.challenge.canonical_message(&[[0; 32]])?;
        if request.challenge.commitment_generator_fingerprint
            != expected_commitment_generator_fingerprint()
        {
            return Err(Ggbp1WalletAdapterError::UnsupportedCommitmentGenerators);
        }
        if request.challenge.network != self.chain.network {
            return Err(Ggbp1WalletAdapterError::NetworkMismatch);
        }
        if request.challenge.genesis_hash != self.chain.genesis_hash {
            return Err(Ggbp1WalletAdapterError::GenesisMismatch);
        }
        if request.challenge.origin_hash != request.relying_party_origin.hash() {
            return Err(Ggbp1WalletAdapterError::OriginBindingMismatch);
        }
        if request.challenge.subject_authentication_public_key != self.subject.public_key() {
            return Err(Ggbp1WalletAdapterError::SubjectMismatch);
        }
        if now >= request.challenge.expires_at_unix_seconds {
            return Err(Ggbp1WalletAdapterError::ChallengeExpired);
        }
        Ok(())
    }

    fn verify_authenticated_request(
        &self,
        request: &Ggbp1AuthenticatedWalletRequest,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        if request.authentication_tag != self.request_authentication_tag(&request.request) {
            return Err(Ggbp1WalletAdapterError::RequestAuthenticationFailed);
        }
        Ok(())
    }

    fn select_and_validate(
        &self,
        state: &WalletState,
        challenge: &Ggbp1Challenge,
    ) -> Result<(Vec<SyntheticOutputWitness>, Vec<[u8; 32]>), Ggbp1WalletAdapterError> {
        let reserved = state
            .reservations
            .values()
            .flat_map(|reservation| reservation.output_hashes.iter().copied())
            .collect::<BTreeSet<_>>();
        let mut selected = Vec::new();
        let mut hashes = Vec::new();
        let mut total = 0u64;
        for (hash, output) in &state.outputs {
            if reserved.contains(hash) || !self.is_eligible(output)? {
                continue;
            }
            if selected.len() == GGBP1_MAX_OUTPUTS {
                break;
            }
            total = total
                .checked_add(output.witness.value_for_wallet_selection())
                .ok_or(Ggbp1WalletAdapterError::AggregateOverflow)?;
            selected.push(output.witness.clone());
            hashes.push(*hash);
            if total >= challenge.threshold_micro_xtm {
                return Ok((selected, hashes));
            }
        }
        Err(Ggbp1WalletAdapterError::InsufficientEligibleValue)
    }

    fn revalidate_reservation(
        &self,
        state: &WalletState,
        reservation: &Reservation,
    ) -> Result<Vec<SyntheticOutputWitness>, Ggbp1WalletAdapterError> {
        let mut witnesses = Vec::with_capacity(reservation.output_hashes.len());
        for hash in &reservation.output_hashes {
            let output = state
                .outputs
                .get(hash)
                .ok_or(Ggbp1WalletAdapterError::ReservationNoLongerEligible)?;
            if !self.is_eligible(output)? {
                return Err(Ggbp1WalletAdapterError::ReservationNoLongerEligible);
            }
            witnesses.push(output.witness.clone());
        }
        Ok(witnesses)
    }

    fn is_eligible(&self, output: &SyntheticWalletOutput) -> Result<bool, Ggbp1WalletAdapterError> {
        if output.state != SyntheticWalletOutputState::Available
            || !output.covenant_supported
            || !output.script_available
            || !output.witness.is_supported_standard_output()
        {
            return Ok(false);
        }
        let (Some(confirmed), Some(script_lock)) =
            (output.confirmed_height, output.script_lock_height)
        else {
            return Ok(false);
        };
        if confirmed > self.chain.tip_height {
            return Ok(false);
        }
        let confirmations = self
            .chain
            .tip_height
            .checked_sub(confirmed)
            .and_then(|depth| depth.checked_add(1))
            .ok_or(Ggbp1WalletAdapterError::ReservationNoLongerEligible)?;
        if confirmations < self.chain.minimum_confirmations
            || output.maturity_height.max(script_lock) > self.chain.tip_height
        {
            return Ok(false);
        }
        if !output.witness.opening_matches_public_commitment() {
            return Err(Ggbp1WalletAdapterError::InvalidStoredOpening);
        }
        Ok(true)
    }

    fn check_prepared(
        &self,
        prepared: &Ggbp1PreparedWalletProof,
        reservation: &Reservation,
        now: u64,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        if reservation.request_fingerprint != prepared.request_fingerprint {
            return Err(Ggbp1WalletAdapterError::ReservationBindingMismatch);
        }
        if reservation.expires_at_unix_seconds <= now {
            return Err(Ggbp1WalletAdapterError::ReservationUnavailable);
        }
        if reservation.lifecycle != ReservationLifecycle::AwaitingForegroundApproval {
            return Err(Ggbp1WalletAdapterError::ReservationInProgress);
        }
        Ok(())
    }

    fn check_approval(
        &self,
        approval: &Ggbp1WalletForegroundApproval,
        reservation: &Reservation,
        now: u64,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        if reservation.request_fingerprint != approval.request_fingerprint
            || approval.approval_tag
                != self.approval_tag(approval.reservation_id, approval.request_fingerprint)
        {
            return Err(Ggbp1WalletAdapterError::InvalidApprovalDecision);
        }
        if reservation.expires_at_unix_seconds <= now {
            return Err(Ggbp1WalletAdapterError::ReservationUnavailable);
        }
        if reservation.lifecycle != ReservationLifecycle::AwaitingForegroundApproval {
            return Err(Ggbp1WalletAdapterError::ReservationInProgress);
        }
        Ok(())
    }

    fn next_reservation_id(
        &self,
        state: &mut WalletState,
        fingerprint: [u8; 32],
    ) -> Result<[u8; 32], Ggbp1WalletAdapterError> {
        let sequence = state.next_reservation_sequence;
        state.next_reservation_sequence = sequence
            .checked_add(1)
            .ok_or(Ggbp1WalletAdapterError::ReservationSequenceOverflow)?;
        let id = keyed_hash(
            &self.approval_key,
            b"com.ghost-gate.ggbp1.reservation/v1",
            &[&sequence.to_le_bytes(), &fingerprint],
        );
        if state.reservations.contains_key(&id) {
            return Err(Ggbp1WalletAdapterError::ReservationIdentifierCollision);
        }
        Ok(id)
    }

    fn request_authentication_tag(&self, request: &Ggbp1WalletProofRequest) -> [u8; 32] {
        keyed_hash(
            &self.request_authentication_key,
            b"com.ghost-gate.ggbp1.synthetic_request_auth/v1",
            &[&request_binding_bytes(request)],
        )
    }

    fn approval_tag(&self, id: [u8; 32], fingerprint: [u8; 32]) -> [u8; 32] {
        keyed_hash(
            &self.approval_key,
            b"com.ghost-gate.ggbp1.wallet_approval/v1",
            &[&id, &fingerprint],
        )
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, WalletState>, Ggbp1WalletAdapterError> {
        self.state
            .lock()
            .map_err(|_| Ggbp1WalletAdapterError::InternalStateUnavailable)
    }

    fn expire_reservations(state: &mut WalletState, now: u64) {
        state
            .reservations
            .retain(|_, reservation| reservation.expires_at_unix_seconds > now);
    }

    #[cfg(test)]
    fn authenticate_fixture_request(
        &self,
        request: Ggbp1WalletProofRequest,
    ) -> Ggbp1AuthenticatedWalletRequest {
        let authentication_tag = self.request_authentication_tag(&request);
        Ggbp1AuthenticatedWalletRequest {
            request,
            authentication_tag,
        }
    }

    #[cfg(test)]
    fn decline_from_wallet_foreground(
        &self,
        prepared: &Ggbp1PreparedWalletProof,
        now: u64,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        self.cancel_prepared_proof(prepared, now)?;
        Err(Ggbp1WalletAdapterError::UserDeclined)
    }

    #[cfg(test)]
    fn try_fixture_spend(&self, hash: [u8; 32], now: u64) -> Result<(), Ggbp1WalletAdapterError> {
        let mut state = self.lock_state()?;
        Self::expire_reservations(&mut state, now);
        if state
            .reservations
            .values()
            .any(|reservation| reservation.output_hashes.contains(&hash))
        {
            return Err(Ggbp1WalletAdapterError::OutputReserved);
        }
        state
            .outputs
            .get_mut(&hash)
            .ok_or(Ggbp1WalletAdapterError::ReservationNoLongerEligible)?
            .state = SyntheticWalletOutputState::Spent;
        Ok(())
    }

    #[cfg(test)]
    fn force_fixture_state(
        &self,
        hash: [u8; 32],
        value: SyntheticWalletOutputState,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        self.lock_state()?
            .outputs
            .get_mut(&hash)
            .ok_or(Ggbp1WalletAdapterError::ReservationNoLongerEligible)?
            .state = value;
        Ok(())
    }

    #[cfg(test)]
    fn corrupt_fixture_opening(
        &self,
        hash: [u8; 32],
        mask: tari_crypto::ristretto::RistrettoSecretKey,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        self.lock_state()?
            .outputs
            .get_mut(&hash)
            .ok_or(Ggbp1WalletAdapterError::ReservationNoLongerEligible)?
            .witness
            .corrupt_mask_for_fixture_test(mask);
        Ok(())
    }

    #[cfg(test)]
    fn recover_synthetic_restart(&self) -> Result<(), Ggbp1WalletAdapterError> {
        self.lock_state()?.reservations.clear();
        Ok(())
    }
}

fn approval_prompt(
    request: &Ggbp1WalletProofRequest,
    selected: &[SyntheticOutputWitness],
    fingerprint: [u8; 32],
) -> Ggbp1WalletApprovalPrompt {
    let challenge = &request.challenge;
    Ggbp1WalletApprovalPrompt {
        network: challenge.network,
        genesis_hash: challenge.genesis_hash,
        relying_party_origin: request.relying_party_origin.clone(),
        gate_id: challenge.gate_id,
        gate_configuration_version: challenge.gate_configuration_version,
        subject_id: challenge.subject_id,
        subject_authentication_public_key: challenge.subject_authentication_public_key.clone(),
        threshold_micro_xtm: challenge.threshold_micro_xtm,
        expires_at_unix_seconds: challenge.expires_at_unix_seconds,
        selected_output_hashes: selected
            .iter()
            .map(|output| output.public.output_hash)
            .collect(),
        request_fingerprint: fingerprint,
    }
}

fn request_fingerprint(
    request: &Ggbp1WalletProofRequest,
    hashes: &[[u8; 32]],
) -> Result<[u8; 32], Ggbp1WalletAdapterError> {
    let canonical = request.challenge.canonical_message(hashes)?;
    Ok(hash(
        b"com.ghost-gate.ggbp1.wallet_request_fingerprint/v1",
        &[&canonical, request.relying_party_origin.as_str().as_bytes()],
    ))
}

fn request_binding_bytes(request: &Ggbp1WalletProofRequest) -> Vec<u8> {
    let challenge = &request.challenge;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GGBP1-WALLET-REQUEST");
    bytes.push(challenge.network);
    bytes.extend_from_slice(&challenge.genesis_hash);
    bytes.extend_from_slice(&challenge.origin_hash);
    bytes.extend_from_slice(&challenge.gate_id);
    bytes.extend_from_slice(&challenge.gate_configuration_version.to_le_bytes());
    bytes.extend_from_slice(&challenge.subject_id);
    bytes.extend_from_slice(challenge.subject_authentication_public_key.as_bytes());
    bytes.extend_from_slice(&challenge.threshold_micro_xtm.to_le_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(&challenge.expires_at_unix_seconds.to_le_bytes());
    bytes.extend_from_slice(&challenge.commitment_generator_fingerprint);
    bytes.extend_from_slice(request.relying_party_origin.as_str().as_bytes());
    bytes
}

fn hash(domain: &[u8], pieces: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for piece in pieces {
        digest.update(&(piece.len() as u64).to_le_bytes());
        digest.update(piece);
    }
    digest.finalize().into()
}

fn keyed_hash(key: &[u8; 32], domain: &[u8], pieces: &[&[u8]]) -> [u8; 32] {
    let mut digest = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts the fixed-size synthetic capability key");
    digest.update(domain);
    for piece in pieces {
        digest.update(&(piece.len() as u64).to_le_bytes());
        digest.update(piece);
    }
    digest.finalize().into_bytes().into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ggbp1WalletAdapterError {
    #[error("the relying-party origin is not a strict canonical HTTPS origin")]
    InvalidRelyingPartyOrigin,
    #[error("the complete proof request did not authenticate to the wallet runtime")]
    RequestAuthenticationFailed,
    #[error("the GGBP-1 challenge network differs from the wallet chain context")]
    NetworkMismatch,
    #[error("the GGBP-1 challenge genesis hash differs from the wallet chain context")]
    GenesisMismatch,
    #[error("the canonical relying-party origin does not match the challenge binding")]
    OriginBindingMismatch,
    #[error("the GGBP-1 challenge subject is not controlled by this synthetic wallet")]
    SubjectMismatch,
    #[error("the GGBP-1 challenge uses unsupported commitment generators")]
    UnsupportedCommitmentGenerators,
    #[error("the GGBP-1 challenge or reservation lease is expired")]
    ChallengeExpired,
    #[error("the reservation policy has a zero lease duration")]
    InvalidReservationPolicy,
    #[error("the reservation lease expiry overflows the Unix timestamp range")]
    LeaseExpiryOverflow,
    #[error("synthetic outputs have duplicate public identifiers")]
    DuplicateOutputIdentifier,
    #[error("eligible output values overflow the supported aggregate")]
    AggregateOverflow,
    #[error("there are insufficient eligible standard outputs for the requested threshold")]
    InsufficientEligibleValue,
    #[error("a wallet-held opening does not match its public commitment")]
    InvalidStoredOpening,
    #[error("the reservation is unavailable, expired, or has been cancelled")]
    ReservationUnavailable,
    #[error("the prepared request does not match its wallet reservation")]
    ReservationBindingMismatch,
    #[error("the wallet foreground approval does not match its exact prepared request")]
    InvalidApprovalDecision,
    #[error("the reservation is already proving")]
    ReservationInProgress,
    #[error("a selected output changed or became ineligible before proof generation")]
    ReservationNoLongerEligible,
    #[error("normal spending must not use an output while a GGBP-1 lease is active")]
    OutputReserved,
    #[error("the synthetic reservation sequence overflowed")]
    ReservationSequenceOverflow,
    #[error("a synthetic reservation identifier collision occurred")]
    ReservationIdentifierCollision,
    #[error("the wallet state mutex is unavailable")]
    InternalStateUnavailable,
    #[error("the wallet user declined the exact GGBP-1 approval prompt")]
    UserDeclined,
    #[error(transparent)]
    Proof(#[from] Ggbp1Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use rand::{SeedableRng, rngs::StdRng};
    use tari_crypto::keys::PublicKey;
    use tari_crypto::ristretto::RistrettoSecretKey;

    use super::*;

    fn key(value: u64) -> RistrettoSecretKey {
        RistrettoSecretKey::from(value)
    }

    fn subject() -> SyntheticSubjectWitness {
        SyntheticSubjectWitness::new(key(31))
    }

    fn origin() -> Ggbp1CanonicalHttpsOrigin {
        Ggbp1CanonicalHttpsOrigin::parse("https://GATE.EXAMPLE:443").unwrap()
    }

    fn challenge(threshold: u64) -> Ggbp1Challenge {
        Ggbp1Challenge {
            network: 42,
            genesis_hash: [1; 32],
            origin_hash: origin().hash(),
            gate_id: [3; 16],
            gate_configuration_version: 7,
            subject_id: [4; 16],
            subject_authentication_public_key: subject().public_key(),
            threshold_micro_xtm: threshold,
            nonce: [5; 32],
            expires_at_unix_seconds: 1_800_000_000,
            commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn output(
        id: u8,
        value: u64,
        confirmed: Option<u64>,
        maturity: u64,
        lock: Option<u64>,
        covenant: bool,
        script: bool,
        state: SyntheticWalletOutputState,
    ) -> SyntheticWalletOutput {
        SyntheticWalletOutput::new_fixture(
            SyntheticOutputWitness::new(
                [id; 32],
                value,
                key(u64::from(id) + 10),
                key(u64::from(id) + 20),
            ),
            confirmed,
            maturity,
            lock,
            covenant,
            script,
            state,
        )
    }

    fn available(id: u8, value: u64) -> SyntheticWalletOutput {
        output(
            id,
            value,
            Some(90),
            91,
            Some(92),
            true,
            true,
            SyntheticWalletOutputState::Available,
        )
    }

    fn fixture_wallet(outputs: Vec<SyntheticWalletOutput>) -> SyntheticWalletGgbp1Prover {
        SyntheticWalletGgbp1Prover::new_fixture(
            SyntheticWalletChainContext {
                network: 42,
                genesis_hash: [1; 32],
                tip_height: 100,
                minimum_confirmations: 2,
            },
            subject(),
            outputs,
        )
        .unwrap()
    }

    fn proof_request(challenge: Ggbp1Challenge) -> Ggbp1WalletProofRequest {
        Ggbp1WalletProofRequest::new(challenge, origin())
    }

    #[test]
    fn wallet_owned_approval_returns_only_a_bound_verifiable_response() {
        let now = 1_799_999_900;
        let wallet = fixture_wallet(vec![available(1, 45), available(3, 55)]);
        let challenge = challenge(100);
        let authenticated = wallet.authenticate_fixture_request(proof_request(challenge.clone()));
        let prepared = wallet
            .prepare_authenticated_proof(&authenticated, now)
            .unwrap();
        assert_eq!(
            prepared.prompt().relying_party_origin.as_str(),
            "https://gate.example"
        );
        assert_eq!(
            prepared.prompt().selected_output_hashes,
            vec![[1; 32], [3; 32]]
        );
        assert_eq!(prepared.prompt().subject_id, [4; 16]);
        let approval = wallet
            .approve_from_wallet_foreground(&prepared, now + 1)
            .unwrap();
        let mut rng = StdRng::from_seed([21; 32]);
        let bytes = wallet.prove_approved(&approval, now + 2, &mut rng).unwrap();
        let wire = Ggbp1WireProof::from_bytes(&bytes).unwrap();
        crate::ggbp1::verify_synthetic(&challenge, &wire.proof).unwrap();
    }

    #[test]
    fn forged_request_approval_origin_or_subject_is_rejected() {
        let now = 1_799_999_900;
        let wallet = fixture_wallet(vec![available(1, 100)]);
        let mut forged = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        forged.authentication_tag[0] ^= 1;
        assert_eq!(
            wallet
                .prepare_authenticated_proof(&forged, now)
                .unwrap_err(),
            Ggbp1WalletAdapterError::RequestAuthenticationFailed
        );
        let mut wrong_origin = challenge(100);
        wrong_origin.origin_hash = [9; 32];
        let wrong_origin = wallet.authenticate_fixture_request(proof_request(wrong_origin));
        assert_eq!(
            wallet
                .prepare_authenticated_proof(&wrong_origin, now)
                .unwrap_err(),
            Ggbp1WalletAdapterError::OriginBindingMismatch
        );
        let mut wrong_subject = challenge(100);
        wrong_subject.subject_authentication_public_key =
            RistrettoPublicKey::from_secret_key(&key(99));
        let wrong_subject = wallet.authenticate_fixture_request(proof_request(wrong_subject));
        assert_eq!(
            wallet
                .prepare_authenticated_proof(&wrong_subject, now)
                .unwrap_err(),
            Ggbp1WalletAdapterError::SubjectMismatch
        );
        let authenticated = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet
            .prepare_authenticated_proof(&authenticated, now)
            .unwrap();
        let mut approval = wallet
            .approve_from_wallet_foreground(&prepared, now)
            .unwrap();
        approval.approval_tag[0] ^= 1;
        let mut rng = StdRng::from_seed([22; 32]);
        assert_eq!(
            wallet
                .prove_approved(&approval, now + 1, &mut rng)
                .unwrap_err(),
            Ggbp1WalletAdapterError::InvalidApprovalDecision
        );
    }

    #[test]
    fn reservation_is_atomic_cancellable_expiring_and_restart_recoverable() {
        let now = 1_799_999_900;
        let wallet = Arc::new(fixture_wallet(vec![available(1, 100)]));
        let barrier = Arc::new(Barrier::new(2));
        let left_wallet = wallet.clone();
        let left_barrier = barrier.clone();
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            let request = left_wallet.authenticate_fixture_request(proof_request(challenge(100)));
            left_wallet.prepare_authenticated_proof(&request, now)
        });
        let right_wallet = wallet.clone();
        let right = std::thread::spawn(move || {
            barrier.wait();
            let request = right_wallet.authenticate_fixture_request(proof_request(challenge(100)));
            right_wallet.prepare_authenticated_proof(&request, now)
        });
        let left = left.join().unwrap();
        let right = right.join().unwrap();
        assert!(left.is_ok() ^ right.is_ok());
        let prepared = left.ok().or(right.ok()).unwrap();
        assert_eq!(
            wallet.try_fixture_spend([1; 32], now),
            Err(Ggbp1WalletAdapterError::OutputReserved)
        );
        wallet.cancel_prepared_proof(&prepared, now + 1).unwrap();
        wallet.try_fixture_spend([1; 32], now + 1).unwrap();

        let wallet = fixture_wallet(vec![available(1, 100)]);
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet.prepare_authenticated_proof(&request, now).unwrap();
        assert_eq!(
            wallet
                .approve_from_wallet_foreground(&prepared, now + 60)
                .unwrap_err(),
            Ggbp1WalletAdapterError::ReservationUnavailable
        );
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet
            .prepare_authenticated_proof(&request, now + 60)
            .unwrap();
        wallet.recover_synthetic_restart().unwrap();
        assert_eq!(
            wallet
                .approve_from_wallet_foreground(&prepared, now + 61)
                .unwrap_err(),
            Ggbp1WalletAdapterError::ReservationUnavailable
        );
    }

    #[test]
    fn revalidation_refuses_changed_output_state_or_opening() {
        let now = 1_799_999_900;
        let wallet = fixture_wallet(vec![available(1, 100)]);
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet.prepare_authenticated_proof(&request, now).unwrap();
        let approval = wallet
            .approve_from_wallet_foreground(&prepared, now)
            .unwrap();
        wallet
            .force_fixture_state([1; 32], SyntheticWalletOutputState::Spent)
            .unwrap();
        let mut rng = StdRng::from_seed([23; 32]);
        assert_eq!(
            wallet
                .prove_approved(&approval, now + 1, &mut rng)
                .unwrap_err(),
            Ggbp1WalletAdapterError::ReservationNoLongerEligible
        );
        let wallet = fixture_wallet(vec![available(1, 100)]);
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet.prepare_authenticated_proof(&request, now).unwrap();
        let approval = wallet
            .approve_from_wallet_foreground(&prepared, now)
            .unwrap();
        wallet.corrupt_fixture_opening([1; 32], key(99)).unwrap();
        assert_eq!(
            wallet
                .prove_approved(&approval, now + 1, &mut rng)
                .unwrap_err(),
            Ggbp1WalletAdapterError::InvalidStoredOpening
        );
    }

    #[test]
    fn selection_excludes_restricted_outputs_and_errors_are_secret_free() {
        let now = 1_799_999_900;
        let wallet = fixture_wallet(vec![
            output(
                1,
                1_000,
                Some(90),
                91,
                Some(92),
                true,
                true,
                SyntheticWalletOutputState::PendingOutgoing,
            ),
            output(
                2,
                1_000,
                Some(90),
                91,
                Some(101),
                true,
                true,
                SyntheticWalletOutputState::Available,
            ),
            output(
                3,
                1_000,
                Some(90),
                91,
                Some(92),
                false,
                true,
                SyntheticWalletOutputState::Available,
            ),
            output(
                4,
                1_000,
                Some(90),
                91,
                Some(92),
                true,
                false,
                SyntheticWalletOutputState::Available,
            ),
            available(5, 100),
        ]);
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet.prepare_authenticated_proof(&request, now).unwrap();
        assert_eq!(prepared.prompt().selected_output_hashes, vec![[5; 32]]);
        assert_eq!(
            Ggbp1CanonicalHttpsOrigin::parse("https://gate.example/path").unwrap_err(),
            Ggbp1WalletAdapterError::InvalidRelyingPartyOrigin
        );
        assert!(
            !Ggbp1WalletAdapterError::RequestAuthenticationFailed
                .to_string()
                .contains("secret")
        );
    }

    #[test]
    fn decline_releases_the_exact_reservation() {
        let now = 1_799_999_900;
        let wallet = fixture_wallet(vec![available(1, 100)]);
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        let prepared = wallet.prepare_authenticated_proof(&request, now).unwrap();
        assert_eq!(
            wallet
                .decline_from_wallet_foreground(&prepared, now)
                .unwrap_err(),
            Ggbp1WalletAdapterError::UserDeclined
        );
        let request = wallet.authenticate_fixture_request(proof_request(challenge(100)));
        assert!(wallet.prepare_authenticated_proof(&request, now).is_ok());
    }
}
