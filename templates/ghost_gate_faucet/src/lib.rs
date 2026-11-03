//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Test-only funding fixture for Ghost Gate's engine tests.
//!
//! NOT part of the shipped Ghost Gate template and not a security component. Its only job is to
//! create a stealth resource and turn the mint into the stealth outputs a test asked for, so the
//! test can then spend them with a mask and spend key it holds.
//!
//! A template cannot construct stealth outputs itself: that needs Pedersen commitments, a
//! bulletproof and an encrypted payload, none of which a WASM template can do. So the test builds
//! the output statement on the Rust side and passes it in — the same arrangement the Ootle cohort's
//! own `tests/templates/stealth` fixture uses.
//!
//! The outputs are authorised by whatever spend key the test put in the statement. These tests put
//! a key derived from their own signing key there, so the engine's ordinary key-path authorisation
//! path runs for real, with a real signature, rather than being bypassed.

use tari_template_lib::prelude::*;

#[template]
mod faucet {
    use super::*;

    pub struct GhostGateFaucet {
        manager: ResourceManager,
        supply_vault: Vault,
    }

    impl GhostGateFaucet {
        /// Creates a stealth resource with `initial_supply` and converts the mint into the
        /// stealth outputs described by `mint`.
        ///
        /// `symbol` and `divisibility` are presentation. The resource *address* is what a gate binds
        /// to and the only thing any of these tests treats as identity; the two are exposed here so a
        /// test can build a second asset that differs from the first in the ways a real user-created
        /// asset differs -- a different symbol and a different number of decimal places -- and so
        /// prove the gate is unaffected by either.
        pub fn new(
            symbol: String,
            divisibility: u8,
            initial_supply: Amount,
            mint: StealthTransferStatement,
        ) -> Component<Self> {
            let bucket = ResourceBuilder::stealth()
                .with_token_symbol(symbol)
                .with_divisibility(divisibility)
                .mintable(rule!(allow_all), OWNER)
                .withdrawable(rule!(allow_all), OWNER)
                .initial_supply(initial_supply);

            let resource_address = bucket.resource_address();

            // Minting into stealth UTXOs is itself a stealth transfer. The statement carries the
            // masks and spend keys the test chose, so the test can spend the outputs afterwards.
            let revealed = bucket.stealth_transfer(mint);

            Component::new(Self {
                manager: resource_address.into(),
                supply_vault: Vault::from_bucket(revealed),
            })
            .with_upgrade_rule(UpdateRule::Locked)
            .with_access_rules(AccessRules::allow_all())
            .create()
        }

        /// Creates the resource alone, holding `initial_supply` without minting it into any stealth
        /// output.
        ///
        /// `new` cannot be used when the outputs have to be built by a wallet rather than by the
        /// test: a stealth output's tag is derived by its *sender* from the resource address, and the
        /// resource address does not exist until this faucet has executed. So a wallet-funded asset
        /// needs the resource created first and the outputs minted afterwards, which is `this` then
        /// [`GhostGateFaucet::mint`].
        pub fn new_resource(symbol: String, divisibility: u8, initial_supply: Amount) -> Component<Self> {
            let bucket = ResourceBuilder::stealth()
                .with_token_symbol(symbol)
                .with_divisibility(divisibility)
                .mintable(rule!(allow_all), OWNER)
                .withdrawable(rule!(allow_all), OWNER)
                .initial_supply(initial_supply);
            let resource_address = bucket.resource_address();
            Component::new(Self {
                manager: resource_address.into(),
                supply_vault: Vault::from_bucket(bucket),
            })
            .with_upgrade_rule(UpdateRule::Locked)
            .with_access_rules(AccessRules::allow_all())
            .create()
        }

        /// Mints the stealth outputs described by `mint` out of newly minted supply.
        ///
        /// `new` mints the resource's *initial* supply, which fixes the outputs before the resource
        /// address exists. A test whose outputs have to be built by a wallet cannot use that path: the
        /// sender derives a stealth output's tag from the resource address, so the wallet cannot build
        /// the output until the resource is on chain. This second entry point lets such a test create
        /// the resource first and mint the wallet's outputs afterwards.
        ///
        /// The amount comes from the statement's own revealed input, so it cannot disagree with the
        /// outputs the statement creates.
        pub fn mint(&mut self, mint: StealthTransferStatement) {
            let bucket = self.manager.mint_stealth(mint.inputs_statement.revealed_amount);
            self.supply_vault.deposit(bucket.stealth_transfer(mint));
        }

        pub fn resource(&self) -> ResourceAddress {
            self.manager.resource_address()
        }

        /// The resource's decimal places, as recorded on chain.
        pub fn divisibility(&self) -> u8 {
            self.manager.divisibility()
        }

        /// Which class of resource this faucet created, as recorded on chain.
        pub fn resource_type(&self) -> ResourceType {
            self.manager.resource_type()
        }
    }
}
