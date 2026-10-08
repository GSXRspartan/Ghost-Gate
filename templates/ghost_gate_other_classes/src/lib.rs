//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Test-only fixture creating the Ootle resource classes Ghost Gate does **not** support.
//!
//! NOT part of the shipped Ghost Gate template and not a security component. Its only job is to
//! create real resources of the three unsupported classes, so that a test can point a gate at them
//! and observe the refusal. It has to create *real* resources: a made-up address would be refused by
//! substate lookup before the template ever ran, which would prove nothing about the gate's rule.
//!
//! A separate crate from `ghost_gate_faucet` because a WASM module carries exactly one template: the
//! loader rejects a second `GhostGateOtherClasses_main` export in the faucet module.
//!
//! Each class is refused for a different reason, which is the point of building all three:
//!   - public fungible: the balance is visible on chain, so hiding it is not the product;
//!   - confidential fungible: values live in vaults and are revealed per output, so there is no
//!     per-output `minimum_value_promise` to pin a floor to;
//!   - non-fungible: indivisible and individually identified, so there is no amount to threshold.

use tari_template_lib::prelude::*;

#[template]
mod other_classes {
    use super::*;

    pub struct GhostGateOtherClasses {
        manager: ResourceManager,
        supply_vault: Vault,
    }

    impl GhostGateOtherClasses {
        /// A public fungible resource: balances are visible on chain.
        pub fn public_fungible(symbol: String, divisibility: u8, supply: Amount) -> Component<Self> {
            let bucket = ResourceBuilder::public_fungible()
                .with_token_symbol(symbol)
                .with_divisibility(divisibility)
                .mintable(rule!(allow_all), OWNER)
                .initial_supply(supply);
            Self::wrap(bucket)
        }

        /// A confidential fungible resource: balances hide inside vaults and are revealed per
        /// output, so a threshold here would need a different proof entirely.
        pub fn confidential(symbol: String, divisibility: u8, supply: Amount) -> Component<Self> {
            let bucket = ResourceBuilder::confidential()
                .with_token_symbol(symbol)
                .with_divisibility(divisibility)
                .mintable(rule!(allow_all), OWNER)
                .initial_supply(ConfidentialOutputStatement::mint_revealed(supply));
            Self::wrap(bucket)
        }

        /// A non-fungible resource: individually identifiable, indivisible, nothing to threshold.
        pub fn non_fungible(symbol: String, count: u64) -> Component<Self> {
            let bucket = ResourceBuilder::non_fungible()
                .with_token_symbol(symbol)
                .mintable(rule!(allow_all), OWNER)
                .initial_supply((1..=count).map(NonFungibleId::from_u64));
            Self::wrap(bucket)
        }

        /// The resource this faucet created, so a test can point a gate at it and assert the
        /// refusal names the class rather than the address.
        pub fn resource(&self) -> ResourceAddress {
            self.manager.resource_address()
        }

        fn wrap(bucket: Bucket) -> Component<Self> {
            let manager = bucket.resource_address().into();
            Component::new(Self {
                manager,
                supply_vault: Vault::from_bucket(bucket),
            })
            .with_access_rules(AccessRules::allow_all())
            .create()
        }
    }
}
