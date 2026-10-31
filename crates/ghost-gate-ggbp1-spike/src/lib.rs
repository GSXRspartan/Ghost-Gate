//! Isolated test harness for the disabled-by-default GGBP-1 feasibility module.
//!
//! Keeping this package dependency-minimal prevents the synthetic crypto tests from starting a
//! Minotari node, wallet, bridge, transaction, or network service.

#[path = "../../ghost-gate-minotari/src/ggbp1.rs"]
pub mod ggbp1;

#[path = "../../ghost-gate-minotari/src/ggbp1_experiment.rs"]
pub mod ggbp1_experiment;

#[path = "../../ghost-gate-minotari/src/ggbp1_wallet_adapter.rs"]
pub mod ggbp1_wallet_adapter;
