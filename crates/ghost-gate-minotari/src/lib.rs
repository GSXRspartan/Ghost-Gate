//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Native Minotari L1 XTM threshold proving.
//!
//! The layout:
//!
//! - [`service`] — the fee fixed point and the shared request/response shapes.
//! - [`artifact`] — the proof artifact's wire form.
//! - [`wallet_service`] — the real wallet-backed proof service.
//! - [`chain_reader`] — the base-node reader over gRPC.
//! - [`bridge_channel`] — the bridge's `XtmChannel` over the service's loopback HTTP API.
//! - [`http`] — that loopback API.
//!
//! The binary `ghost-gate-minotari-wallet` runs the service against a base node.

pub mod artifact;
#[cfg(feature = "base-node-grpc")]
pub mod chain_reader;
#[cfg(feature = "experimental-ggbp1")]
pub mod ggbp1;
#[cfg(feature = "experimental-ggbp1")]
pub mod ggbp1_chain_view;
#[cfg(feature = "experimental-ggbp1")]
pub mod ggbp1_experiment;
#[cfg(feature = "experimental-ggbp1")]
pub mod ggbp1_wallet_adapter;
pub mod http;
pub mod service;
pub mod wallet_service;

pub fn protocol_version() -> &'static str {
    "xtm-mvp-v1"
}
