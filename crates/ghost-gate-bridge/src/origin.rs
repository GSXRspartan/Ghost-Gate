//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Which browser origins may talk to this process, and why the answer is a list.
//!
//! A bridge on `127.0.0.1` is reachable by **every page the user has open**, and a browser will happily
//! attach an `Origin` header from any of them to a `fetch` to localhost. Binding the loopback interface
//! stops the network; it does nothing about the browser, because the request originates locally and
//! loopback is exactly where a malicious page expects a wallet to be.
//!
//! So this is an explicit allowlist of full origins, compared for equality. Not a suffix match, not a
//! regex, not "anything on localhost": `http://evil.test` and `http://localhost.evil.test` are not the
//! site operator, and neither is a page served from the operator's own host under a path they do not
//! control.
//!
//! Requests with **no** `Origin` header are allowed, because that is not a browser: it is `curl`, a test
//! harness, or the bridge's own operator. Anything that *does* send an `Origin` must be on the list.
//! That asymmetry is the correct one -- the header's presence is what marks a request as coming from a
//! page, and a page is the untrusted case.

use std::collections::BTreeSet;

/// The exact origins permitted to call the bridge.
#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    allowed: BTreeSet<String>,
}

impl OriginPolicy {
    /// A policy permitting nothing. Every browser origin is refused until one is added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permits one origin, e.g. `https://vip.example`.
    ///
    /// Normalised: a trailing slash is dropped, and the scheme and host are lowercased, so
    /// `HTTPS://VIP.Example/` and `https://vip.example` are the same entry rather than two that quietly
    /// never match. A path is *not* stripped: an origin has no path, and a caller that supplies one is
    /// expressing a misunderstanding this type should not accommodate.
    pub fn allow(mut self, origin: &str) -> Self {
        self.allowed.insert(normalise(origin));
        self
    }

    /// The permitted origins, for logging and for an operator to check.
    pub fn allowed(&self) -> impl Iterator<Item = &str> {
        self.allowed.iter().map(String::as_str)
    }

    /// Whether a request carrying `origin` may proceed.
    pub fn permits(&self, origin: Option<&str>) -> Result<(), OriginRejection> {
        match origin {
            // No Origin: not a browser. A CLI, a test, or the operator.
            None => Ok(()),
            Some(origin) if self.allowed.contains(&normalise(origin)) => Ok(()),
            Some(origin) => Err(OriginRejection::NotAllowed {
                origin: origin.to_string(),
            }),
        }
    }
}

/// Why a request's origin was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OriginRejection {
    #[error("GG: origin {origin} is not permitted to call this bridge")]
    NotAllowed { origin: String },
}

/// Trims and lowercases an origin so the comparison cannot be dodged by case or a trailing slash.
/// The origin comparison used by both the allowlist and the challenge-issuer binding.
///
/// One function, deliberately: the binding check must normalise exactly as the allowlist does, or
/// two spellings of the same origin pass one check and fail the other (the second pass caught the
/// issuer side drifting from the allowlist side).
pub(crate) fn normalise(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OriginPolicy {
        OriginPolicy::new().allow("https://vip.example")
    }

    #[test]
    fn the_listed_origin_is_permitted() {
        assert!(policy().permits(Some("https://vip.example")).is_ok());
    }

    #[test]
    fn case_and_trailing_slash_do_not_defeat_the_list() {
        assert!(policy().permits(Some("HTTPS://VIP.Example/")).is_ok());
        assert!(policy().permits(Some("  https://vip.example  ")).is_ok());
    }

    #[test]
    fn every_other_browser_origin_is_refused() {
        for bad in [
            "https://evil.test",
            // A prefix of the real origin is not the real origin.
            "https://vip.example.evil.test",
            // Nor is a suffix of it.
            "http://vip.example",
            // Nor a subdomain, which a different party may control.
            "https://wallet.vip.example",
            // Nor plain localhost, which every other local process may serve.
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            // Nor an opaque origin, which is what a sandboxed frame sends.
            "null",
            "",
        ] {
            assert!(
                policy().permits(Some(bad)).is_err(),
                "{bad:?} must not be permitted"
            );
        }
    }

    #[test]
    fn a_request_with_no_origin_is_not_a_browser_and_is_allowed() {
        // curl, a test harness, the operator. The header's absence is what marks a request as
        // non-browser, and a non-browser is the trusted case.
        assert!(policy().permits(None).is_ok());
        assert!(
            OriginPolicy::new().permits(None).is_ok(),
            "even with an empty allowlist"
        );
    }

    #[test]
    fn an_empty_policy_refuses_every_browser_origin() {
        let empty = OriginPolicy::new();
        assert!(empty.permits(Some("https://vip.example")).is_err());
        assert_eq!(empty.allowed().count(), 0);
    }

    #[test]
    fn an_origin_with_a_path_is_not_normalised_into_a_match() {
        // An origin has no path. If a caller sends one, refusing is better than accommodating it.
        assert!(policy().permits(Some("https://vip.example/admin")).is_err());
    }

    #[test]
    fn the_allowlist_reports_what_it_permits() {
        assert_eq!(
            policy()
                .allow("http://localhost:5173")
                .allowed()
                .collect::<Vec<_>>(),
            vec!["http://localhost:5173", "https://vip.example"]
        );
    }
}
