# Ghost Gate — Contest Submission Draft

## 1. Project name

Ghost Gate

## 2. Tagline

**Prove enough. Reveal less.**

## 3. Short description

Ghost Gate is privacy-aware access control for Tari. It lets a relying application verify that a
visitor meets a published minimum tTARI policy without asking for a seed phrase, private key,
wallet screenshot, video, or exact total balance.

## 4. Problem

Token-gated communities often ask people to show a wallet video or screenshot to human moderators.
That exposes more financial information than the gate needs, creates forwards/stored media, lacks
strong freshness and replay controls, and makes moderators handle sensitive wallet evidence.

## 5. Solution

Ghost Gate converts that manual-disclosure problem into a policy-bound proof and authorization
decision. The current Crypt demo checks a 100 tTARI lower bound on Esmeralda testnet, then issues a
seven-day verified session. The application learns whether the published policy was met, not the
user's total balance.

## 6. Why it matters for Tari

Tari communities and applications can need eligibility decisions without needing a user's whole
financial story. Ghost Gate explores an access-control primitive for community membership,
application features, contributor access, and future policy-controlled resource gates.

## 7. What works today

- Crypt v3: native tTARI, Esmeralda testnet, 100 tTARI threshold, credential mode.
- Fail-closed challenge, policy, relying-site, session, and replay controls.
- Seven-day verified session after a qualifying proof.
- Public Privacy Lab with Simple and Technical views.

The current proof uses a qualifying revealed/public tTARI output. It is not a fully confidential
aggregate wallet-balance proof.

## 8. Live demo

- Privacy Lab: [https://ghostgate.boo](https://ghostgate.boo)
- Test gate: Crypt — 100 tTARI — Esmeralda testnet
- Short walkthrough: [docs/DEMO.md](DEMO.md)

## 9. Wallet integrations

Sapient supports connection, Crypt challenge/proof, refusal of insufficient qualifying funds,
successful verification, and Telegram claim flow. Ghost Gate also works in Web Tari Universe's
embedded dApp browser: the iframe loads, wallet connection works, Crypt proof succeeds, and external
Telegram links safely open outside the frame.

## 10. Telegram integration

`@GhostGateGSXRBot` turns a proof result into an actual, identity-bound membership decision:
`/join` produces a single-use link bound to the Telegram account; the service re-checks server-side
authorization and approves only the matching pending join request. One internal user and one
external user independently completed the gated admission flow during testing.

## 11. Privacy and security design

The flow binds a fresh challenge to the relying site, configured gate, policy hash/version, network,
session commitment, and expiry. Replay coordination and fail-closed behavior prevent a captured or
ambiguous result from becoming an authorization. Telegram does not trust browser success text; it
re-verifies server-side and binds the result to the Telegram user and chat.

Ghost Gate does not request seed phrases or private keys. It does not need the exact total wallet
balance for its access decision. The current revealed/public qualifying output and transaction
metadata remain a stated limitation.

## 12. Technical architecture

Wallet → Privacy Lab/claim UI → Cloudflare Worker → Ghost Gate verifier bridge → Tari/Ootle
qualifying-output evidence → policy-bound session. A Durable Object coordinates replay-sensitive
state when configured. The Telegram service independently calls the bridge before approving the
matching request. Private administration publishes versioned policy separately from public traffic.

## 13. Testing and validation

The release check recorded 53 passing Worker/security/UI tests with one intentionally skipped
integration test, and 31 passing browser-provider tests. Those checks were repeated in a clean clone
after a locked dependency install. Live testnet validation covered insufficient-threshold refusal,
qualifying acceptance, Crypt session issuance, Sapient, Web Tari Universe, and Telegram admission.

The Rust workspace suite is currently blocked before tests start by a missing compatible Windows
Visual Studio/CMake toolchain for `randomx-rs`; this is disclosed in the final public-release audit,
and no test was weakened or bypassed.

## 14. Current limitations

- Operator-trusted Esmeralda testnet demonstration, not production authorization infrastructure.
- Current Crypt path uses a revealed/public qualifying tTARI output.
- Telegram grant state is process-memory state.
- Fully confidential threshold proofs are future work.

## 15. Future roadmap

Persistent grants; self-service gate and Telegram-group onboarding; production trust/bootstrap
hardening; more policy-controlled assets; and confidential threshold proofs.

## 16. XTM / Minotari L1 research direction

Ghost Gate is actively investigating privacy-preserving minimum-balance proofs for Minotari L1 XTM,
including L1 wallet ownership challenges, experimental GGBP-1 work, chain-state verification, and
wallet-core/browser/mobile integration paths. No mainstream XTM wallet is claimed to support the
finished Ghost Gate private-threshold proof today.

## 17. Why this is more than a UI demo

Ghost Gate demonstrates a policy-bound authorization lifecycle across multiple real surfaces:
Sapient, Web Tari Universe's embedded dApp browser, and automated Telegram admission. The Telegram
integration independently re-checks server authorization and approves a specific pending request;
it is not a screenshot collector or browser-text trust exercise.

## 18. GitHub link

`[GitHub release candidate URL to be added after public remote configuration]`

## 19. Screenshots and media

`[Privacy Lab, technical view, Web Tari Universe, and Telegram admission media placeholders]`

## 20. Suggested concise contest-form version

Ghost Gate is privacy-aware access control for Tari: a user proves enough to satisfy a published
policy without handing a moderator their seed phrase, private key, screenshot, video, or exact total
balance. The live Crypt v3 demo checks a 100 tTARI lower bound on Esmeralda testnet, works with
Sapient and Web Tari Universe, and drives a server-reverified Telegram admission flow. It is a
fail-closed, operator-trusted testnet demonstration with an explicit roadmap toward confidential
threshold proofs and broader resource policies.

## 21. Suggested longer technical version

Ghost Gate turns token-gated access from a manual financial-disclosure workflow into a policy-bound
authorization decision. Privacy Lab exposes the live Crypt v3 demonstration at ghostgate.boo;
Sapient and Web Tari Universe complete the qualifying native-tTARI credential flow, and Telegram
uses a single-use account-bound link plus independent server-side re-verification to approve only
the matching pending join request. Challenge freshness, relying-site and policy hash/version binding,
replay coordination, session expiry, origin restrictions, and private policy administration make the
boundary explicit. The current demo uses a revealed/public qualifying output and remains
operator-trusted testnet technology; fully confidential threshold proofs and Minotari L1 XTM support
are active future-work directions, not present-tense claims.
