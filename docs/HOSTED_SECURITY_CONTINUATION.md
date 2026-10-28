# Hosted security continuation â€” public authorization is not ready

The hosted authorization boundaries below are implemented and locally tested. Independent protocol review and Cloudflare runtime verification remain required before public authorization. CBOR and Linux deployment are separate tasks.

## Generation and trust boundary — implemented locally

The coordinator now obtains fresh backend eligibility through POST `/v1/hosted/verify` with the authenticated `hostedState` operation. It uses the existing request/response HMAC keys. Each query has a cryptographically random request nonce; the signed response echoes the entire request and includes an issuance time. The coordinator requires a matching request, valid HMAC, at most five seconds clock skew/response age and a five-second round trip. There is no positive cache or outage fallback. Keys must be configured on both the Worker and Durable Object environment. This uses the existing tunnel route.

The bridge reloads the authoritative registry AND durable generation ledger for each operation. It checks tenant equals registry application ID, gate/network/resource/threshold, published policy (`vN`), relying origin allowlist, effective generation, enabled state and evidence trust. `hosted_state` invokes the same `issue_session_with_token` and `check_access` functions used by local authorization, using a non-persisted eligibility session. No synthetic session is granted or saved. Only actual `CredentialVerifier` acceptance produces VERIFIED. Indexer evidence stays IndexerAsserted, capped at OperatorTrustedTestnet. Hosted mode requires registry bindings; preview-only acceptance is removed.

Each durable record gains a nullable `backend_state` column without deleting replay history. Legacy records without that binding cannot authorize. State binds generation (decimal string), policy hash, halt revision and maximum session TTL. The coordinator fetches state at issue, reserve, authorize, access, status and revoke. A mismatch permanently retires the record. Proof requests carry the reserved backend state under a Worker-created wrapper; the bridge compares state before and after credential verification. The coordinator independently checks it again before redemption. Sessions and pending challenges from earlier generations cannot be migrated or revived. The registry's append-only generation floor rejects configuration rollback; each coordinator also retires a record on any state mismatch, including rollback.

Manual `latch_halt` rotates a durable `hosted_halt_revision` before creating the halt file. The revision rotates again at recovery and survives clearing and restart. Thus a halt and recovery that happen between requests still invalidate old sessions and pending challenges. An active halt returns no eligible signed state, so decisions fail closed. Preserve this revision file together with the generation ledger and registry during backup/restore. Use the supported halt/recovery functions rather than deleting files manually. No automatic reset detector was added.

Authorization is linearized at the fresh bridge state read for that decision, with checks repeated after chain verification and at coordinator redemption. A request overlapping a halt may finish based on a read immediately preceding that halt; requests observing the halt cannot authorize. Instant cancellation of already in-flight HTTP responses across machines is not claimed. Independent review must assess this ordering contract, the five-second clock/transport bound, filesystem atomic replacement and halt concurrency, durable state preservation/rollback protection, and actual Cloudflare DO scheduling. Production runtime, live wallet and live testnet checks remain separate. The local cross-language integration test runs the compiled Rust handler with real Schnorr signatures over simulated chain outputs, the Worker, and SQLite coordinator; it is not a Cloudflare runtime test.

Focused test commands (PowerShell):

```powershell
cargo test -p ghost-gate-bridge --lib
# Set to the executable path printed by Cargo above, not a production binary:
$env:GG_HOSTED_TEST_BINARY = 'ABSOLUTE_PATH_TO_ghost_gate_bridge_TEST_EXECUTABLE'
node --test --test-isolation=none cloudflare/test/*.test.js
Remove-Item Env:GG_HOSTED_TEST_BINARY
```

## Chain wire format

`crates/ghost-gate-walletd/src/esmeralda.rs::JsonChainReader` is the live JSON credential reader; `ghost-gate-cbor` is an isolated decoder and is not connected to it. Do not infer the engine UTXO layout from a generic CBOR value. Capture a real supported response and upstream schema, then add strict typed mapping and malformed, unknown-version, resource, liveness, key and balance fixtures before enabling CBOR. Decoding does not provide independent consensus verification.

## Deployment safeguards

The previous tunnel template forwarded every bridge path, including administrative and diagnostic routes. The narrowed template permits only the hosted verifier, the Telegram credential paths, and the bot claim endpoint; verify with the installed `cloudflared tunnel ingress validate` and `cloudflared tunnel ingress rule` commands before use. Path routing is not authentication. Check URL normalization and method behavior in the deployed version and confirm all unrelated paths return 404. `web/telegram/join.html` requires exact HTTPS origin metadata for both bridge and claim; leaving it blank intentionally fails closed. Do not publish or configure secrets until the new authorization protocol is independently reviewed. Local checks do not prove a live wallet, Telegram admission, VPS build, Cloudflare routing, or current indexer compatibility.

## Local validation checkpoint (2026-10-27)

- `cargo test -p ghost-gate-bridge --lib`: 169 passed, 0 failed (includes the fixture entry point, a no-op unless invoked by the integration harness).
- `cargo test -p ghost-gate-registry generation`: 7 passed, 0 failed, 17 filtered out.
- With `GG_HOSTED_TEST_BINARY` pointing at the compiled Rust test executable, `node --test --test-isolation=none cloudflare/test/*.test.js`: 14 passed, 0 failed, 0 skipped. This includes Worker issuance, real Rust credential verdict, SQLite redemption, protected access, halt and recovery, old pending challenges, generation change between verification and redemption, backend outage, trust rejection and revocation. Additional coordinator tests reject forged, stale and replayed signed state.
- `git diff --check`: clean for this patch. Existing unrelated admin modifications were preserved.

Ready for independent security review of these authorization changes. Public authorization remains gated on that review and actual Cloudflare/runtime verification. Keep registry, generation ledger and halt revision durable and protected; restoring/deleting authoritative state outside the supported administrative process can defeat filesystem-based rollback protection. Clocks must satisfy the five-second bound or hosted access fails closed.

## Independent review follow-up (2026-10-27)

- Operator halt commands: `GG_BINDINGS_PATH=<registry dir> ghost-gate-bridge halt "<reason>"` and `... clear-halt "<ack>"`. Before this, nothing outside tests called `latch_halt`/`clear_halt`, so the only available halt was hand-creating/deleting `reset_halt.json`, which skips the revision rotation and lets pre-halt hosted sessions and pending challenges revive after recovery. Never edit the halt file or `hosted_halt_revision` by hand.
- `hosted_state` now refuses gates scoped `telegram`, matching the local credential route.
- Hosted sessions have no per-session administrative revocation (the registry's session revocation does not reach Durable Object records). Mass revocation is available through halt + clear-halt, generation migration, or republishing the gate policy; per-visitor revocation is the visitor's own `/revoke`.
