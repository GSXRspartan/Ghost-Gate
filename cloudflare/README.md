# Ghost Gate hosted edge (not deployed)

This directory is the hosted-style edge for Ghost Gate. It is deliberately separate from the
local walletd bridge: it contains neither a walletd endpoint nor an operator account, seed, or
wallet API token.

## Hosted browser entrypoint

`/` is a static, Cloudflare-served browser application (`web/hosted.html`). It reuses the
capability-driven Sapient and Tari Universe adapters: a visitor may connect an account, inspect
its reported Ootle network/capabilities, select only a server-published gate, and request a
server-bound challenge. The account address and account name are not sent to the Worker.

The UI deliberately does **not** construct a proof transaction or display access granted until the
hosted verifier independently validates current chain/finality evidence. A connected wallet,
ownership signature, client balance metadata, or an indexer's `verified` field is not enough.

For a local browser-only Worker run, `GG_LOCAL_DEVELOPMENT=1` permits an `http://localhost` or
`http://127.0.0.1` relying site in `GG_GATE_CATALOG` and uses non-`__Host-` development cookies.
That exception is rejected unless the explicit flag is present, and it is never suitable for a
deployed origin. Production gate origins remain exact HTTPS origins and use Secure `__Host-`
cookies.

## Authority split

- The `ReplayCoordinator` Durable Object is the single authority for a hosted challenge nonce.
  It uses Durable Object SQLite storage and owns `issued -> submitted -> authorized/revoked`, the
  original proof job, session expiry, and revocation. It stores hashes of the visitor and access
  bearer values, not their plaintext values.
- The Rust bridge's authenticated `/v1/hosted/verify` adapter validates ownership and chain
  evidence. It has no authority to create a browser session. It receives the server-created tenant, gate, relying
  site, network, asset, threshold, policy version, nonce, proof digest, and proof material.
- The Worker checks a verifier-response HMAC before it asks the Durable Object to authorize.
  Browser-provided balance, account names, threshold metadata, and verdicts are never accepted.

Only the Durable Object is authoritative for a hosted lifecycle. The local Rust `FileReplayStore`
is for a local bridge on one filesystem and is not a second coordinator for hosted challenges.

## Required bindings and secrets

Configure public `GG_GATE_CATALOG` with server-reviewed policy only. Each entry needs tenant,
gate id, relying-site origin, network byte, resource address, raw threshold, divisibility, and
optionally `policyVersion` and `sessionTtlSecs`.

Set these as secrets, never in `wrangler.toml`, browser JavaScript, or a URL:

- `GG_COORDINATOR_TOKEN` — Worker-to-Durable-Object capability.
- `GG_VERIFIER_TOKEN` — Worker-to-Rust-verifier capability.
- `GG_VERIFIER_REQUEST_KEY` — HMAC key over the complete Worker-to-verifier request.
- `GG_VERIFIER_RESPONSE_KEY` — shared HMAC key for canonical verifier responses.

Set `GG_VERIFIER_ORIGIN` to the HTTPS origin of the trusted verifier. Until all three verifier
settings are present, `/proof` returns 503 and cannot create an authorization.

The verifier response must be HMAC-SHA-256 over canonical JSON and contain exactly the request's
nonce, tenant, gate id, relying site, network, resource address, threshold, policy version, proof
digest, a unique verification id, and one of `VERIFIED`, `REJECTED`, `PENDING`, or `UNKNOWN`.
Timeouts, invalid signatures, and malformed results remain pending; they are never released into a
second proof attempt. Only a signed definite `REJECTED` result releases the reservation.

## Local checks

From this directory:

```powershell
npm install
npm test
node .\node_modules\wrangler\bin\wrangler.js deploy --dry-run
```

`deploy --dry-run` validates the bundle and Durable Object binding; it does not deploy. Use a
separate staging configuration and staging-only secrets before any actual `wrangler dev` or
deployment. Secure `__Host-` cookies require HTTPS, including for browser session testing.

## Current boundary

The Worker and Durable Object are locally tested, including a real local Workerd SQLite issue
transition. Restricted staging must set `GG_VERIFIER_ORIGIN` to the bridge tunnel's
`/v1/hosted/verify` endpoint; that adapter invokes the real credential verifier and does not use
the standalone hosted-verifier binary, which returns only `UNKNOWN`. This is not a claim of
cross-region Cloudflare runtime validation: Durable Object single-object execution, tunnel
connectivity, authenticated backend freshness, and real-wallet behavior still require the staging
checks in `docs/VPS_PROVISIONING_RUNBOOK.md`.
