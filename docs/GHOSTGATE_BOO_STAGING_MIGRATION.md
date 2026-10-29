# ghostgate.boo restricted staging migration

This is an operator sequence, not a deployment script. It keeps the existing `ghost-gate-staging`
Worker and its `ReplayCoordinator` Durable Object state. It does not reset a registry, bindings,
replay data, Cloudflare Tunnel, or a WebAuthn credential.

## Pre-change boundary

The public Worker may serve `https://ghostgate.boo/`, `/bot`, and `/claim`. It returns a hard 404
for `/admin` and `/admin/*`; neither a Worker asset fallback nor the bridge proxy may expose the
administrator. The tunnel must continue to expose only the current explicit bridge and claim
routes with its `http_status:404` fallback.

The deployed administrator's Windows Hello passkey is registered with RP ID `localhost`.
WebAuthn credentials scoped to `localhost` cannot be used at `ghostgate.boo` or
`admin.ghostgate.boo`. Also, the current dashboard has no reviewed managed-credential enrollment
screen after bootstrap. Therefore `/admin` is intentionally **not** a migration target yet. Keep
administration private over `ssh -N -L 7811:127.0.0.1:7811 ...` until an independently reviewed
new-RP enrollment flow exists. Cloudflare Access alone cannot make the existing localhost passkey
work at a public hostname.

## Ordered restricted-staging procedure

1. Read and copy, without editing, `/opt/ghost-gate/data/registry/registry.json`,
   `bindings.json`, audit files, generation ledger, and bridge replay data to a timestamped VPS
   backup. Confirm the published `Crypt` binding is present once before proceeding.
2. Build and install the tested private-admin UI commit that fixes detached existing-gate prefill.
   Restart only `ghost-gate-admin`; verify it remains `127.0.0.1:7811`. Do not change the bridge,
   bot, tunnel, registry, or policy as part of this UI update.
3. In the Cloudflare dashboard, manually attach the existing `ghost-gate-staging` Worker to the
   apex custom domain `ghostgate.boo` using the existing script/DO deployment. Do not create a
   second Worker, DO namespace, tunnel connector, or a zone route that reaches port 7811. Confirm
   the generated DNS record and retain the previous Workers.dev deployment as rollback.
4. Through the SSH-forwarded `http://localhost:7811` dashboard, select application **Crypt** and
   set **Relying-site / challenge domain** to the exact literal `https://ghostgate.boo`. Click
   **Save gate**, review the draft, then click **Publish** and complete the existing Windows Hello
   step-up. This creates the next immutable policy version. It is the only authorized way to alter
   this policy; do not edit JSON files.
5. Read the newly published `bindings.json` and verify the expected `Crypt` entry has the exact
   new `challenge_domain`, a new `policy_version`, and canonical `policy_hash`. Do not proceed if
   the resource, network, genesis hash, generation, threshold, divisibility, TTL, scope, or proof
   mode changed unexpectedly.
6. On an administrator workstation, make a one-entry origins map:

   ```json
   { "Crypt/Crypt": "https://ghostgate.boo" }
   ```

   Run `scripts/render-worker-catalog.ps1` on the read-only downloaded `bindings.json`. The
   generated catalog must contain that exact origin, `policyVersion`, and `policyHash`. Preserve it
   with the change record; it contains no secrets.
7. Generate staging assets with exact origins:

   ```powershell
   .\scripts\prepare-staging-web.ps1 `
     -WorkerOrigin https://ghostgate.boo `
     -BridgeOrigin https://bridge.ghostgate.boo `
     -ClaimOrigin https://claim.ghostgate.boo
   ```

   Copy `cloudflare/wrangler.ghostgate.toml.template` to ignored
   `cloudflare/wrangler.ghostgate.toml`, insert only the rendered catalog, and retain the existing
   four Worker secrets. Deploy only after an operator has approved the dashboard change. A catalog
   hash mismatch, stale backend, tunnel failure, reset-halt, or generation change fails closed.
8. Configure the existing Telegram service only after the website proof path passes runtime tests:
   `GG_JOIN_BASE_URL=https://ghostgate.boo` and
   `GG_BRIDGE_PUBLIC_URL=https://bridge.ghostgate.boo`. The bridge/claim metadata in generated
   assets must match these exact origins. Leave `GG_TELEGRAM_BOT_URL` absent unless the official
   bot username has been independently confirmed; `/bot` then stays an instruction page instead
   of making an unverified link.

## Runtime acceptance and rollback

Before enabling public authorizations, exercise actual Cloudflare runtime tests: a fresh Sapient
proof at `https://ghostgate.boo`, insufficient-balance rejection, single-use replay resistance,
concurrent redemption, bridge tunnel outage, reset-halt, generation migration, session revocation,
and a Telegram claim/admission/revocation with an account-bound bot token. Local Node/Rust tests
do not prove Cloudflare routing, durable-object behavior, browser wallet behavior, tunnel latency,
or a live Ootle indexer response.

If a check fails: stop issuing proofs, set the bridge reset halt if authorization safety is in
doubt, roll the Worker back to its recorded deployment, and restore only binaries/configuration.
Do not roll back registry, bindings, generation, audit, or replay data to make a failure disappear.
