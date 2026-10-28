# Ghost Gate restricted staging runbook

This runbook is for a separate restricted staging deployment. It does not
authorize VPS access, Cloudflare changes, DNS, tunnel creation, secret upload,
public authorization, or Telegram membership changes.

Security baseline: 260b1921a19e4e23c5427e08b65878ad9188a1d9 plus the local
deployment-readiness commit that contains this runbook. Credential evidence is
OperatorTrustedTestnet: it is indexer-derived and not independent consensus
verification.

## Local source package

Ghost Gate uses the sibling path dependency ../_ootle-v042-ghost-gate. Generate
a clean package from reviewed local HEAD:

~~~powershell
pwsh -File .\scripts\package-staging-source.ps1
Get-FileHash .\artifacts\ghost-gate-staging-source-*.tar.gz -Algorithm SHA256
~~~

The packager uses git archive for Ghost Gate and rejects keys, environment
files, databases, registry/session/replay/halt state, target trees, git
directories, node modules, and Worker runtime state. It adds a manifest with
the source commit. Do not add wallets, administrator data, bot tokens, Worker
secrets, or existing replay state.

## Approved VPS transfer and Linux build

After explicit approval, substitute VPS_HOST and the archive name:

~~~powershell
scp .\artifacts\ghost-gate-staging-source-<commit>.tar.gz root@VPS_HOST:/tmp/
scp -r .\deploy root@VPS_HOST:/tmp/ghost-gate-deploy
ssh root@VPS_HOST 'bash /tmp/ghost-gate-deploy/setup-vps.sh'
ssh root@VPS_HOST 'mkdir -p /opt/ghost-gate/source && tar -xzf /tmp/ghost-gate-staging-source-<commit>.tar.gz -C /opt/ghost-gate/source'
ssh root@VPS_HOST 'cd /opt/ghost-gate/source/ghost-gate-staging-source-<commit>/ghost-gate-laptop && CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/var/tmp/ghost-gate-target cargo build --locked --release -j 2 -p ghost-gate-walletd -p ghost-gate-telegram'
ssh root@VPS_HOST 'install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-bridge /opt/ghost-gate/bin/ghost-gate-bridge && install -o root -g root -m 0755 /var/tmp/ghost-gate-target/release/ghost-gate-telegram /opt/ghost-gate/bin/ghost-gate-telegram && file /opt/ghost-gate/bin/ghost-gate-* && sha256sum /opt/ghost-gate/bin/ghost-gate-*'
~~~

The binaries are ghost-gate-bridge from ghost-gate-walletd and
ghost-gate-telegram from ghost-gate-telegram. Build with two jobs on the
2-vCPU/4-GB server. Do not claim a Linux build until file reports Linux ELF
binaries.

The bridge binds only 127.0.0.1:7799. Telegram claims bind only
127.0.0.1:7808. Neither port is opened in UFW.

### Disposable halt command test

Before starting services, test the installed command path without touching
production registry data:

~~~bash
tmp=$(mktemp -d /var/tmp/gg-halt.XXXXXX)
chown ghostgate-bridge:ghostgate "$tmp"
sudo -u ghostgate-bridge env GG_BINDINGS_PATH="$tmp" /opt/ghost-gate/bin/ghost-gate-bridge halt "staging command test"
test -f "$tmp/reset_halt.json" && test -f "$tmp/hosted_halt_revision"
sudo -u ghostgate-bridge env GG_BINDINGS_PATH="$tmp" /opt/ghost-gate/bin/ghost-gate-bridge clear-halt "staging command test reviewed"
test ! -e "$tmp/reset_halt.json"
rm -rf -- "$tmp"
~~~

Both commands must succeed. Never create or remove reset_halt.json directly:
the commands rotate hosted_halt_revision, retiring hosted sessions and pending
challenges.

## Services and staging policy state

The installation template creates:

~~~
/etc/systemd/system/ghost-gate-bridge.service
/etc/systemd/system/ghost-gate-telegram.service
~~~

It uses separate no-login users, ghostgate-bridge and ghostgate-telegram. Only
the bridge writes /opt/ghost-gate/data; the bot uses loopback HTTP and has no
registry/replay write permission. Binaries are root-owned and the environment
files are root-owned and each is readable only by its corresponding service
account, mode 0640.

Use exact staging values:

~~~dotenv
GG_BRIDGE_BIND=127.0.0.1:7799
GG_BRIDGE_ORIGINS=https://STAGING_WORKER_ORIGIN
GG_BRIDGE_PERMITTED_HOSTS=bridge.STAGING_DOMAIN
GG_BINDINGS_PATH=/opt/ghost-gate/data/registry
GG_REPLAY_STORE_PATH=/opt/ghost-gate/data/replays
GG_INDEXER_ENDPOINT=https://OOTLE_INDEXER_ENDPOINT
GG_OPERATOR_TRUSTED_INDEXER=1
GG_MAX_TRUST_TIER=operator-trusted-testnet
GG_BRIDGE_ENDPOINT=http://127.0.0.1:7799
GG_JOIN_BASE_URL=https://STAGING_WORKER_ORIGIN
GG_BRIDGE_PUBLIC_URL=https://bridge.STAGING_DOMAIN
~~~

Keep GG_WALLETD_ENDPOINT unset. The VPS must hold no wallet keys.

Prepare a new staging-only policy snapshot through the existing admin workflow.
Do not copy a laptop registry, sessions, replay data, audit log, wallet, or
admin login state. A reviewed first-start bundle contains only registry.json,
bindings.json, generations.ndjson, and sessions.json. Its admin_sessions and
sessions arrays must be empty; public administrator credential material remains
only because registry validation requires the policy owner.

Copy the reviewed bundle while services are stopped, set its owner to
ghostgate-bridge:ghostgate-bridge, then run:

~~~bash
systemctl enable --now ghost-gate-bridge ghost-gate-telegram
curl --fail --silent http://127.0.0.1:7799/health
systemctl --no-pager --full status ghost-gate-bridge ghost-gate-telegram
~~~

Do not enable cloudflared yet.

## Reset and generation procedure

Automatic reset detection is not implemented. If continuity is unknown, an
epoch/indexer response is suspicious, or the response format is unsupported:

1. Run ghost-gate-bridge halt against the real registry directory.
2. Migrate the isolated staging authority to a strictly higher generation using
   the existing admin workflow. Never hand-edit or roll back generations.ndjson.
3. Review the resource, network byte, indexer format, and policy. Stop bridge
   before installing a reviewed replacement policy bundle.
4. Run clear-halt with a meaningful review acknowledgement.
5. Require a fresh proof. Old hosted sessions and pending challenges must stay
   retired.

The Worker and Durable Object obtain fresh authenticated backend state for
issuance, redemption, and session checks. Unavailable or stale backend state
fails closed.

## Separate Cloudflare staging

Copy cloudflare/wrangler.staging.toml.template to untracked
wrangler.staging.toml. Generate untracked staging assets with exact origins:

~~~powershell
pwsh -File .\scripts\prepare-staging-web.ps1 -WorkerOrigin https://STAGING_WORKER_ORIGIN -BridgeOrigin https://bridge.STAGING_DOMAIN -ClaimOrigin https://claim.STAGING_DOMAIN
Copy-Item .\cloudflare\wrangler.staging.toml.template .\cloudflare\wrangler.staging.toml
~~~

Set a separate Worker name, Durable Object binding, staging-only gate catalog,
verifier origin, coordinator token, bearer token, and HMAC keys. The tunnel is
not an authorization boundary: Worker-to-bridge requests also require bearer
and canonical HMAC validation; the bridge checks tenant, gate, relying site,
network, resource, threshold, policy, generation, halt, and trust tier.

The tunnel template permits only:

~~~
bridge.STAGING_DOMAIN  /v1/hosted/verify
bridge.STAGING_DOMAIN  /gate/<id>[/(challenge|credential)]
claim.STAGING_DOMAIN   /claim
all other paths        HTTP 404
~~~

Do not expose admin, walletd, health, diagnostic, or wildcard bridge routes.
Before testers get a URL, configure Cloudflare WAF limits as an account action:
challenge 20 requests/min/IP, proof 10/min/IP, status 60 requests/min/IP, and
the same limits for direct Telegram bridge paths. Test Web Tari Universe with
Cloudflare Access before depending on Access; its iframe may not complete an
Access interstitial. Do not place Access on hosted verify until the Worker has
a service-token integration; HMAC/bearer remain mandatory.

## Required deployed-runtime checklist

Local Rust and Miniflare tests are not Cloudflare runtime proof. After approved
deployment, validate:

1. Linux ELF binaries, source manifest, and canonical request/response HMAC.
2. A genuine Worker challenge and Durable Object concurrent redemption: at most
   one usable session.
3. Forged or stale signatures, tunnel interruption, stale backend state, and a
   revoked session all fail closed.
4. A qualifying Sapient wallet authorizes; below 10 tTARI rejects; the result
   is labeled OperatorTrustedTestnet only.
5. Halt, generation migration, recovery, old session, and old pending
   challenge behavior require a fresh proof after recovery.
6. Live Esmeralda JSON or supported CBOR compatibility. Leave halt latched if
   continuity or decoding is unknown.
7. Tunnel latency and clock skew, because backend state has a five-second
   freshness bound.
8. Telegram qualification, insufficient balance, revocation, expiry, and exact
   bridge and claim destination handling.

For an incident, halt first and then disable tunnel routing or cloudflared. Do
not delete replay or registry evidence. Roll back only to a reviewed binary and
a generation-monotonic policy snapshot.
