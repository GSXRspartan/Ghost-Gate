# Ghost Gate authorized security audit and remediation

**Audit date:** 2026-11-05 to 2026-11-06 (America/Los_Angeles)  
**Repository baseline:** `35ae1db`  
**Local remediated head:** `587b0fb` plus the later commit containing this report  
**Production mutations:** none

## Executive verdict

Ghost Gate is not security-verified for production Telegram admission. The native tTARI credential
path has substantial fail-closed controls in source and regression tests, but this audit did not run
a live qualifying and non-qualifying wallet against the deployed Esmeralda service. The current
chain reader is explicitly an operator-trusted testnet dependency, not an independently verified
consensus proof.

The most important unresolved risks are:

1. A Telegram join token is not cryptographically bound to the accepted bridge proof receipt.
2. Telegram membership persists across a bot restart while the bot loses its user-to-session map.
3. Other Telegram administrators, manual adds, and legacy invite links are not reconciled by the
   bot because it does not consume `chat_member` updates.
4. The bridge service can read the full registry containing administrator sessions, collapsing the
   intended bridge/admin process boundary if the bridge is compromised.

The public Cloudflare edge also accepts HTTP without redirect, permits TLS 1.0, has no HSTS, and is
in Full rather than Full (strict) mode. These settings were not changed because production
Cloudflare mutations require approval. Full (strict) must not be selected until every non-Tunnel
origin in the zone has been inventoried and its certificate verified.

Six local remediation checkpoints were completed and tested. They are not active at
`ghostgate.boo` until deliberately deployed.

## Scope and evidence boundaries

Reviewed:

- Worker, Durable Object replay coordinator, static Privacy Lab and Telegram join code.
- Rust bridge credential, challenge, replay, access-session, HTTP, and registry paths.
- Telegram claim, invite, join-request, revocation, and Bot API update handling.
- Administrator WebAuthn/wallet-key authentication and bind configuration.
- VPS service units, environment templates, Tunnel template, setup, backup, and rollback docs.
- Wrangler production/staging templates and the locally present ignored production configuration.
- Low-volume public `HEAD`/`GET` requests and DNS resolution for project hostnames.
- User-confirmed Cloudflare findings dated 2026-11-05.

Not reviewed directly:

- The live Cloudflare dashboard, because the read-only computer-control approval timed out.
- The complete live DNS, WAF, rate-limit, Tunnel, and account-member inventory.
- The VPS firewall, listening sockets, installed binaries, live systemd settings, or cloudflared
  process/configuration.
- Live Cloudflare mutations, VPS deployment, credential rotation, or Telegram permission changes.
- A live wallet qualification/shortfall proof, live Telegram admission/revocation, or destructive
  tests.
- Independent source review of the deployed wallet, indexer, validator, Telegram, Cloudflare, or
  browser binaries.

The on-demand Security Insights API was already known to return HTTP 403. That denial is not
evidence that the underlying findings are remediated.

## Production architecture and trust boundaries

| Layer | Active path | Security authority | Observed protection |
|---|---|---|---|
| Cloudflare edge | `ghostgate.boo` Worker and assets | HTTPS edge, request filtering, Worker routing | Proxied; TLS 1.3 and BIC on; HTTPS redirect/HSTS/TLS floor deficient |
| Cloudflare Tunnel | `bridge.ghostgate.boo`, `claim.ghostgate.boo` | Host/path-to-loopback routing | DNS is proxied; live path allowlist has drifted from the checked-in template |
| Worker | direct `/gate/Crypt/...`, `/proof/.../status`, `/lab/trace`; hosted `/api/...` | Same-origin browser boundary; Durable Object for hosted replay | Local patch adds write-origin checks and reduces route surface |
| Bridge | intended `127.0.0.1:7799` | Gate policy, challenge, chain lookup, signature, replay, access session | Loopback/Host/origin/body caps; registry and replay stores |
| Admin | intended `127.0.0.1:7811` over SSH forwarding | Registry policy and credentials | WebAuthn/wallet-key, Origin, CSRF, step-up; local patch enforces loopback bind |
| Telegram | intended `127.0.0.1:7808` claim listener | Join token, receipt re-read, join-request identity, membership removal | Live-testnet guard; unresolved persistence and alternate-admission gaps |

The active Crypt configuration inspected locally uses network byte `38` (`0x26`, Esmeralda), the
native tTARI resource, divisibility `6`, threshold raw `100000000` (100 tTARI), credential proof
mode, policy v3, relying site `https://ghostgate.boo`, and a seven-day access-session TTL.

The apex production UI uses the direct bridge proxy path. The Worker-native hosted `/api/...`
Durable Object path exists but is not the main Privacy Lab proof route.

## Baseline observations

### Public edge

- `http://ghostgate.boo/` returned `200 OK`, not a redirect.
- `https://ghostgate.boo/` returned `200` without HSTS, CSP, `X-Content-Type-Options`,
  `Referrer-Policy`, or `Permissions-Policy`. It did carry the deliberate cross-origin embedding
  headers required by the Web Tari Universe container.
- `/_edge/health` returned configuration booleans; `/admin` returned a hard JSON 404.
- `claim.ghostgate.boo/` and `/claim` returned application `405`, showing the live public hostname
  reaches the claim process rather than a Tunnel catch-all.
- `bridge.ghostgate.boo/health`, `/gate/Crypt`, `/wallet/status`, and `/lab/gates` returned `200`;
  `/access/check` reached the bridge and returned `400`. This is broader than the checked-in Tunnel
  template and proves live configuration drift.
- Apex, bridge, and claim resolved only to Cloudflare anycast addresses during the baseline. No
  direct VPS address was identified from those records. This does not prove that historical DNS,
  other records, or the VPS firewall cannot expose the origin.

### Confirmed Cloudflare state

- Free plan; nine active insights (seven Moderate, two Low).
- Always Use HTTPS off; minimum TLS 1.0; Full mode; HSTS disabled.
- TLS 1.3 on; Browser Integrity Check on; security level Medium.
- Claim and bridge are proxied CNAMEs.

### Local baseline tests before changes

| Suite | Result |
|---|---:|
| Cloudflare Worker | 53 passed, 0 failed, 1 intentional integration skip |
| Browser provider | 31 passed, 0 failed |
| Telegram Rust | 25 passed, 0 failed |

## Findings

### Critical

No Critical issue was confirmed within the tested scope. This does not mean none exists; the live
Cloudflare account, VPS, wallet/indexer deployment, and Telegram group were not penetration-tested.

### High

#### H-01 — Telegram proof receipt is not bound to the join token — open

The bot binds its random join token to a Telegram user, but the browser later supplies an arbitrary
`proof_id`. The bot re-reads that accepted receipt and its access grant, yet neither the bridge
challenge nor receipt contains a commitment to the join token or Telegram account. The bridge keeps
the access grant readable on proof-status responses because the browser observes the status before
the bot re-reads it. A party who obtains an accepted proof ID can pair it with another valid join
token and authorize a different Telegram identity.

Evidence: `Bot::claim` in `crates/ghost-gate-telegram/src/main.rs`; repeated access-grant lookup in
`crates/ghost-gate-bridge/src/server.rs`; corrected limitation in `docs/TELEGRAM.md`.

Required fix: commit a domain-separated hash of the one-time join token (and gate/chat identity) into
the server-created challenge, wallet-signed message, receipt, and one-time claim consumption record.
The bot must compare that commitment and atomically consume it. Add two-user and shared-proof
adversarial tests before enabling production admission.

#### H-02 — Telegram membership can outlive authorization — open

Grant state and update offset are in memory. Restarting the bot loses the user-to-session mapping,
but members already admitted to Telegram remain members. The bot requests only `message` and
`chat_join_request` updates, not `chat_member`, so other administrators, manual adds, or legacy
invite links are not detected or removed. The present code therefore cannot prove that every group
member entered through Ghost Gate.

Required fix: persist grant/user/session/update-offset state; reconcile `chat_member` events; remove
unmapped members; revoke all pre-existing links; restrict administrator roles; and run restart,
missed-update, manual-add, and second-admin tests against an isolated group.

#### H-03 — Bridge access to the full registry exposes the admin trust domain — open

`AccessPlane::registry()` loads `registry.json`. That file contains administrator credentials,
administrator session bearer tokens, CSRF values, and step-up timestamps. The bridge systemd unit
has registry read/write access through the shared group. A compromised bridge process can therefore
read an administrator session and reach the loopback admin service, defeating the intended process
separation.

Required fix: split public policy/bindings and verified sessions from administrator credentials and
admin sessions. The bridge should receive only a narrow, authenticated policy snapshot plus its own
session store, with no read access to admin authentication state. Rotate existing admin sessions
after that migration.

### Medium

#### M-01 — HTTP downgrade, TLS 1.0, and no HSTS — approval required

The public apex answered plaintext HTTP. The confirmed zone floor is TLS 1.0 and HSTS is disabled.
This permits downgrade/first-visit manipulation and obsolete TLS clients. Enable HTTPS redirect and
TLS 1.2 first, observe, then phase HSTS as specified below.

#### M-02 — Full mode does not authenticate traditional origins — verification required

Full mode encrypts but does not validate a traditional origin certificate. Full (strict) requires a
current trusted/Origin-CA certificate whose SAN matches the origin hostname. The public certificate
is Cloudflare's edge certificate and says nothing about the origin chain.

The checked Tunnel routes use HTTP loopback services. Cloudflare documents that a zone SSL mode does
not change a Tunnel service URL and that cloudflared's connection to Cloudflare is independently
encrypted. Inventory every other proxied record before changing the zone mode.

#### M-03 — Live Tunnel route drift exposes extra bridge/claim paths — fixed locally, undeployed

The public bridge reached health, wallet, gate-list, and access-check paths that the checked-in
allowlist rejects. The local template now permits only hosted verify, gate metadata/challenge/
credential, proof status, sanitized Lab trace, and exact claim. It sets the claim origin Host header
to loopback and ends in a 404 catch-all. Live configuration still requires an approved update.

#### M-04 — Claim HTTP boundary failed open — fixed locally, undeployed

The claim handler ignored the request target, skipped validation for a no-port hostile Host, accepted
a missing JSON media type, did not validate Origin, and let one slow client hold the single pending
read indefinitely. It now requires exact path, loopback Host, exact configured Origin, JSON,
bounded size, a five-second read timeout, and non-cache/sniff/referrer headers. Regression tests
cover hostile/missing Host/Origin/media type/path and replay behavior.

#### M-05 — Admin listener could be exposed by configuration — fixed locally, undeployed

`GG_ADMIN_BIND` was documented as loopback-only but accepted `0.0.0.0`. Startup now rejects every
non-loopback or malformed bind before creating a data directory or bootstrap token. Tests cover
IPv4/IPv6 loopback, localhost, unspecified, public, hostname, and malformed values.

#### M-06 — Sensitive backups had permissive default modes — fixed locally, undeployed

Backups contain registry and replay state, including authorization data, despite the former comment
saying secrets were not backed up. Setup left the backup directory under a mode-755 data directory,
and archive creation inherited the caller's umask. The script now uses umask 077, root-only 0700
directory, 0600 temporary archive, and atomic publish; setup enforces matching ownership/mode.

#### M-07 — Access bearer appeared in a query URL — fixed locally, undeployed

The bot sent access-session tokens in `/access/check?...&token=...`, allowing leakage into proxy,
request, or diagnostic logs. The route is now a bounded JSON POST; legacy query requests are 404;
the server also verifies that the supplied application matches the gate's registry binding. A
wire-level test confirms the bearer is absent from the request target.

#### M-08 — Cross-site pages could issue blind bridge writes through the Worker — fixed locally,
undeployed

The Worker proxy rewrote POSTs as JSON but did not require the browser Origin, allowing cross-site
challenge-cap consumption. The Worker now requires its exact origin for bridge writes, strips
browser cookies/authorization/origin before forwarding, removes the inactive production `/prove`
route, and adds no-referrer/nosniff headers. Full Worker regression coverage is green.

### Low

#### L-01 — CSP and Permissions-Policy remain absent — open

No CSP was added because the Lab is embedded in Web Tari Universe, uses inline styles, and the
Telegram page contacts configured cross-origin endpoints. A rushed policy could break wallet or
claim behavior. Create a report-only policy in staging, include Cloudflare challenge assets if Bot
Fight Mode is ever enabled, observe violations, then enforce the smallest compatible policy.

#### L-02 — Edge health discloses configuration booleans — open

`/_edge/health` reveals whether coordinator/verifier dependencies are configured. It does not reveal
credentials, but it assists reconnaissance. Restrict it to operator monitoring or return only a
generic liveness status.

### Informational

- The credential verifier checks resource address from the UTXO address, current unspent lookup,
  verified chain data, minimum-value promise at or above the configured threshold, key-spendable
  output, and a Schnorr signature against the on-chain authorization key. The signed message binds
  network, resource, substate, and the server challenge. The page-supplied public key is ignored.
- Challenge validation binds gate, nonce, expiry, policy hash, origin, and session commitment; the
  durable replay store reserves/consumes accepted attempts and failures/outages deny or remain
  pending rather than authorize.
- The active reader is operator-trusted testnet evidence. This audit does not convert it into an
  independently authenticated production proof.
- Credential mode reveals a public output identifier and its committed lower bound. This report
  makes no claim that the proof hides that linkage.
- Bot Fight Mode is not a required remediation. Cloudflare states it can challenge API/mobile
  traffic and cannot be skipped with WAF rules. Defer it until wallet, claim, Telegram, and monitor
  clients pass staging tests. AI Labyrinth is not relevant to these trust boundaries.

## Remediation commits

| Commit | Change |
|---|---|
| `814880c` | Claim request boundary and Tunnel allowlist |
| `609b081` | Enforce loopback administrator binding |
| `9f1562c` | Protect sensitive VPS backups |
| `47b1dca` | Restrict Worker bridge writes and add response headers |
| `a4d5bd8` | Move access-session bearer out of URLs and bind application/gate check |
| `587b0fb` | Correct overstated Telegram admission guarantees |

No live settings, services, credentials, Telegram permissions, or production data were changed.
Pre-existing untracked user files were preserved and excluded from commits.

## Test results after remediation

| Suite | Result |
|---|---:|
| Cloudflare Worker full suite | 54 passed, 0 failed, 1 intentional integration skip |
| Telegram full suite after claim hardening | 25 passed, 0 failed |
| Telegram access-token wire regression | 1 passed |
| Bridge access-check regression | 1 passed (174 filtered) |
| Admin bind regression | 1 passed |
| Tunnel/backup deployment contracts | 2 passed |
| Browser provider baseline | 31 passed |
| `git diff --check` at each checkpoint | passed |

The intentionally skipped Worker+SQLite+real-Rust integration means the combined deployed Worker,
Durable Object, Tunnel, and Rust verifier path was not exercised by this audit.

## Exact Cloudflare changes requiring approval

### 1. Capture rollback state first

Export/record:

- All DNS records, including unproxied/wildcard records and CNAME targets.
- Worker custom domains/routes, current deployment/version ID, bindings, and Durable Object
  namespace.
- Tunnel ID, connector replicas, live ingress rules, and service URLs.
- WAF custom/managed/rate-limit rules and account-member/API-token permissions.
- Current SSL/TLS settings and certificate inventory.

Do not proceed if an unknown hostname or traditional origin remains.

### 2. Deploy and validate the narrow Tunnel configuration

Use `deploy/cloudflared-config.yml.template` as the reviewed allowlist. Before activation:

```bash
cloudflared tunnel ingress validate
cloudflared tunnel ingress rule https://bridge.ghostgate.boo/gate/Crypt
cloudflared tunnel ingress rule https://bridge.ghostgate.boo/proof/example/status
cloudflared tunnel ingress rule https://bridge.ghostgate.boo/access/check
cloudflared tunnel ingress rule https://claim.ghostgate.boo/claim
cloudflared tunnel ingress rule https://claim.ghostgate.boo/anything-else
```

Expected: the first two route to bridge loopback, `/access/check` and the final claim URL hit the
404 catch-all, and exact `/claim` routes to claim loopback with Host `127.0.0.1`. Prefer a second
cloudflared replica for the new configuration, verify it healthy, then retire the old replica.

### 3. Edge TLS phase one

In **SSL/TLS → Edge Certificates**:

1. Turn **Always Use HTTPS** on.
2. Set **Minimum TLS Version** to **TLS 1.2**.
3. Leave TLS 1.3 on.
4. Keep Browser Integrity Check and Security Level Medium unless compatibility evidence says
   otherwise.

Acceptance: every known hostname redirects HTTP to the same HTTPS URL; TLS 1.0/1.1 handshakes fail;
TLS 1.2/1.3 work; wallet and Telegram flows pass.

### 4. Full (strict) gate

Do not change Full yet. First classify every proxied hostname as Worker, Tunnel, or traditional
origin. For each traditional HTTPS origin, test from the Cloudflare-facing network:

```bash
openssl s_client -connect ORIGIN_IP:443 -servername HOSTNAME \
  -verify_hostname HOSTNAME -verify_return_error </dev/null
```

Require an unexpired public/Cloudflare Origin CA chain, matching SAN, and `Verify return code: 0`.
For HTTPS Tunnel service URLs, keep `noTLSVerify: false` and set `originServerName` correctly. For
the current HTTP loopback Tunnel services, zone mode does not add local TLS. After the full zone
inventory is green, change **SSL/TLS → Overview → Full (strict)** and watch 526/origin errors.

### 5. HSTS phase two

After at least seven stable days with forced HTTPS and after checking every subdomain:

- Enable HSTS with the shortest dashboard max-age, currently **1 month**.
- `includeSubDomains`: **off**.
- `preload`: **off**.
- Keep HTTPS permanently enabled.

Increase max-age only after another stable observation window. Do not enable includeSubDomains or
preload until all current and future subdomains are HTTPS-only and an explicit long-term decision is
recorded.

### 6. WAF and rate limiting

First inventory the five Free-plan custom-rule slots and the one Free-plan rate-limit slot.
Recommended custom block rules:

```text
(http.host eq "claim.ghostgate.boo" and
 (http.request.uri.path ne "/claim" or
  not http.request.method in {"POST" "OPTIONS"}))
```

```text
(http.host eq "bridge.ghostgate.boo" and
 (http.request.uri.path in {"/health" "/wallet/status" "/lab/gates" "/access/check"} or
  starts_with(http.request.uri.path, "/admin") or
  starts_with(http.request.uri.path, "/wallet/")))
```

```text
(http.host eq "ghostgate.boo" and starts_with(http.request.uri.path, "/admin"))
```

Use **Block**, not a browser challenge, on service-only deny rules. Enable the Cloudflare Free
Managed Ruleset if it is not already enabled, then review sampled Security Events for false
positives.

For the single Free-plan rate-limit rule, start with a conservative path-only expression:

```text
http.request.uri.path in {"/claim" "/gate/Crypt/challenge" "/gate/Crypt/credential"}
```

Suggested initial value: 20 requests per 10 seconds per IP, Block for 10 seconds. Observe shared-NAT
and wallet behavior in staging before production. The Free plan cannot count separately by path or
method, so this is defense in depth, not an exact application quota.

### 7. Bot Fight Mode

Leave off during this remediation. Cloudflare documents that Bot Fight Mode applies domain-wide,
may challenge API/mobile traffic, and cannot be skipped by WAF custom rules. Consider it only after
an isolated compatibility run; it is not a substitute for the route allowlist or application
authorization.

## Deployment procedure

1. Stage these commits on an isolated Worker/Tunnel/VPS and a separate Telegram test supergroup.
2. Create a root-only, timestamped backup of registry, bindings, sessions, generations, audit, replay,
   halt state, installed configs, and binary hashes. Do not print or copy secrets into the change
   record.
3. Build reviewed binaries with locked dependencies and bounded jobs:

   ```bash
   CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/var/tmp/ghost-gate-target \
     cargo build --locked --release -j 2 \
       -p ghost-gate-walletd -p ghost-gate-telegram -p ghost-gate-admin
   ```

4. Preserve current binaries under a root-only release directory, atomically install the new
   root-owned 0755 binaries, and restart one service at a time: admin, bridge, Telegram. Confirm
   listeners remain only `127.0.0.1:7811`, `127.0.0.1:7799`, and `127.0.0.1:7808`.
5. Validate and deploy the Tunnel allowlist. Confirm denied routes from both the VPS and public edge.
6. Record the current Worker deployment ID:

   ```powershell
   npx wrangler deployments list --config wrangler.ghostgate.toml --json
   ```

7. Deploy the Worker only after staging acceptance. Do not replace the Durable Object namespace or
   secrets. Run low-volume acceptance for sufficient/insufficient wallets, malformed proof, replay,
   wrong gate/origin/session, outage, and stale proof.
8. Do not enable production Telegram admission until H-01 and H-02 are fixed. In a test group,
   verify exact account/chat approval, forwarded link rejection, restart, revocation, expiry,
   manual-add detection, and alternate-admin behavior.
9. Apply Cloudflare TLS/WAF phases separately so each change has an attributable rollback.

## Rollback

- **Incident first:** stop issuing proofs and latch the bridge halt when authorization safety is in
  doubt. Disable the affected Tunnel route if exposure is possible. Preserve logs and replay data.
- **Worker:** use the recorded version ID:

  ```powershell
  npx wrangler rollback VERSION_ID --config wrangler.ghostgate.toml `
    --message "security audit rollback"
  ```

  Worker rollback does not roll back Durable Object storage. Never create a replacement namespace
  to hide a replay/state failure.
- **VPS:** restore only the previous reviewed binaries and configuration, then restart sequentially.
  Do not restore older registry, bindings, session, generation, audit, replay, or halt state.
- **Tunnel:** restore the previous config only after halting authorization; a rollback to the known
  broad live routing reopens M-03, so prefer a corrected narrow config. Validate before restart.
- **Cloudflare TLS:** Always Use HTTPS and TLS 1.2 should normally remain. If Full (strict) causes
  526 after a verified change, restore the previous mode while fixing the exact origin certificate.
  HSTS cannot be instantly undone for browsers that cached it; this is why the first max-age is one
  month and includeSubDomains/preload stay off.

## Independent penetration testing still required

- Cloudflare account/DNS/Tunnel/WAF/IAM review with read-only exports.
- VPS host/firewall/package/service hardening and direct-origin discovery from authorized vantage
  points.
- Live wallet tests at 99.999999, 100, and above 100 tTARI; spent output; stale/unverified indexer;
  wrong network/resource/gate/policy/origin/session; replay/concurrency; dependency outage.
- Cryptographic review of the credential message construction, chain proof provenance, and
  operator-trusted indexer assumption.
- Browser embedding, CSP report-only, clickjacking, extension/provider substitution, and error/log
  leakage review.
- Telegram proof-to-account commitment, durable reconciliation, restart/missed updates, all admin
  roles, legacy links, manual adds, bans/unbans, and race conditions.
- Backup restore drill and incident-response exercise that preserves monotonic generation/replay
  evidence.

## Final assurance statement

Locally verified: the patched request boundaries, access-token transport, admin bind restriction,
backup permissions, Worker origin/route controls, and existing unit-level credential/replay checks.

Observed but not changed: the public HTTP/TLS/HSTS configuration and live Tunnel route drift.

Not verified: production Cloudflare account state, VPS hardening, live sufficient/insufficient wallet
outcomes, live Telegram exclusivity, independent chain-proof provenance, or resistance to an
independent penetration test.

Ghost Gate must not be described as unhackable or production Telegram-enforced on this evidence.

## Primary external references

- [Cloudflare Always Use HTTPS](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/)
- [Cloudflare Minimum TLS Version](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/)
- [Cloudflare Full (strict)](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/)
- [Cloudflare Tunnel HTTPS origins](https://developers.cloudflare.com/tunnel/troubleshooting/https-origins/)
- [Cloudflare HSTS](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/)
- [Cloudflare custom rules](https://developers.cloudflare.com/waf/custom-rules/)
- [Cloudflare rate limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [Cloudflare Bot Fight Mode limitations](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/)
- [Cloudflare Worker rollback](https://developers.cloudflare.com/workers/wrangler/commands/workers/)
