# Running the Ghost Gate administrator dashboard

This is the operator's document. It assumes no Rust knowledge beyond "build once, then run", and
no cryptocurrency terminology beyond what the dashboard itself explains.

The dashboard is the **only** place gate policy lives. It replaced editing environment variables by
hand: thresholds, tiers, session lengths, test lanes, revocations and the list of gates an
application has are all decided here, recorded in an audit log, and served to visitors by the bridge.

---

## 1. What you get

* A web page at `http://localhost:7811/admin` listing every application and its gates.
* First run: paste a one-time bootstrap token to register your administrator credential.
* After that: sign in with a **passkey** (fingerprint, face, Windows Hello, security key) or with a
  **wallet key** (your Tari/Minotari spend key, verified with the same Ristretto machinery the
  gate credential flow uses).
* Every change requires a *fresh* approval: a passkey ceremony or a wallet signature taken within
  the last few minutes. A stolen cookie alone cannot change policy.

## 2. Build and start

```bash
cargo build -p ghost-gate-admin --bin ghost-gate-admin
GG_ADMIN_DATA=~/ghost-gate-admin \
GG_GENESIS_HASH=<your chain's genesis hash> \
GG_ADMIN_HOSTNAME=localhost \
  ghost-gate-admin
```

On first start it prints a **bootstrap token**. Copy it. It is also written to
`<GG_ADMIN_DATA>/bootstrap.token` and becomes void the moment one administrator exists.

| Variable | Meaning | Default |
| --- | --- | --- |
| `GG_ADMIN_BIND` | loopback address and port to listen on | `127.0.0.1:7811` |
| `GG_ADMIN_HOSTNAME` | the hostname you will open in the browser | the bind host |
| `GG_ADMIN_DATA` | where the registry, bindings, sessions and audit log live | `gg-admin-data` |
| `GG_GENESIS_HASH` | the ledger's genesis identity, hex — applied to applications that do not name their own | none |

### Why `GG_ADMIN_HOSTNAME` exists

Passkeys require a **domain** as the relying party. A browser refuses a passkey ceremony on an IP
address with `SecurityError: This is an invalid domain`. So bind to `127.0.0.1` (the admin plane is
never exposed to a network) and *open* the page through `localhost`, or through your own domain if
you put a reverse proxy in front. The dashboard detects an IP address, disables the passkey buttons
and tells you what to do instead of showing you a cryptic browser error.

## 3. First run, step by step

1. Open `http://localhost:7811/admin`.
2. Paste the bootstrap token into the box and press **Register a passkey**.
3. Approve the prompt (Windows Hello, Touch ID, your security key…).
4. You are signed in. The page shows **no applications yet**.

### If you prefer a wallet key

Press **Register a wallet key** instead. The page gives you a challenge; sign it with your wallet's
spend key and paste the public key, nonce and signature. A helper that does this locally lives in the
repository:

```bash
cargo run -p ghost-gate-admin --example wallet_sign -- --generate          # mint a key
cargo run -p ghost-gate-admin --example wallet_sign -- <secret_hex> <challenge>
```

A wallet key registered this way is a **deployment administrator**: it can add and revoke other
credentials, but it cannot move funds.

## 4. Creating your first application

Press **New application** and fill in:

| Field | What it means |
| --- | --- |
| Application id | stable, lowercase identifier (`meme-coin`); never reused |
| Display name | what operators see |
| Topology | **hierarchical** (a higher gate can open lower ones) or **independent** (no tiers) |
| Default session | how long a verified visitor stays unlocked when a gate does not override it |
| Production | a production application may never enable a test-lane gate |

**Network** defaults to the deployment's `GG_GENESIS_HASH`; set it per application only if you serve
more than one ledger. The cohort byte and the genesis hash are part of every policy digest, and the
bridge refuses to bind a gate from a ledger other than the one it is configured to serve.

## 5. Adding gates — two steps, on purpose

### Step 1: add the gates

Fill in the gate form and press **Add gate**:

* **Gate id** — stable and unique (`gold`).
* **Resource address** — the `resource_…` address the threshold is denominated in.
* **Component address** — the deployed `component_…` gate. An enabled gate must have one.
* **Divisibility + human amount** — you type `1000000`, the **server** computes the raw units and
  refuses anything it cannot represent exactly. It is never rounded, and the browser's arithmetic is
  never trusted.
* **Proof mode** — *Consensus* (wallet daemon, the real thing) or *Credential* (browser wallet
  provider). *Native L1 XTM* exists as a draft only and cannot be activated yet.
* **Test lane** — for a rehearsal gate. A test-lane session can never authorise a production gate.

### Step 2: wire the tiers

A grant may only name a gate that already exists, so the dashboard refuses a gold gate that opens a
silver gate you have not created yet. This is deliberate: the hierarchy is always explicit.

Once the gates exist, each one gets a **Tiers** row with a checkbox per other gate. Tick
`gold → silver` and the change saves immediately. Each save is a full, audited policy write.

### Step 3: publish

**Add gate** saves a *draft*. A draft is invisible to visitors. **Publish** freezes a version: that is
what the bridge serves, what sessions are checked against, and what appears in the audit log. The
bridge picks up a published change on its next request — no restart.

> Changing a threshold, resource or component after publishing is a **replacement**: a new version,
> it invalidates outstanding challenges and existing sessions for that gate, and it is recorded with
> its reason. That is the point: a threshold cannot move silently.

## 6. What visitors experience

1. The page asks the bridge for the gate.
2. The bridge mints a challenge **bound to the policy version in force at that moment**.
3. The visitor proves it (consensus or credential mode).
4. The bridge issues a **verified access session** and hands the token to the page.
5. Every door the visitor opens is checked **server-side** against the registry: expiry, revocation,
   policy hash, tier and test-lane rules are all decided by the bridge, never by the browser.
6. Reloading the page drops the token: a new proof is required. Long-lived sessions belong to the
   *site's* login, not to a visitor's browser.

`GET /access/check?application=<id>&gate=<id>&token=<token>` is the integration point for anything
else you build. It answers with the decision and the reason.

## 7. Sessions, revocation and the audit log

The **Sessions** panel lists every verified access session: which gate proved it, what it unlocked,
when it expires, and a **Revoke** button. Revocation is honoured on the bridge's next check — no
restart, no redeploy. `app:<id>:*` revokes everything for an application at once.

The **Audit** panel is append-only: every privileged action with its actor, the application and gate,
the versions before and after, and whether it was accepted or refused.

## 8. Running the bridge against the dashboard

The registry is the only gate authority. `GG_BRIDGE_GATES` is no longer required and is ignored:

```bash
GG_BRIDGE_BIND=127.0.0.1:7799 \
GG_BRIDGE_ORIGINS=http://127.0.0.1:7799 \
GG_BINDINGS_PATH=~/ghost-gate-admin \
GG_BRIDGE_NETWORK=localnet \
  ghost-gate-bridge
```

* `GG_BINDINGS_PATH` — the same directory the dashboard writes. The bridge re-reads it when it
  changes and keeps the last known good copy if the file is ever corrupt.
* `GG_BRIDGE_NETWORK` — optional, and a good idea: if the snapshot is for another cohort the bridge
  refuses to bind rather than serving a mainnet-shaped localnet gate.
* If no gate is published, the bridge serves no gates. That is the honest empty state, not a warning.

## 9. Checking it works

```bash
scripts/admin_live_demo.sh          # the whole control plane on one machine, ~40 assertions
scripts/browser_admin_check.sh      # the real page in headless Edge, incl. a virtual passkey
cargo test -p ghost-gate-admin      # the API, against a real HTTP server
```

The browser harness is the one that proves the parts you touch: that a passkey ceremony completes,
that gates and tier checkboxes render, that a tier wired by clicking survives a reload, and that a
gate named `<img onerror=…>` is shown to you as text and never executed.

## 10. Where the data lives

```
<GG_ADMIN_DATA>/
  registry.json     applications, gates, published versions, credentials, admin sessions
  bindings.json     what the bridge serves (derived; only published gates)
  sessions.json     verified access sessions (revocable)
  audit.ndjson      append-only audit history
  bootstrap.token   first-run token; void once an administrator exists
  store.lock        single-writer lock; a second writer is refused, never queued forever
```

Back this directory up. It is the authoritative record of who may pass which gate.

## 11. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `SecurityError: This is an invalid domain` | passkeys on an IP address | open the page through `GG_ADMIN_HOSTNAME=localhost` or a domain |
| "this change requires fresh authentication" | the step-up window expired | press **Step up** and approve again |
| "grants \"x\", which is not a gate in this application" | tiers wired before the gate exists | add every gate first, then wire tiers |
| "10 cannot be represented exactly at divisibility 6" | an amount smaller than one unit | raise the amount or lower the divisibility |
| Bridge serves no gate | nothing published yet | publish the gate in the dashboard |
| Bridge refuses to bind | `GG_BRIDGE_NETWORK` disagrees with the snapshot, or a corrupt file | check the bridge log; the last good snapshot is still in use |
| "the registry is locked by another process" | two writers at once | a refusal by design; retry — nothing was half-written |