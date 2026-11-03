# Esmeralda live readiness — Ootle 0.49.1 servers with v0.49.2 Ghost Gate source

Date: 2026-11-03
Branch: `upgrade/ootle-live-0.49.1`
Preserved future checkpoint: `future/ootle-0.49.2` at
`821daa6e54526481707251f8e26a663b0bbb98ee`

## Current result

The public network gate now passes. A read-only run of
`scripts/check-esmeralda-live-readiness.ps1` observed both official indexers at epoch 12831. Both
reported Ootle `0.49.1`, Esmeralda byte 38, ready status, and verified proof-bearing native tTARI
and built-in faucet substates. The indexers agreed on every hard network gate.

Overall live bootstrap remains **blocked**. In addition to the two browser-wallet flows, the
operator must read the protected registry and generation ledger, match the deployed genesis value
to authoritative provenance, select the next monotonic generation, and build/attest the patched
walletd runtime. No transaction or deployment should be attempted merely because the network
monitor passes.

## Evidence-based version rule

Expected live server version: **0.49.1**.

Tested Ghost Gate client/source version: **0.49.2**.

Compatibility justification: the exact upstream v0.49.1-to-v0.49.2 diff changes only release
metadata, lockfile workspace versions, and the `tari_logging` metrics feature spelling needed to
build release binaries. It changes no protocol, engine, transaction, wallet, walletd, indexer,
CBOR, template, resource-proof, stealth, authorization, or WebAuthn implementation. See
`docs/OOTLE_0491_LIVE_COMPATIBILITY.md`.

This is an exact compatibility rule, not a wildcard or ignored mismatch. Any server version other
than `0.49.1` makes the current monitor fail until it receives a new source review.

## Repeatable network gate

Run from the repository root:

```powershell
.\scripts\check-esmeralda-live-readiness.ps1
```

The script performs GET requests only, requires no secret, and submits no transaction. It checks:

- official indexers A and B `/info`, `/network`, and `/wait-until-ready`;
- exact Esmeralda network name and byte 38;
- identical epoch/network/version observations from both indexers;
- exact compatible live version `0.49.1`;
- proof-bearing `verified: true` state for native tTARI and the built-in faucet; and
- any genesis/sidechain field exposed by `/info`, `/network`, or the public checkpoint route as a
  diagnostic.

It exits zero only when the hard network gates pass. The observed 2026-11-03 summary was:

```text
A: network=esmeralda/38 epoch=12831 version=0.49.1 native=PASS faucet=PASS identity=none
B: network=esmeralda/38 epoch=12831 version=0.49.1 native=PASS faucet=PASS identity=none
agreement=PASS expected-network=PASS compatible-live-version=PASS required-state=PASS api-identity-diagnostic=NOT_EXPOSED
LIVE NETWORK GATE: PASS
```

## Identity boundary

Two different identity concepts must not be conflated.

### Security-required

`Application.genesis_hash` / `GG_GENESIS_HASH` is mandatory Ghost Gate policy state. It is validated
as hex, included in the v1/v2 canonical policy digest, copied into registry snapshots, and required
by `binding_from_snapshot`. The bridge fails closed on an empty value. The operator must recover
the existing value from the protected registry/configuration and verify its documented provenance,
or obtain an authoritative replacement before publishing the reset generation. Do not substitute
an Ootle tag commit, epoch/root hash, random value, or an unreviewed native-resource hash.

The reset must also advance the registry's positive, monotonic `chain_generation`; it is the
explicit security dimension that distinguishes L2 resets when the network byte, L1 genesis, and
native resource address remain unchanged.

### Diagnostic only for the current credential path

The optional indexer `/info.sidechain_id` and a public checkpoint/genesis field are not consumed by
the credential reader. The reader requires the configured official indexer, a verified response,
base64-CBOR `SubstateValue::Utxo`, correct resource/output, and current gate/session/challenge
bindings. `ExpectedIdentity.sidechain_id` is optional, and an absent observed value is
`Inconclusive`; the reset guard uses reports only in the safe direction to latch a halt.

Therefore absence of an API-exposed `sidechain_id` is recorded as `NOT_EXPOSED` but no longer
causes the network monitor to fail. This does not remove or weaken the registry genesis and chain
generation boundaries above.

## Stage 3A.4 identity attestation

### What the registry field means

`Application.genesis_hash` is intended to be the **Minotari/L1 Esmeralda height-zero block-header
hash**. This is not an Ootle tag commit, epoch checkpoint, native resource hash, or L2 reset ID.
The interpretation is source-backed: the optional native base-node adapter reads block height zero
and assigns its header hash to `Ggbp1ChainSnapshot.genesis_hash`. Ootle resets are distinguished
separately by `Application.chain_generation`.

The exact pinned Minotari dependency (`tari_core 6.3.0-pre.2`, Cargo checksum
`d688f591135bf19f5b4fffbd662c66f2a31fff57f1cf49b76e15206db0d49cf3`) asserts this Esmeralda
genesis hash in `esmeralda_genesis_sanity_check`:

```text
3c3681ad318eb54ca3f3e8aed79d3d207d94a5291aec84ba1a0b628633db3621
```

The exact upstream Ootle v0.49.1 tag commit
`b94de26c3ec463b17926a92f2189507a195ac00c` locks that same `tari_core` version and checksum, and
its Esmeralda epoch-oracle preset points to `https://grpc.esmeralda.tari.com` with start/birthday
height 669506. This ties the candidate to the chosen live release configuration; it still does not
reveal what Ghost Gate's protected registry currently stores.

This establishes an authoritative **source candidate**. It does not establish that the protected
deployment currently contains the same value. The live v0.49.1 `/info`, `/network`, and checkpoint
responses expose no usable genesis/sidechain identity (`sidechain_id` is null), and the checkout
contains no protected registry snapshot. There is also no configured SSH host/alias or concrete VPS
target in this environment, so a read-only remote comparison could not be made without inventing a
target.

Classification:

| Item | Classification | Reason |
|---|---|---|
| Official Minotari Esmeralda L1 genesis source candidate above | **VERIFIED** | Pinned `tari_core` source asserts the exact height-zero header hash |
| Current live Ootle API identity | **NOT VERIFIED / NOT EXPOSED** | Official indexers report Esmeralda/38 and `sidechain_id: null`, not the L1 genesis |
| Genesis value in the deployed Ghost Gate protected registry | **NOT VERIFIED** | No protected state or authorized VPS target exists in this checkout/session |

The Rust field `Application.genesis_hash` persists as `applications[].genesisHash` in
`/opt/ghost-gate/data/registry/registry.json` (deployment path derived from the tracked service
configuration). `StorePaths` also derives `bindings.json` in that directory. Policy publication
copies the value into each frozen `PolicyVersion` and `GateBindingSnapshot`; both v1 and v2 policy
canonical forms hash it. The bridge rejects an empty binding. If the deployed value differs from
the authoritative value, it is **STALE or incorrectly sourced** and the next policy hash must be
recomputed after correction. Do not preserve the old public policy hash by choosing a convenient
genesis value.

Before any activation, an operator with private VPS access must make a read-only, field-limited
inventory of `registry.json` and compare the Crypt application's value byte-for-byte to the hash
above. Do not copy the whole registry into a tracked file: it contains administrative state.

No SSH configuration, concrete VPS hostname, or authorized remote target is available in this
environment. Use the following read-only commands from an operator terminal after replacing only
`VPS_USER` and `VPS_HOST`. They require an already-installed `jq`; if that prerequisite check fails,
stop rather than installing software or falling back to printing either complete protected file.

```bash
ssh VPS_USER@VPS_HOST 'command -v jq >/dev/null || { echo "BLOCKED: jq is not installed" >&2; exit 127; }'

ssh VPS_USER@VPS_HOST 'set -eu
registry=/opt/ghost-gate/data/registry/registry.json
ledger=/opt/ghost-gate/data/registry/generations.ndjson
expected=3c3681ad318eb54ca3f3e8aed79d3d207d94a5291aec84ba1a0b628633db3621
sudo test -r "$registry"
if sudo test -e "$ledger"; then
  ledger_input="$ledger"
  ledger_present=true
else
  ledger_input=/dev/null
  ledger_present=false
fi
sudo jq -n -e \
  --slurpfile registry "$registry" \
  --slurpfile ledger "$ledger_input" \
  --argjson ledgerPresent "$ledger_present" \
  --arg expected "$expected" '\''
  ($registry | if length == 1 then .[0] else error("registry must contain one JSON document") end) as $r
  | if (($r.applications | type) != "array") then error("registry applications must be an array") else . end
  | if all($r.applications[];
      (.chainGeneration | type) == "number"
      and .chainGeneration >= 0
      and .chainGeneration == (.chainGeneration | floor))
    then . else error("invalid registry chainGeneration") end
  | if all($ledger[];
      (.application_id | type) == "string"
      and (.generation | type) == "number"
      and .generation > 0
      and .generation == (.generation | floor))
    then . else error("invalid generation ledger record") end
  | {
      registrySchemaVersion: ($r.schemaVersion // null),
      storeRevision: ($r.store_revision // 0),
      generationLedgerPresent: $ledgerPresent,
      applications: [
        $r.applications[] as $app
        | ([
            $ledger[]
            | select(.application_id == $app.applicationId)
            | .generation
          ] | if length == 0 then 0 else max end) as $durableFloor
        | {
            applicationId: $app.applicationId,
            gateIds: [$app.gates[].gateId],
            genesisHash: $app.genesisHash,
            genesisComparison: (
              if $app.genesisHash == $expected
              then "MATCHES CURRENT RESET"
              else "UNKNOWN/INVALID"
              end
            ),
            registryGeneration: $app.chainGeneration,
            durableFloor: $durableFloor,
            selectedNewGeneration: ([
              $app.chainGeneration,
              $durableFloor
            ] | max) + 1
          }
      ],
      publishedVersions: [
        $r.versions[] | {applicationId, gateId, version, policyHashVersion}
      ]
    }
  '\'''
```

The registry has no explicit schema-version field in the current Rust type; a null
`registrySchemaVersion` is therefore expected. `storeRevision` is an optimistic-concurrency
revision, not a schema version. Application and gate fields are persisted in camelCase, while the
append-only `GenerationActivation` ledger uses `application_id` and `generation`. The command
validates integer generation fields, makes malformed JSON/NDJSON fail, compares every application
to the authoritative genesis candidate, and computes the monotonic next generation without writing
either file. An absent ledger is correctly reported and treated as floor zero. Record only the
field-limited output in operator evidence; do not redirect the protected source files.

The current authenticated `app.migrate-generation` operation does **not** replace the genesis
binding: it changes only `chainGeneration`. The ordinary application-update handler also exposes no
`genesisHash` field, and a direct file edit would invalidate the frozen policy-version checks rather
than constitute a sanctioned migration. Therefore a `MATCHES CURRENT RESET` result may proceed to
the reviewed generation migration, but an `UNKNOWN/INVALID` mismatch is an additional Stage 3B
blocker requiring a separately reviewed genesis-rebind/application-replacement operation. Do not
claim that the existing generation endpoint can repair it.

### Chain generation high-water mark

The previous generation cannot be recovered from the public Lab/health APIs and is absent from this
checkout. It must be read from two protected sources:

1. the Crypt application's `applications[].chainGeneration` in `registry.json`; and
2. the maximum `generation` for the same `application_id` in the append-only
   `generations.ndjson` ledger.

Select exactly:

```text
next_generation = max(registry_declared_generation, durable_generation_floor) + 1
```

Neither the public policy version (`v3`) nor the current policy hash is evidence of a generation.
Until both protected inputs are known, the previous and next values remain `null` in
`deploy/esmeralda-live-bootstrap.json` and bootstrap is blocked.

Before activation, record the selected value in the reviewed predeployment manifest. During the
authorized Stage 3B mutation, use only the admin plane's fresh-authenticated
`app.migrate-generation` operation. That operation first appends/fsyncs `generations.ndjson`, then
updates `registry.json`, increments the application revision, retires sessions, and appends audit
state. It intentionally does not rebuild `bindings.json`: a reviewed policy publication must follow
so the derived binding carries the new generation. The bridge must then reload that binding; old
challenges, replay records, and sessions remain non-authorizing. `GG_CHAIN_GENERATION` is only a
default for creating an application and must not be used to bypass migration for an existing one.

### Minimum-value-promise wallet attestation

Source provenance is verified:

- base: official Ootle v0.49.2 commit `aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90`;
- patch: `docs/wallet-mvp-0492.patch`, SHA-256
  `b627a3d95766968cce30b8cd6dc541adb5d76a759ea22d7932338abfbd63e168`;
- scope: exactly five wallet SDK/walletd files named in the patch; and
- attestation: all 3,645 other tracked files in `_ootle-v0492-ghost-gate` are byte-identical to the
  exact-tag reference, no tracked file is missing, the patch applies to the clean reference with
  `git apply --recount -p1`, and the reverse patch applies to all five edited files.

No `tari_ootle_walletd` executable exists in either reviewed source tree's debug or release target.
The only walletd executables found in the reviewed local download locations identify as 0.42.0,
0.45.0, or 0.47.0; none can contain this patch. Therefore **no current runtime binary is attested**.

Build a fresh binary from the attested patched tree; do not reuse an old download:

```powershell
$patchedOotle = (Resolve-Path ..\_ootle-v0492-ghost-gate).Path
$env:CARGO_BUILD_JOBS = "2"
cargo test --manifest-path "$patchedOotle\Cargo.toml" --locked -p tari_ootle_wallet_sdk minimum_value_promise
cargo build --manifest-path "$patchedOotle\Cargo.toml" --locked --release --package tari_ootle_walletd --bin tari_ootle_walletd
& "$patchedOotle\target\release\tari_ootle_walletd.exe" --version
Get-FileHash -Algorithm SHA256 "$patchedOotle\target\release\tari_ootle_walletd.exe"
```

Record the exact `rustc --version --verbose`, `cargo --version --verbose`, binary version, binary
SHA-256, build source commit, and patch SHA-256 in a nonsecret operator record and then in the
predeployment manifest. The currently observed toolchain is Rust/Cargo 1.97.1 on
`x86_64-pc-windows-msvc`; it is not a promise that a future build used that toolchain. A build is
acceptable only if the three filtered minimum-value-promise tests pass first and the resulting
binary reports the expected v0.49.2 cohort.

For a reproducible Linux artifact, the manually triggered workflow
`.github/workflows/walletd-mvp-attested-build.yml` reconstructs the source from the official base
commit, verifies the patch SHA-256, requires exactly the reviewed five-file modification set, reruns
the three MVP tests, builds release walletd and its web assets on Ubuntu 24.04 with Rust 1.97.1,
Node 24.15.0, and pnpm 12.4.2, verifies the binary SHA-256, and uploads separate binary and
attestation artifacts. It has read-only repository
permission and no production secrets or deployment step. Preparing the workflow is not an
attestation: `binarySha256` and the workflow-run fields remain null until an operator pushes the
workflow, dispatches it, and independently checks the successful run artifacts.

A local Windows release build was not started in Stage 3A.5: the observed host had Node 24.14.0,
pnpm 11.6.0, and 16.36 GiB free, while the exact upstream source declares Node 24.15.0 and pnpm
12.4.2. Reusing that environment would weaken the web-asset/build provenance and risk exhausting
the shared disk. The filtered Rust tests were rerun and passed; the release artifact remains a CI
action, not a locally attested binary.

## Browser-wallet acceptance against live 0.49.1

Use an isolated test wallet/profile. Never record a seed, private key, setup token, cookie, API
token, full challenge, or signature bytes. Stop if an ostensibly basic connection test presents a
transaction, fee, transfer, faucet claim, or output-creation approval.

### Sapient

1. Record the Sapient build/provider version and select Ootle Esmeralda.
2. Open `https://ghostgate.boo/` in a top-level HTTPS tab and select Crypt/Sapient.
3. Connect through `tari_requestAccounts`; approve only the site connection.
4. Require the provider network to resolve to Esmeralda byte 38 and capabilities to load after
   approval. A pre-approval 4100 is acceptable; a post-approval 4100 is not.
5. Request only the basic `tari_signWalletOwnershipChallenge` diagnostic. Require a site-scoped
   approval UI and a successful response.
6. Stop before Prove access or any transaction request. Record exact method/shape errors and confirm
   no v0.47/v0.48 provider assumption appears.

Required record: wallet version, network, provider discovery, site connection, capabilities,
signature approval UI, signature response, obsolete-API check, and overall PASS/FAIL.

### Web Tari Universe

1. Record the actual Universe and connector/provider versions; a plain browser tab is not a test.
2. Select Ootle Esmeralda and load Ghost Gate inside Universe's supported embedded dApp frame.
3. Require the embedded Tari provider (`isEmbedded === true`), successful connection/capability
   handshake, and network byte 38.
4. Request only the basic wallet-ownership signature and require a site-scoped approval plus a
   successful response.
5. Confirm the Telegram/external-link control opens outside the iframe without joining a chat or
   sending a message, then confirm the embedded dApp remains intact.
6. Stop before Prove access or credential creation. Record exact provider, iframe, CSP, navigation,
   or response-shape errors.

Required record: app/provider version, network, embedded page/provider, handshake, signature UI,
signature response, external-link behavior, obsolete-API check, and overall PASS/FAIL.

## Live bootstrap gates

| Gate | Current result | Stop condition |
|---|---|---|
| Both official indexers reachable and ready | PASS | Either endpoint fails |
| Both agree on Esmeralda byte 38 and current epoch | PASS at epoch 12831 | Any disagreement |
| Both report reviewed compatible server version 0.49.1 | PASS | Any other version before review |
| Verified native tTARI and faucet state | PASS | Missing, unverified, or proofless state |
| Registry genesis provenance | **BLOCKED / NOT VERIFIED** | Protected value has not been compared with the verified source candidate |
| Positive next chain generation and migration plan | **BLOCKED / values unknown** | `registry.json` and `generations.ndjson` high-water mark not inventoried |
| Patched walletd runtime provenance | **BLOCKED / workflow prepared, not run** | No successful artifact run or binary SHA-256 yet |
| Sapient basic provider/signing | **UNKNOWN** | Anything other than recorded PASS |
| Web Tari Universe provider/signing/navigation | **UNKNOWN** | Anything other than recorded PASS |
| Deployment authorization | Not granted | Any attempt in this stage |

The missing public `sidechain_id` is a diagnostic and is not a separate stop condition. The
security-required registry genesis value, generation inventory, and wallet binary remain stop
conditions until their evidence is recorded. The remaining work is therefore **not limited to the
two manual browser checks**.

## What changed and what did not

Changed on the live branch:

- renamed and retargeted the read-only readiness monitor to the exact live v0.49.1 server cohort;
- replaced the version-string-only rejection with the reviewed compatibility rule;
- made API-exposed sidechain/genesis identity diagnostic while preserving registry identity
  requirements;
- added the exact comparison and live operator readiness documents; and
- added `deploy/esmeralda-live-bootstrap.json` as a nonsecret, deliberately blocked
  predeployment evidence record. It is not an executable deployment manifest.

Not changed: Rust source, Cargo manifests/lockfiles, template source, authorization behavior,
transaction construction, executable deployment tooling, Cloudflare, VPS, production
configuration, chain addresses, or GitHub Actions. Because no dependency or Rust source changed,
the existing Linux engine validation remains applicable to the identical code commit; no new Linux
workflow path was needed for this documentation/tooling retarget.

## Local validation

The live branch was validated after the retarget. All commands completed successfully:

| Command | Result |
|---|---|
| `cargo check --workspace --locked` | PASS |
| `cargo test --workspace --exclude ghost-gate-tests --locked` | PASS; 397 passed, 5 intentional live-indexer/localnet skips, 0 failed |
| documented nightly `rustfmt --check` over migration-touched Ghost Gate-owned sources | PASS |
| `cargo check --target wasm32-unknown-unknown --locked` in each of the three template workspaces | PASS / PASS / PASS |
| wallet SDK `minimum_value_promise` filtered tests against the patched cohort | PASS; 3 passed, 0 failed |
| live readiness monitor against both official indexers | PASS |
| Stage 3A.4 predeployment JSON parse/null stop-condition assertions | PASS |
| `cargo test --locked -p ghost-gate-registry generation` | PASS; 7 passed, 0 failed |
| Stage 3A.4 rerun of wallet SDK `minimum_value_promise` filtered tests | PASS; 3 passed, 0 failed |
| Stage 3A.5 exact base/patch hash/clean-apply/five-file-set checks | PASS |
| Stage 3A.5 wallet SDK `minimum_value_promise` filtered test rerun | PASS; 3 passed, 0 failed |
| `walletd-mvp-attested-build.yml` YAML parse, trigger, permission, command, and secret-context assertions | PASS; workflow prepared but not dispatched |

The existing GitHub Actions Linux engine run covers the same Rust/dependency tree. Stage 3A.5 adds
only documentation, predeployment manifest metadata, and a manual build-only workflow. The requested
Stage 3A.4 local checkpoint commit could not be created because this execution environment denied
write access to `.git/index.lock`; no commit or push occurred.

## Bootstrap decision

Network compatibility is ready. Live mutation remains blocked pending operator-controlled genesis
and generation inventory, patched wallet runtime provenance, and recorded PASS results for both
browser wallets. The machine-readable predeployment record is
`deploy/esmeralda-live-bootstrap.json`; every unresolved field is deliberately null rather than
guessed.

LIVE READINESS STATUS: BLOCKED
