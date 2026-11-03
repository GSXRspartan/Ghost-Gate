# Ootle 0.49.2 manual-push audit

Audit date: 2026-11-02 (America/Los_Angeles)

## Publication scope

This audit covers the local Ootle 0.49.2 migration, its bootstrap/validation documentation, and the
narrow wallet minimum-value-promise patch. It authorizes no deployment, template publication,
transaction, tag, release, pull request, Cloudflare change, VPS change, or remote Git operation.

`SAFE TO PUSH` in this document means safe to publish this validation checkpoint to its existing
upgrade branch without leaking the operator's identity or credentials. It does **not** change the
`RUST VALIDATION VERDICT: BLOCKED` result and does not mean safe to bootstrap or deploy.

## Git state and destination

- Branch: `upgrade/ootle-0.49.2`
- Pre-publication base HEAD: `279cc662db6bc914a24ac58cb797ae5df89e6262`
- Base subject: `ci: add Linux validation for Ootle 0.49.2`
- Remote: `origin`
- Fetch/push URL: `https://github.com/GSXRspartan/Ghost-Gate.git`
- Publication HEAD: the single local repair commit containing this refreshed audit, with subject
  `fix: complete Ootle 0.49.2 test migration`

The exact publication commit hash is reported by the post-commit `git show`/`git rev-parse HEAD`
handoff. A commit cannot embed its own content-derived hash without changing that hash; the stable
identifiers recorded here are its parent, branch, subject, remote, author, and committer.

## Commit identity

Repository-local identity is exactly:

```text
GSXRspartan <304655218+GSXRspartan@users.noreply.github.com>
```

The global `user.name` and `user.email` are unset and were not changed. The new commit must use the
same repository-local identity for both author and committer.

## Reachable-history identity audit

Before the repair commit, the complete history reachable through `--all` contained three commits.
All three reported the exact same public identity for author and committer:

```text
279cc662db6bc914a24ac58cb797ae5df89e6262
04d638b745f5e93382110c803a03f15712b34271
f960d1575c7175f98625d2ae0015a300980b0b68
AUTHOR/COMMITTER=GSXRspartan <304655218+GSXRspartan@users.noreply.github.com>
```

No personal email, alternate author, or unexpected committer was found. History was not rewritten.

## Files included

Dependency and lockfiles:

- `Cargo.toml`
- `Cargo.lock`
- `crates/ghost-gate-bridge/Cargo.toml`
- `crates/ghost-gate-core/Cargo.toml`
- `crates/ghost-gate-ggbp1-spike/Cargo.toml`
- `crates/ghost-gate-minotari/Cargo.toml`
- `crates/ghost-gate-tests/Cargo.toml`
- `crates/ghost-gate-walletd/Cargo.toml`
- `templates/ghost_gate/Cargo.toml`
- `templates/ghost_gate/Cargo.lock`
- `templates/ghost_gate_faucet/Cargo.toml`
- `templates/ghost_gate_faucet/Cargo.lock`
- `templates/ghost_gate_other_classes/Cargo.toml`
- `templates/ghost_gate_other_classes/Cargo.lock`

Migration source:

- `crates/ghost-gate-minotari/src/lib.rs`
- `crates/ghost-gate-minotari/src/wallet_service.rs`
- `crates/ghost-gate-wallet/src/lib.rs`
- `crates/ghost-gate-walletd/src/bin/ghost-gate-bridge.rs`
- `crates/ghost-gate-walletd/src/esmeralda.rs`
- `crates/ghost-gate-walletd/src/indexer.rs`
- `crates/ghost-gate-walletd/src/lib.rs`
- `templates/ghost_gate/src/lib.rs`
- `templates/ghost_gate_faucet/src/lib.rs`
- `templates/ghost_gate_other_classes/src/lib.rs`

Linux validation and engine-test migration:

- `.github/workflows/ootle-0492-validation.yml`
- `crates/ghost-gate-tests/tests/adversarial.rs`
- `crates/ghost-gate-tests/tests/cross_resource.rs`
- `crates/ghost-gate-tests/tests/gate_engine.rs`

Migration evidence and planning:

- `docs/OOTLE_0492_MIGRATION_AUDIT.md`
- `docs/OOTLE_0492_IMPLEMENTATION.md`
- `docs/OOTLE_0492_RUST_VALIDATION.md`
- `docs/ESMERALDA_0492_BOOTSTRAP_PLAN.md`
- `docs/wallet-mvp-0492.patch`
- `docs/PRE_PUSH_AUDIT_0492.md`

No generated `target/` tree, local log, local database, wallet state, editor state, ignored deployment
environment template, or temporary artifact is included.

## Sensitive-data and identity scan

The audit used Git-aware history/tracked-file searches, a separate full working-tree search including
untracked files, candidate-diff searches, known credential-prefix/JWT/private-key patterns, sensitive
filename searches, and manual review of ignored environment templates.

Results:

- no requested personal-name, personal-email-domain, Windows-user, or private absolute-path pattern remains;
- five machine-specific paths initially found in the new migration documents were replaced with
  repository/sibling-relative descriptions, then the scans were rerun successfully;
- no seed phrase, mnemonic, wallet private key, SSH private key, API key, Cloudflare credential,
  Telegram token, bearer credential, cookie, setup token, or `.env` value was found;
- token-shaped values in `crates/ghost-gate-bridge/src/trace.rs` are deliberately fake test canaries
  used to prove trace redaction;
- ignored `deploy/*.env.template` files contain placeholders only and are not staged;
- `gitleaks` is not installed, so equivalent repository/Git-aware pattern scans were performed
  directly instead of installing or downloading a scanner.

The `.gitignore` covers Cargo targets, local Cargo configuration, environment files, key/seed formats,
wallet databases, credentials/secrets directories, local Tari/Ghost Gate state, browser profiles,
Cloudflare local state, logs, archives, staging assets, and editor/OS noise.

## Candidate-diff audit

`git diff` was reviewed file by file, with lockfile dependency/version changes reviewed separately.
`git diff --cached` was empty before staging. The changes are limited to:

- the Ootle 0.49.2 / wallet 0.51 / indexer 0.50 / Minotari 6.3 dependency cohort;
- current signer, transaction, wallet SDK, receipt-event, and base64-CBOR indexer APIs;
- locked upgrade rules for newly republished components;
- an opt-in, fail-closed native Minotari base-node feature boundary;
- the narrow wallet minimum-value-promise patch and its tests;
- migration, validation, bootstrap, and publication evidence.

The patch applies cleanly in check mode to the pristine sibling Ootle v0.49.2 reference. No Ootle
source is vendored into this repository.

## Validation result

Publication-preparation reruns, refreshed after the engine-test migration repair:

- `cargo check --workspace --locked` — **PASS** (warnings only);
- `cargo test --workspace --exclude ghost-gate-tests --locked` — **PASS**: 397 passed, 0 failed,
  5 intentionally ignored live-indexer tests;
- the repository-specific `rustfmt +nightly-2025-12-05 --edition 2024 --check` command used by CI —
  **PASS** for all 13 Ghost Gate-owned files in scope;
- all three template `wasm32-unknown-unknown` checks with `--locked` — **PASS**;
- focused wallet SDK minimum-value-promise tests with `--locked` — **PASS**, 3/3;
- `.github/workflows/ootle-0492-validation.yml` — **PASS** through PyYAML safe parsing;
- `git diff --check` — **PASS** before staging (only Git CRLF conversion notices for four lockfiles);
- staged `git diff --check`, excluding the standalone patch artifact — **PASS**; checking the patch
  artifact itself reports its whitespace-only context-marker lines, which are required unified-diff
  syntax rather than source whitespace defects;
- `git apply --check --recount -p1` for `docs/wallet-mvp-0492.patch` against the pristine reference —
  **PASS**.

The secret/identity audit was also repeated against the repaired candidate:

- all three reachable commits use exactly
  `GSXRspartan <304655218+GSXRspartan@users.noreply.github.com>` for author and committer;
- repository-local author configuration matches that identity exactly;
- origin fetch and push URLs remain `https://github.com/GSXRspartan/Ghost-Gate.git`;
- no private-key block, AWS key, GitHub token, Slack token, Telegram token, Cloudflare token, bearer
  value, JWT, or local Windows user path was introduced by the candidate diff;
- history-wide token-shaped matches remain the documented fake redaction canaries in
  `crates/ghost-gate-bridge/src/trace.rs`; no value was printed during the audit;
- `gitleaks` remains unavailable, so the Git-aware pattern scan was used without downloading tools.

Recorded in `docs/OOTLE_0492_RUST_VALIDATION.md`:

- `cargo test --workspace` — **ENVIRONMENT BLOCKED** before engine test execution because upstream
  `wasmer-compiler-cranelift 7.5.0` rejects Windows;
- WSL engine-test fallback — **ENVIRONMENT BLOCKED** because the registered distributions point to
  missing VHDX files;
- Linux engine tests — pending the blocking GitHub Actions job for the repaired commit.

No test was weakened or ignored. The GitHub workflow's owned-source formatting job is now blocking,
and its engine job runs all four Linux-only targets. `markdownlint` and `lychee` are not installed; no
tooling was downloaded merely for this audit. The documents' paths, headings, verdicts, and patch
application instructions were inspected manually.

## Remaining safety boundary

This commit is suitable as an auditable migration checkpoint on the upgrade branch. It must not be
treated as deployment approval. Before Stage 3 bootstrap or merge-to-release, the GitHub Linux job
must pass all four `ghost-gate-tests` engine suites for the exact pushed commit. The formatting
policy/scope is now pinned and locally green.

## Manual operator command

After verifying that local `HEAD`, author, committer, and clean status match the post-commit handoff,
the operator may run:

```powershell
git push -u origin upgrade/ootle-0.49.2
```

This command was not executed by Codex.

MANUAL PUSH VERDICT: SAFE TO PUSH
