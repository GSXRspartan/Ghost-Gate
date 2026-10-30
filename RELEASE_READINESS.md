# Release Readiness — Contest Candidate

## Freeze inventory

| Item | Value |
| --- | --- |
| Audit started | 2026-10-30 |
| Starting branch | `main` |
| Starting HEAD | `404cbb51cf3fe230c960f9510758fb6f6fab59e1` |
| Existing tags | `audit-baseline`, `gate3-green` |
| Git remotes at audit start | None configured |
| Rust package version convention | Workspace packages at `0.1.0` |
| Worker compatibility date | `2026-10-23` |
| Active Crypt policy | v3, credential mode, 100 tTARI / `100000000` raw, network `38` |
| Policy hash | `13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f` |
| Session lifetime | 7 days |

Telegram is built from the workspace `ghost-gate-telegram` package. No independent deployed binary
version was recorded in tracked source; deployment images and local service configuration are not
part of this candidate.

## Security audit

- Tracked source and configuration were scanned for high-confidence Telegram, Cloudflare, AWS,
  private-key, and GitHub credential patterns without printing values.
- The only GitHub-PAT-shaped match is a synthetic test input in
  `crates/ghost-gate-bridge/src/trace.rs`; it is intentionally rejected by the sanitizer test.
- Git history was scanned with the same high-confidence patterns. No live credential finding was
  identified.
- Local untracked deployment artifacts/configuration were inspected but are excluded from the
  candidate by `.gitignore`.

## Validation

| Check | Outcome |
| --- | --- |
| Current Worker suite (`cloudflare/npm test`) | PASS — 53 passed, 1 intentionally skipped integration test |
| Current browser-provider suite (`node --test web/js/ghost/test.js`) | PASS — 31 passed |
| Clean clone | PASS — local clone at `35c59ca2e8b25cd41437f2b9759e864cb4e2291d`, clean status |
| Fresh Tari cohort bootstrap | PASS — official v0.42.0 commit cloned and `docs/wallet-mvp.patch` applied; clean-clone Cargo metadata resolved |
| Clean-clone Worker install/test | PASS — `npm ci` followed by 53 passed / 1 skipped |
| Clean-clone browser-provider suite | PASS — 31 passed |
| Rust workspace suite (`cargo test --workspace`) | BLOCKED — `randomx-rs` CMake selected Visual Studio 18 2026, but no compatible Visual Studio instance is installed. Tests did not start. |
| Clean-clone Rust workspace suite | NOT RUN — blocked by the same missing Windows CMake/Visual Studio toolchain prerequisite |

The candidate must not be tagged or pushed until the Rust workspace suite passes in an environment
with the required native build toolchain and a GitHub destination is configured.

## GitHub release state

No Git remote was configured at audit start or at this checkpoint. No GitHub authentication,
repository visibility, push, remote README check, or release tag verification was possible.

## Public-source review

The current candidate has no personal-path or private-network reference match. Historical commits
contain development-era local-path references in archival documents/scripts; no history rewrite was
performed. The scan found no live secret in current files, local candidate artifacts, or history.

## Known release limitations

- Crypt v3 uses a revealed/public qualifying tTARI output.
- Telegram grants are process-memory state.
- The current trust model is operator-trusted testnet.
- Fully confidential threshold proofs are future work.
