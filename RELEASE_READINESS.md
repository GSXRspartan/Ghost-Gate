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

Validation outcomes and the final release commit/tag are recorded here immediately before release.
The candidate must not be pushed unless this section shows successful applicable checks and the
remote is explicitly configured.

## Known release limitations

- Crypt v3 uses a revealed/public qualifying tTARI output.
- Telegram grants are process-memory state.
- The current trust model is operator-trusted testnet.
- Fully confidential threshold proofs are future work.
