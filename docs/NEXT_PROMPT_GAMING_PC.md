# Next OpenCode prompt — Ghost Gate gaming PC

Paste the following into a fresh OpenCode session after importing the repository on the gaming PC.

```text
Continue Ghost Gate from the gaming PC migration handoff.

First read docs/HANDOFF_GAMING_PC.md completely and treat it as the authoritative starting state. Do not rediscover work that it already records.

Then:

1. Verify the imported repository:
   - pwd
   - git status --short
   - git branch --show-current
   - git rev-parse HEAD
   - git log --oneline -12
   - git remote -v
   - git worktree list
   - confirm branch main and HEAD b1ea62a (unless the handoff says otherwise after later local commits)
   - preserve every untracked and modified file listed in the handoff; do not delete, reset, or clean anything.

2. Verify the gaming PC toolchain and build paths:
   - rustc --version
   - cargo --version
   - node --version
   - python --version
   - wsl -l -v
   - confirm $env:CARGO_TARGET_DIR='D:\pb-target' or set it explicitly in each shell
   - verify the sibling cohort ../_ootle-v042-ghost-gate exists and is at the pinned commit with docs/wallet-mvp.patch applied
   - if missing, follow the exact preparation commands in docs/HANDOFF_GAMING_PC.md before building the main workspace.

3. Verify external isolated-verifier sources:
   - tools/m13-mainnet-verifier path dependencies to the v0.55.0 source checkout
   - tools/ghost-gate-v047-verifier path dependencies to .tari-v047-reference
   - tools/m16-fixture-bridge path dependencies and version pins
   - report any path that needs updating for the new PC before running builds.

4. Resume the latest incomplete work in this order:
   a. Fix the known M16 helper bug in scripts/start-m16-real-wallet-test.ps1: Start-Process -ArgumentList @() fails on Windows PowerShell 5.1; omit -ArgumentList when the collection is empty or pass @('').
   b. Start and health-check ONLY the local M16 fixture services using the helper; do not start a real Telegram bot, do not touch the production group, and do not use production credentials.
   c. Confirm the bridge serves gate esme on Esmeralda network 0x26, native TARI resource, threshold 100000000, and a real indexer chain reader.
   d. Generate a fresh on-demand session only when I explicitly ask for it; print the full local URL and never print HMAC keys, bot tokens, wallet data, or credentials.
   e. Prepare the exact Chrome/Sapient browser steps and stop before any wallet approval. Do not shield, spend, burn, request view access, or create a transaction.

5. Keep the GGBP-1 cross-layer Tari Universe investigation separate:
   - source and deployed bundle already show GGBP-1 methods in the Universe wallet, but no real embedded browser session has been tested;
   - do not assume documentation or source proves browser interoperability;
   - prepare a separate non-authorizing test plan and wait for my approval before any wallet interaction.

6. Run focused regression checks after any code change:
   - cargo test -p ghost-gate-bridge --lib -j 1
   - cargo test -p ghost-gate-telegram --bin ghost-gate-telegram -j 1
   - cargo test -p ghost-gate-registry -p ghost-gate-admin -j 1
   - npm test --prefix cloudflare
   - node --test web/js/ghost/test.js
   - cargo test --manifest-path tools/m13-mainnet-verifier/Cargo.toml --bin adapter -j 1
   Use D:\pb-target for Cargo artifacts; do not run multiple heavy Cargo builds concurrently.

7. Safety constraints (always enforce):
   - no deploy, no VPS/Cloudflare changes, no pushes, no mainnet admissions, no live Telegram membership changes;
   - no spending, shielding, burning, or wallet-secret requests;
   - no certificate-store changes;
   - no GGBP-1 L1 authorization; keep it non-authorizing;
   - do not weaken trust tiers or fail-closed checks;
   - do not commit unless I explicitly ask;
   - do not delete or discard untracked files.

8. Report:
   - verified repo state and toolchain;
   - migrated paths that needed updates;
   - M16 helper/service status;
   - exact browser URL only after I ask for a fresh session;
   - what is source-verified versus real-browser verified versus still awaiting my wallet approval;
   - any blockers and the next safe step.
```

Do not modify production code unless a verified bug requires it and the change is explained first.
