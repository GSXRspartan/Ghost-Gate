# M3 security review status — deployment blocked

Baseline `90626fc`. No production system, Telegram group, credential or persistent state was changed.

## Changes reviewed locally

- `e30dd29`: remove the bot trait's ban/unban methods and implementations. The private-supergroup
  diagnostic now requires invite rights but does not require member restriction rights. This does
  not change the live bot's permissions.
- `da9fde1`: real `/join` reports the pause without minting a link; the join web page stops before
  requesting a wallet proof, including for a stale link. Local fixture bot tests remain isolated.

Affected code: `crates/ghost-gate-telegram/src/main.rs`, `web/telegram/claim.js`, and
`cloudflare/test/telegram-join-config.test.js`.

## Unresolved High findings

1. **Identity binding:** the bridge wallet signs a challenge nonce and the bot obtains its identity
   from Telegram updates, but the two are not committed together. M2 denies real claims and approvals;
   M3 has not implemented an authenticated bot-to-bridge challenge, bound receipt or durable replay
   consumption. No qualified real user can currently be admitted by this local version.
2. **Restart recovery:** Telegram grant mappings and update offsets remain in memory. Existing
   memberships are separate and are not removed by the patched ticker. Missing mappings cannot
   authorize new admissions because real admissions are paused. The durable store, crash-safe
   migration, monitoring of out-of-band joins and recovery tests do not exist yet. Other
   administrators and their invite links remain outside the bot's exclusive control.
3. **Admin isolation:** the bridge still loads the full registry containing administrator sessions,
   CSRF material and credential records, and its configured service identity has shared access to
   the registry directory. No separate admin store, migration, filesystem isolation test, or
   indirect-API isolation test has been implemented.

These are unresolved implementation tasks, not accepted platform limitations. Current indexer
evidence is operator-trusted testnet, not independently authenticated production consensus evidence.

## Verification performed

- Telegram: 30 tests passed after the final bot change, including a fake membership set preserved
  through process replacement, unbound-proof denial, and no link on a real `/join`.
- Worker: 55 passed, zero failed, one integration test skipped after the final page change. The
  new page test checks source ordering; no real wallet or browser end-to-end proof was exercised.
- Bridge: 175 passed; administration: 38 passed; registry: 25 passed in the full local Rust suite
  at `e30dd29`. Those components were unchanged after that run. Existing compiler warnings remain.
- No isolated end-to-end upgrade/migration/rollback drill or operating-system permission test was
  performed. No production Telegram mutation was performed.

## Deployment and rollback gate

**NO-GO / BLOCKED.** No tested safe rollback binary or migration artifact was produced. The old
deployed binary may remove members automatically and is not an acceptable rollback target. The
mock restart evidence does not demonstrate that a live deployment or rollback preserves membership.

Before any deployment, complete the three architectures above; validate wallet-provider signing
compatibility; create versioned and atomically recoverable state without overwriting legacy data;
verify separate service users and filesystem ACLs on Linux; build and hash a rollback artifact
without member-removal code; and run isolated full upgrade, crash, corrupt-state, restart and rollback
tests with existing members, qualifying and nonqualifying users, and duplicate join requests. Have
an independent reviewer assess the protocol and privilege boundaries.

Only then, after separate explicit production approval, inventory members and administrator/invite
paths read-only, take root-only verified backups, stage the exact artifacts and configuration, deploy
in an isolated test group first, and monitor without removing or reapproving existing members. Keep
legacy memberships with incomplete proof data unchanged and marked unknown. Preserve registry,
generation, session, audit, replay and halt records during any recovery; never reset the group.
