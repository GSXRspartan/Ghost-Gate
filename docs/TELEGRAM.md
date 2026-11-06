# Telegram Integration

Ghost Gate's Telegram integration gates a join request; it is not a browser-only claim.

1. A user sends `/join` to `@GhostGateGSXRBot`.
2. The bot creates a short-lived, single-use link bound to that Telegram account.
3. The user completes the Ghost Gate proof in Privacy Lab.
4. The Telegram service re-verifies the proof with the server-side bridge.
5. Telegram sends a pending join request. The bot approves only if its chat and account match the
   verified grant.

Within the bot's tracked flow, wrong, expired, unverified, or account/chat-mismatched requests are
not admitted. The flow is fail-closed if authoritative verification is unavailable.

## Current security limitations

This is a private-test-group integration, not a complete production admission boundary:

- An accepted bridge proof id is not cryptographically committed to the bot-minted join token.
  Anyone who obtains a still-readable accepted proof id may pair it with a different valid join
  token. Production use requires the join-token commitment in the challenge and receipt.
- Pending/grant state is in process memory. A restart loses the user-to-session mapping while
  memberships already approved by Telegram persist, so expiry and revocation are not guaranteed
  across restarts.
- The bot consumes `message` and `chat_join_request` updates, not `chat_member` updates. Another
  administrator, a manual add, or an old invite link can bypass the bot unless those Telegram-side
  paths are removed. Operational restrictions reduce exposure but do not replace persistent
  membership reconciliation.

## Operations

The BotFather token, chat ID, bridge credentials, and Worker/verifier keys are deployment secrets.
Use the placeholder-only service templates under [`deploy/`](../deploy/README.md); do not commit
live environment files or paste tokens into diagnostics.

Keep the live-testnet guard enabled only for the explicitly configured private test supergroup.
Do not describe Telegram admission as production-enforced until the three limitations above have
regression coverage and a live membership reconciliation test.
