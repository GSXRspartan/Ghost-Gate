# Telegram Integration

Ghost Gate's Telegram integration gates a join request; it is not a browser-only claim.

1. A user sends `/join` to `@GhostGateGSXRBot`.
2. The bot creates a short-lived, single-use link bound to that Telegram account.
3. The user completes the Ghost Gate proof in Privacy Lab.
4. The Telegram service re-verifies the proof with the server-side bridge.
5. Telegram sends a pending join request. The bot approves only if its chat and account match the
   verified grant.

Wrong, expired, replayed, unverified, or mismatched requests are not admitted. The flow is
fail-closed if authoritative verification is unavailable.

## Operations

The BotFather token, chat ID, bridge credentials, and Worker/verifier keys are deployment secrets.
Use the placeholder-only service templates under [`deploy/`](../deploy/README.md); do not commit
live environment files or paste tokens into diagnostics.

The current implementation keeps pending/grant state in process memory. A restart loses that state;
persistent grant storage is planned future work.
