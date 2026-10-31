# Security Model

Ghost Gate is a fail-closed, operator-trusted Esmeralda testnet demonstration. It is not production
consensus-verified authorization infrastructure.

## What is bound

The release flow binds a proof decision to the relying-site origin, configured gate/policy,
policy version/hash, network, fresh challenge nonce, and session commitment. A malformed,
incomplete, unverifiable, expired, or replayed result is rejected rather than converted to access.

The Worker authenticates its verifier-bridge contract. When configured, a Durable Object owns the
replay-sensitive challenge lifecycle. The public frontend is not trusted to set a threshold,
verdict, wallet balance, or Telegram identity.

## Privacy boundary

Ghost Gate does not request a seed phrase or private key. It does not disclose the user's total
wallet balance or the amount above the policy floor in the Ghost Gate result.

However, Crypt v3 currently uses a revealed/public qualifying tTARI output. The lower-bound policy,
the qualifying transaction/output, and transaction metadata can be observable. Ghost Gate does not
provide anonymity, an ongoing-balance guarantee, or fully confidential balance proof today.

## Telegram boundary

Telegram `/join` creates a short-lived, single-use link bound to Telegram's own account identity.
The server re-verifies the Ghost Gate result and approves only the matching pending join request in
the configured chat. Browser-provided Telegram identities are not authoritative.

## Operational limits

- Testnet/indexer/operator trust remains part of the current assurance model.
- Telegram grants are held in process memory; restart persistence is future work.
- Secrets belong in deployment secret stores, not source control, Wrangler configuration, logs,
  screenshots, or shell history.
- The private administrator plane must remain separate from the public application surface.
