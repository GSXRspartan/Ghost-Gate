# Architecture

Ghost Gate separates public presentation, policy verification, and administration.

```mermaid
flowchart TD
  U[Visitor wallet] --> W[Cloudflare Worker / Privacy Lab]
  W --> R[Durable Object replay coordinator]
  W --> B[VPS verifier bridge]
  B --> G[Crypt v3 policy]
  G --> B
  B --> W
  W --> A[Seven-day verified session]
  TG[Telegram bot] --> B
  TG --> JR[Bound Telegram join request]
  ADM[Private administrator plane] --> G
```

## Components

- **Privacy Lab:** the public interface at `https://ghostgate.boo`.
- **Cloudflare Worker:** serves the static interface and handles public request routing.
- **Durable Object:** coordinates a challenge nonce's replay-sensitive lifecycle when configured.
- **VPS verifier bridge:** validates the submitted credential against the active gate policy and
  returns a signed result to the Worker.
- **Telegram service:** creates account-bound join links, re-verifies server-side, and approves
  only a matching pending join request.
- **Private administrator plane:** manages policy/admin concerns independently of public traffic.
- **Cloudflare Tunnel:** provides restricted ingress to the verifier bridge rather than exposing
  its loopback listener directly.

## Active Crypt policy

Crypt v3 is bound to `https://ghostgate.boo`, Esmeralda testnet network `38`, the 100 tTARI raw
floor `100000000`, credential proof mode, and policy hash
`13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f`.

This is a testnet, operator-trusted flow. The credential is based on a revealed/public qualifying
tTARI output, not a fully confidential balance proof.
