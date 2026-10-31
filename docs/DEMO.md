# Ghost Gate Contest Demo

Ghost Gate is privacy-aware access control for Tari: **Prove enough. Reveal less.**

The live test gate is **Crypt**: 100 native tTARI on Esmeralda testnet, Crypt v3 credential mode,
and a seven-day verified session. It uses a qualifying revealed/public tTARI output; it is not a
fully confidential aggregate-balance proof or production authorization infrastructure.

## Option A — Privacy Lab

1. Open [ghostgate.boo](https://ghostgate.boo).
2. Connect a supported wallet.
3. Select **Crypt** and review the published 100 tTARI policy.
4. Complete the wallet-approved qualifying-output proof.
5. Observe the verified session in the **Simple** or **Technical** view.

Privacy Lab demonstrates wallet connection, gate discovery, challenge/proof lifecycle, threshold
outcome, public technical diagnostics, session state, and Telegram onboarding. An insufficient
qualifying amount is refused.

## Option B — Telegram

Only use this path when a judge has separately been provided the intended test-group invite; this
document does not publish a private group link.

1. Open `@GhostGateGSXRBot` and send `/join`.
2. Open the account-bound, single-use Ghost Gate link.
3. Connect a supported wallet and complete the Crypt proof.
4. Submit the matching pending Telegram join request.
5. The bot re-checks authorization server-side and approves only that matching account/request.

This demonstrates an actual access decision, not a screenshot-review workflow. The bot never needs
a seed phrase, private key, or exact total wallet balance, and it does not trust browser success text
without server-side verification.
