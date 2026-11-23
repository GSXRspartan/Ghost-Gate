# M15 real Sapient session-bound ownership test plan

This plan is prepared but **not executed**. It requires the user to approve a wallet signature. No wallet seed phrase, private key, balance, or transaction is requested.

## Goal

Prove, with a real Sapient wallet on Esmeralda, that a wallet signature over a Ghost Gate challenge is accepted only for the exact bound output, gate, network, policy, session and Telegram user/chat.

## Prerequisites

- Sapient wallet installed and connected to Esmeralda.
- An existing qualifying tTARI output with `minimum_value_promise >= 100000000` raw (100 tTARI). Do **not** create a new output for this test; use the existing fixture or an operator-provided output.
- Local bridge and fixture Telegram bot built with the existing M12 test scripts.
- `GG_TG_LIVE_TESTNET=1` remains unset unless explicitly approved for a live Telegram API; use the simulated Telegram API.
- No mainnet gate, no `GG_MAINNET_ADMISSIONS_ENABLED`, no `__Host-` cookie or certificate changes.

## Steps

1. Start the M12 simulated Telegram fixture and local bridge exactly as in `scripts/test-m12-e2e.sh`, but leave the wallet approval to the user.
2. Obtain a `/join` link from the simulated bot for a test Telegram user/chat.
3. Open the join link in the same browser that has Sapient installed.
4. The page must show the gate, network `0x26`, threshold, and the output id it intends to sign; verify these before approving.
5. Click **Connect wallet** if prompted; this should only authorize site access, not a spend.
6. Paste or confirm the existing qualifying output id. The page must not call `tari_createTransactionRequest` or shield/spend anything.
7. Request the challenge. Confirm the displayed challenge is freshly issued and bound to this session.
8. In Sapient, approve `tari_signOwnershipChallenge` for that exact output and challenge. This is the only wallet approval.
9. The page submits the signature to `/v1/bot/sessions/:id/proof`, then posts `{bot_session_id}` to the simulated `/claim`.
10. Confirm the bot redeems the single-use session and the simulated Telegram API records exactly one approval for the bound user/chat.
11. Replay the same session id; the bridge and bot must refuse it.
12. Repeat with a wrong user/chat binding in the simulated bot; the bot must refuse.

## Required evidence to record

- capability detection result (no seed/view secret);
- exact substate id and challenge domain;
- signature verification verdict from `CredentialVerifier`;
- bridge session state transition Created → Verified → Redeemed;
- simulated Telegram approval count (must be exactly one);
- replay and wrong-user refusal outputs.

## Stop condition

Stop before any wallet approval if the page requests:
- shield, send, burn, or any transaction creation;
- view access or private balance;
- a different network/resource/output than the published gate;
- a mainnet gate.

No mainnet Sapient proof is attempted until the Esmeralda test succeeds and the user explicitly approves a separate mainnet plan.
