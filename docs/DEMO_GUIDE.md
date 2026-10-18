# Demo guide — screenshots, video storyboard, presentation notes

This is the presentation kit for the contest submission. Everything here is reproducible on the
demo machine; nothing requires publishing anything without operator approval.

## The two demonstrations

1. **The Privacy Lab** (`/lab`) — the contest application's home. Choose a gate, choose a wallet,
   prove the minimum threshold, and watch either a plain-English walkthrough or the sanitized
   protocol inspector. No game, no puzzle, no fictional result.

## Screenshot set (reproducible)

Take these in Windows Chrome against `http://127.0.0.1:7799` (bridge started per
`scripts/start_vault.sh`). Save under `docs/screenshots/` (not committed unless the operator
wants them in the repo).

2. **The Sanctum** — after "Descend": three doors with the thresholds the bridge reported
   (`100k / 500k / 2M` raw with display conversions), the relics/whispers HUD.
3. **Preview banner** — after "Preview without a wallet": the PREVIEW banner across the top and
   each open door carrying the "PREVIEW — not verified" label.
4. **the Lab puzzle** — inside the first chamber: the epitaph and the four candles, two lit.
5. **Relic modal** — after completing a puzzle: the relic art, title and lore.
6. **Door opening** — mid-animation: doors ajar with the ember glow between them (use Chrome's
   screenshot-after-animation trick: press the door's Enter, then screenshot during the 2.1s
   opening; or enable "Capture node screenshot" in DevTools on the `.door` element).
7. **Proof overlay (real mode)** — with a wallet connected: the four-step proof list with the
   "Consensus is deciding. The floor is public; the amount is not." line.
8. **The Abyss** — the eye and the four echo pads mid-flash.
9. **Telegram fixture** — terminal with `[fixture] -> tg_user 42: Verified: …` and the browser's
   join page side by side.
10. **Bridge honesty** — `/health` and `/wallet/status` in adjacent tabs: reachable but carrying
    no balances, ever.

For automation on the demo machine (optional): Chrome's `--headless=new --screenshot` works for
1–5 and 8–9; 6 needs the animation timing, so capture it manually.

## Demo-video storyboard (3–4 minutes)

| Time | Shot | Voice-over beat |
|---|---|---|
| 0:00–0:20 | Title screen, fog drifting, the wordmark flickering | "Ghost Gate is a token gate that never learns your balance." |
| 0:20–0:45 | The Sanctum, three doors with thresholds; hover each | "Three doors, three thresholds — all read live from the chain, none hard-coded." |
| 0:45–1:20 | Preview walkthrough, PREVIEW banner visible; one puzzle solved | "Every room is playable in a labelled preview that mints nothing." |
| 1:20–2:10 | REAL: connect walletd, click Break the Seal; the proof overlay; the wallet's own approval UI (screenshot or live); the door opening | "The real unlock is a private proof the network verifies: a public minimum, committed in a range proof. The gate learns a floor — never an amount." |
| 2:10–2:50 | Replay attack: submit the same challenge twice → refused; a second account below threshold → refused | "Replay refuses. A proof is single-use, bound to a challenge, and the threshold is enforced by consensus — not by wallet software." |
| 2:50–3:30 | Telegram: /join → the link → the wallet approving → the invite lands; then the expiry tick revokes | "The same verifier gates a community: fresh proof, expiring seat, automatic re-verification." |
| 3:30–4:00 | The security summary slide: the audit's four fixed findings, the eleven refused forgeries, the release gate | "The privacy boundary is the API surface. The security boundary is the engine." |

## Presentation notes (say these, precisely)

- **Consensus proof vs credential proof** — consensus: a `StealthTransferStatement` executed by
  the engine inside the transaction; the bulletproof over the claimed minimum and the balance
  proof over the public excess are what enforce the threshold; nothing about the wallet's holdings
  crosses the boundary. Credential: a real output whose own range proof publicly commits to a
  minimum, plus an ownership signature over a fresh challenge; public and permanent by design,
  verified against the on-chain key. The UI labels which produced any unlock; nothing downgrades
  automatically in either direction.
- **Multi-wallet** — capability-driven (`tari_getCapabilities`), never wallet-detection; matrix in
  `docs/PROVIDER_COMPATIBILITY.md` §1.
- **Generic resources** — any Ootle stealth-fungible; the gate binds resource ADDRESSES; symbols
  are display-only (`docs/RESOURCE_SUPPORT.md`).
- **Native L1 XTM status** — experimental, blocked upstream (no L1 dApp surface; Minotari wallet
  gRPC signs with the node-identity key only). Never advertised as working; never demonstrated
  unless separately verified.
- **Security limitations** — point at `docs/SECURITY_RELEASE_GATE.md`; the honest one-liner is
  "mainnet rows are NO-GO until the cohort re-pin and live wallet passes are done".
