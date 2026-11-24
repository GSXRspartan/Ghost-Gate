# Ghost Gate — October contest final checklist

**Status date:** 2026-10-25. This is an evidence checklist, not a claim that every item has been run today. Never turn a synthetic result, a UI display, or an unverified indexer response into an authorization claim.

## Submission classification

| Area | Classification | Evidence / current limitation |
| --- | --- | --- |
| Privacy Lab decision flow | **BLOCKED THIS SPRINT** | The documented loopback Lab is not running on `127.0.0.1:7799`; it can run offline once the native bridge is built. |
| Gate selection; Simple/Technical UI | **NOT TESTED THIS SPRINT** | Test only against the live loopback Lab, after checking its URL and browser context. |
| Browser provider mapping | **AUTOMATED** | `node --test web/js/ghost/test.js`: 30/30 passed on 2026-10-25. This covers feature detection, error taxonomy, network matching, and refusal of an L2 provider for an L1 gate. |
| Sapient physical connection and signature | **NOT LIVE TESTED** | Existing adapters are tested; a user-approved Sapient prompt and trusted chain evidence have not been observed this sprint. |
| Ootle L2 consensus authorization | **RECORDED PRIOR EVIDENCE** | See `docs/GATE3_RESULTS.md`; do not present it as re-run today. New live claims require current authenticated chain evidence. |
| Web Tari Universe L1 GGBP-1 | **SYNTHETIC / HANDOFF ONLY** | Isolated Web TU commit `450ba207798f8765e12b003dbfe9d7b0616ea711` documents an explicitly disabled `ggbp1BalanceProof` capability. No live L1 proof API exists. |
| Telegram | **OUT OF SCOPE** | Separate workstream; do not change code, tokens, configuration, or claims here. |

## Safe Windows Lab startup

The Windows launcher is `scripts/dev.ps1`; it uses `127.0.0.1` only, browser/offline mode by default, and does not touch the protected administrator service on port 7811. It intentionally requires a native `ghost-gate-bridge.exe` and does not compile it itself.

After all pre-existing Cargo work has finished, run this in PowerShell from the repository root:

```powershell
$env:CARGO_TARGET_DIR = "$PWD\_cargo-target-native"
cargo build -p ghost-gate-walletd --bin ghost-gate-bridge
$env:GG_BRIDGE_PORT = '7799'
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 start -Mode browser
Invoke-WebRequest http://127.0.0.1:7799/health
```

`browser` mode removes walletd credentials/endpoints from the launched process. It serves a loopback-only offline demonstration; any proof route without an authenticated wallet remains refused. Stop only the launcher-owned process with:

```powershell
$env:GG_BRIDGE_PORT = '7799'
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 stop -Mode browser
```

## Lab test run sheet

Record PASS, FAIL, BLOCKED, or NOT TESTED and a timestamp for each item:

1. Open exactly `http://127.0.0.1:7799/lab`; confirm the active URL before testing.
2. Check the gate selector and displayed threshold/divisibility against `/lab/gates`.
3. Switch Simple and Technical views; confirm neither view represents a simulation as access.
4. Create a challenge; retain only public nonce/session test metadata.
5. Exercise offline visitor denial and labelled Lab simulation. Confirm simulation returns no access session.
6. Refresh after a challenge and verify recovery/refusal behavior; test expiry only with a short-lived fixture.
7. Replay a consumed fixture challenge and record the refusal. Do not fabricate a wallet proof.
8. With Sapient installed, check provider detection, user-approved connection, Esmeralda byte binding, and a clean declined request. A successful credential flow also requires independently verified current chain evidence.
9. Test narrow and mobile viewports; capture only non-sensitive UI.

Run the existing focused provider suite before a browser run:

```powershell
node --test web/js/ghost/test.js
```

## Screenshots and short demo

Use `docs/DEMO_GUIDE.md` and `docs/DEMO_SCRIPT.md`. Capture the gate selector; Simple/Technical views; challenge and visitor-denial states; explicitly labelled offline simulation with no session; provider unavailable/declined states; and a credential result only with retained authenticated-chain evidence. Never capture seed phrases, backup exports, keys, wallet databases, bearer tokens, Telegram tokens, or administrator pages.

## Submission materials

- Main narrative: `docs/CONTEST_SUBMISSION.md`
- Honest feature/readiness map: `docs/CONTEST_README.md`
- Demo and screenshots: `docs/DEMO_SCRIPT.md`, `docs/DEMO_GUIDE.md`
- Security/privacy limits: `docs/PRIVACY_MODEL.md`, `docs/THREAT_MODEL.md`, `docs/SECURITY_FINDINGS.md`
- Source provenance: `docs/GAME_PROVENANCE.md`; repository license: `LICENSE` (MIT)
- Web TU is separate, CPAL-1.0 licensed, and its source is not copied into this submission.

**Tari payment address:** `[OPERATOR TO PROVIDE BEFORE SUBMISSION]`.

### Announcement draft

> Ghost Gate is a Tari Ootle privacy gate demo: it lets a site check whether a visitor meets a configured threshold without asking the site for an exact balance. The submission documents the privacy limits, offline Lab demo, and tested failure paths. Experimental Web Tari Universe L1 GGBP-1 work is a disabled, synthetic-only integration handoff—not a live wallet feature.

### Tari forum submission draft

> **Ghost Gate — contest submission**
>
> Ghost Gate demonstrates a configurable Tari Ootle threshold gate with a local Privacy Lab and documented verification boundaries. The repository includes the component/bridge design, adversarial tests, a reproducible demo script, and explicit privacy limitations. Browser-provider support is capability-detected and fails closed when chain evidence is missing. The separate Web Tari Universe GGBP-1 handoff remains disabled and synthetic-only pending wallet-internal proof support and review. Demo instructions: `docs/DEMO_SCRIPT.md`; limitations: `docs/PRIVACY_MODEL.md`.

Do not publish either draft until the payment address, live-test classification, screenshots, and official contest destination are confirmed.
