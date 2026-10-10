# Vendored third-party artifacts — review record

Both files are copies of third-party work, fetched 2026-10-09 and read before inclusion. They are
pinned by SHA-256; re-verify both hashes before trusting a fresh copy, and expect the upstream
connector to change without notice — it is served live from `universe.tari.mw`, which is exactly why
it is vendored instead of hot-linked.

| File | Source | SHA-256 |
| --- | --- | --- |
| `tari-connector.js` | `https://universe.tari.mw/tari-connector.js` | `dddb0224220bec6f8307d5b2f71714c166b231005630661baca1a714bc278839` |
| `tari-dapp.d.ts` | `https://universe.tari.mw/integration/tari-dapp.d.ts` | `5b465357c77119bef5aab2938707119d76ea706deabce8d11d515d729e048dc4` |

## `tari-connector.js` — what was reviewed

Read in full before vendoring. Findings:

- No `eval`, no `new Function`, no `innerHTML`, no dynamic script insertion. The only outbound URL
  in the file is its own `https://universe.tari.mw/tari-connector.js` origin comment.
- Outbound traffic is exactly one `window.parent.postMessage` per request, sent to `"*"`. That target
  is acceptable here, not sloppy: the page cannot know the embedding wallet's origin ahead of time,
  and the payload is only a *request* the wallet must still authorise. The reply path is the strict
  direction and it is checked — `event.source !== window.parent` drops the message before any
  callback runs.
- Replies resolve/reject by request id, carry the provider error codes through unchanged
  (`4001/4100/4200/-32603`), and expose `isTariWallet: true`, `isEmbedded`, and
  `info.rdns = "mw.tari.universe"`. In a plain tab every call rejects rather than hanging — the
  property our UI relies on to show an honest "not available here" state.
- Sugar helpers (`requestAccounts`, `proveFunds`, `verifyFunds`, `requestTransaction`, …) are one-line
  wrappers over `request({ method, params })`; nothing second API.

Risk accepted by vendoring: this file is the transport between our page and an embedding wallet. It
is reviewed as of the pinned hash; a changed upstream is a changed trust decision, hence the pin.

## `tari-dapp.d.ts` — what it is for

A declaration file only; nothing executes it. It is the contract our provider adapters and mock-based
tests are written against, kept so tests fail loudly if code and contract drift apart. Field names and
the capability list were additionally cross-checked against Sapient's own implementation (see
`docs/PROVIDER_COMPATIBILITY.md` §7 for the divergences found there).
