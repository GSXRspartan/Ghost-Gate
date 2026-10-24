# Next implementation handoff

Stage 5 anchor research ends here. The verifier remains pinned-root-only and fail-closed; no
production wallet, Sapient authorization, access session, or Telegram production admission may be
enabled until the maintainer-authenticated anchor statement described in
`INDEPENDENT_ANCHOR_BOOTSTRAP.md` is available.

## First: Telegram private test-group completion

Continue from `5840b01` and `docs/TELEGRAM_ADMISSION.md`.

1. Run the read-only Bot API diagnostic with locally stored `GG_TG_BOT_TOKEN` and
   `GG_TG_CHAT_ID`; it calls `getMe`, `getChat`, and `getChatMember` for the bot.
2. If the configured chat is a private supergroup and the bot has invite/restrict permissions, use
   `GG_TG_TEST_MODE=1` and matching `GG_TG_TEST_CHAT_ID` only for the designated test group.
3. Exercise matching identity approval, wrong identity, expired fixture grant, replay, wrong chat,
   removal, explicit unban recovery, and re-verification. Confirm member state with the optional
   read-only `GG_TG_TEST_MEMBER_ID` diagnostic.
4. Record real Bot API results separately from fixtures. Test-only authorization must never be
   configured for a production group.

## Then: Tari Universe and XTM threshold-proof research

Research capability discovery and ownership-proof surfaces before implementation. Keep browser
wallet accounts visitor-controlled; never route a visitor-selected account into the operator's
walletd. For XTM, preserve the existing explicit experimental/fail-closed boundary and do not
infer a usable proof method from a wallet connection or public balance query.

Neither follow-up changes the Stage 5 production authorization verdict.
