# Telegram admission boundary

> **Historical security/design record.** It captures an earlier deployment stage. The current
> public-release summary is `docs/TELEGRAM.md`; do not use this document as a live runbook.

Ghost Gate's Telegram bot binds a browser proof to the Telegram account that sent `/join`. It
does not accept a browser-provided Telegram user ID. A one-time token is minted from Telegram's
own update, the bot re-reads the proof from the bridge, and the eventual Telegram join request is
approved only for that same account and configured chat.

## Current safety state

Production admission is deliberately disabled. Stage 5 does not yet have an independently
authenticated Esmeralda trust root or a verified genuine handover, so no production bot process
may issue or approve membership. A receipt merely being `credential_accepted` is not sufficient:
live admission also requires a server-issued access session, and startup exits fail-closed after
the read-only Telegram diagnostic while Stage 5 remains blocked.

`GG_TG_FIXTURE=1` is the local-only lifecycle mode. It never contacts Telegram and requires
`GG_TG_FIXTURE_TEST_CHAT_ID` to exactly equal `GG_TG_CHAT_ID`; it cannot change any Telegram
membership. Its HTTP response and browser UI are labelled `test_only`.

For a controlled real Bot API exercise against a designated private test supergroup, set
`GG_TG_TEST_MODE=1` and set `GG_TG_TEST_CHAT_ID` to the same numeric value as
`GG_TG_CHAT_ID`. This is disabled by default, requires the BotFather token, runs the same
read-only private-supergroup diagnostic first, and uses only the clearly-labelled fixture bridge.
It cannot issue a consensus-verified production grant and must never be pointed at a production
group. Neither test-mode variable is accepted from a browser request.

## Read-only private-supergroup diagnostic

Keep the token in a user- or service-scoped secret store, not a repository file. The bot must be
an administrator of a **private supergroup** (no public username) with `can_invite_users` and
`can_restrict_members`.

In PowerShell, set secrets only for the diagnostic process, then run:

```powershell
$env:GG_TG_BOT_TOKEN = '<BotFather token>'
$env:GG_TG_CHAT_ID = '<private supergroup id>'
$env:GG_TG_DIAGNOSE = '1'
cargo run -p ghost-gate-telegram
Remove-Item Env:GG_TG_BOT_TOKEN
```

The diagnostic calls `getMe`, `getChat`, and `getChatMember`; it creates no invite, processes no
updates, and changes no membership. Do not copy the token into logs, shell history, a `.env` file
tracked by Git, or an issue.

To confirm the Telegram-side state of a designated test account after a controlled admission,
removal, or re-verification, set the non-secret numeric `GG_TG_TEST_MEMBER_ID` before the same
diagnostic command. It makes one additional read-only `getChatMember` call and prints only the
returned membership status, not the token. Remove it afterwards with the other process variables.

After a successful diagnostic, an operator may run the isolated real test mode only with the
private test group's ID in both variables:

```powershell
$env:GG_TG_TEST_MODE = '1'
$env:GG_TG_TEST_CHAT_ID = $env:GG_TG_CHAT_ID
cargo run -p ghost-gate-telegram
Remove-Item Env:GG_TG_TEST_MODE, Env:GG_TG_TEST_CHAT_ID, Env:GG_TG_TEST_MEMBER_ID, Env:GG_TG_BOT_TOKEN -ErrorAction SilentlyContinue
```

The test bridge accepts only proof IDs beginning `fixture_`; this is intentional. It exercises
Telegram identity binding, join-request approval, expiry, revocation and re-verification without
claiming a genuine consensus authorization. A production group must not be configured as this
test group.

## Intended admission lifecycle after Stage 5 approval

1. Configure one private group and Telegram-scoped gate per bot deployment. Independent gates
   use separate configuration/deployments; a gate identifier is never accepted from the browser.
2. The user sends `/join`; Telegram supplies the user identity and the bot mints a 10-minute,
   single-use token bound to it.
3. The browser completes a fresh gate proof. The bot obtains the receipt and access session from
   the bridge itself, checks the configured gate, then creates an expiring join-request invite.
4. Telegram delivers `chat_join_request`; only the bound user with a live server session is
   approved. Forwarded invites and wrong-chat requests are declined.
5. On expiry or registry revocation, the bot removes the member with a temporary ten-minute ban
   followed by an explicit `unbanChatMember`. Ten minutes stays well above Telegram's 30-second
   permanent-ban threshold under ordinary clock skew and API latency. An ambiguous ban/unban
   result enters a bounded retry queue; a process crash is still bounded by the temporary ban.
   A bridge outage defers removal rather than guessing.

Before enabling this lifecycle, retain the raw genuine 12634-to-12635 checkpoint evidence, verify
it from the reviewed anchor, and obtain explicit operator approval for the production root and
membership change.
