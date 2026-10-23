# Telegram admission boundary

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

The only non-production lifecycle mode is `GG_TG_FIXTURE=1`. It never contacts Telegram and
requires `GG_TG_FIXTURE_TEST_CHAT_ID` to exactly equal `GG_TG_CHAT_ID`; it cannot change any
Telegram membership. Its HTTP response and browser UI are labelled `test_only`.

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

## Intended admission lifecycle after Stage 5 approval

1. Configure one private group and Telegram-scoped gate per bot deployment. Independent gates
   use separate configuration/deployments; a gate identifier is never accepted from the browser.
2. The user sends `/join`; Telegram supplies the user identity and the bot mints a 10-minute,
   single-use token bound to it.
3. The browser completes a fresh gate proof. The bot obtains the receipt and access session from
   the bridge itself, checks the configured gate, then creates an expiring join-request invite.
4. Telegram delivers `chat_join_request`; only the bound user with a live server session is
   approved. Forwarded invites and wrong-chat requests are declined.
5. On expiry or registry revocation, the bot removes the member with a temporary 60-second ban
   followed by unban. If unban fails, the ban still expires automatically rather than becoming
   permanent. A bridge outage defers removal rather than guessing.

Before enabling this lifecycle, retain the raw genuine 12634-to-12635 checkpoint evidence, verify
it from the reviewed anchor, and obtain explicit operator approval for the production root and
membership change.
