# M2 membership safety and remaining security work

Baseline: audit commit `6c878d9`. This document describes local code only; no live settings,
membership, invitations, credentials, or databases were changed.

## Current local containment

Real Telegram claim and join-request approval are disabled until a durable proof binds the numeric
Telegram user and chat to the wallet-signed challenge. A shared accepted proof and a legacy in-memory
grant cannot create a real admission. The isolated fake-Telegram fixture remains available for tests.
The real Telegram test mode is also denied fixture admissions. Existing Telegram memberships are not
removed when a tracked authorization expires or is revoked. Bridge outages retain existing grants.

This is containment, not completion of the identity-binding protocol. It prevents new legitimate
bot-controlled admissions too. It does not prove ownership of existing memberships, restore forgotten
authorizations, protect against other administrators, or separate bridge and admin stores. Do not
deploy as a production-ready resolution.

## Membership and state inventory

`Bot::tick` previously called `remove_member`, which called `kick_member` (Telegram
`banChatMember`, then `unbanChatMember`). An ambiguous failure queued another unban. The patched
ticker no longer invokes either removal or unban, and no other normal event-loop path calls them.
The low-level API methods still exist and must be separately reviewed before any future feature
uses them. No automatic membership revalidation/removal feature is enabled.

`claim` creates an invite, consumes a join token, and inserts a grant; the real path now stops before
these actions. `handle_join_request` may decline an unverified pending request; that is not removal of
an existing member. It cannot approve real requests in this local version. `/join` can mint in-memory
tokens, and `tick` expires tracked grants and tokens; neither changes Telegram membership. A failed
bridge check on `/join` no longer discards a stored grant.

The bot has no durable grant, token, update-offset, or user/session database. On restart those
in-memory records disappear. Bridge registry, sessions, bindings, generation ledger and replay
store are separate persistent security records; they do not contain a complete Telegram identity
mapping. No migration in this patch touches them. The existing backup script archives registry and
replay data, but not bot memory. A backup taken after a restart cannot reconstruct that missing map.

## Legacy members and migration

Existing members, including the operator, spouse, and 0xHRA, remain members whether or not their
historic proof can be reconstructed. Missing or corrupt authorization state must be treated as
unknown, not as a reason to remove someone or approve a new request. Do not infer wallet ownership
from usernames, Telegram membership, or old proof IDs. A future opt-in re-verification can create a
new record without changing membership; do not issue removals automatically.

The durable design must version records, write atomically, refuse corrupted or unknown versions,
preserve original files, and bind numeric user ID, chat ID, gate, policy hash, network, expiry and a
single-use server challenge to the wallet signature. The commitment must be verified and consumed
atomically across restarts. Import only verifiable records, retain the originals, and explicitly mark
unverifiable legacy memberships as unknown. Add restart, crash, corruption, replay, two-account,
concurrent claim, and rollback tests before considering deployment.

Other administrators can add members or issue links outside the bot. Review admin roles and invite
links with the operator; no bot can guarantee prevention while another administrator retains that
authority. Detection should use `chat_member` updates and durable audit/reconciliation; it must
alert only, with no automatic removals. Review Telegram platform behavior in an isolated test group.

## Bridge/admin boundary

The bridge still reads `registry.json` through `AccessPlane`, including admin session tokens, CSRF
values and step-up state, and its service has shared registry directory access. Public HTTP route
checks do not protect these secrets if the bridge process is compromised. A durable fix needs a
separately permissioned admin-auth store and a narrowly authenticated policy snapshot plus separate
session store, with atomic migration and concurrent writer handling. Merely clearing fields in memory
does not protect the file. This High issue remains open.

## Approval-gated deployment and rollback

Before any deployment, inventory current members and all administrator/invite paths read-only;
record service versions, configuration and file ownership; make a root-only backup of registry,
bindings, sessions, generation, replay, audit and halt state. Test a copy with representative
legacy records, including corrupt/missing state, on an isolated host and mock group. Verify all
existing mock members survive startup, expiration, restart, upgrade and rollback; verify no real
admission is approved. No complete migration or rollback simulation has yet been performed.

After explicit approval only, stage the binary and reviewed configuration, verify no member-changing
API calls, and compare group membership via an operator-controlled inventory. For rollback, stop the
new service and restore the exact recorded prior binary/configuration; retain current registry,
replay, generation, audit and halt data. **The prior binary contains automatic kick/ban behavior:**
keep it stopped or block its Telegram access until a separate reviewed containment is in place.
Rolling it back while active may remove members. Do not roll back security state or reset the group.

## Readiness

The local containment is not a full remediation of the three High findings. Identity binding,
durable restart recovery, out-of-band detection, bridge/admin store separation, and a full isolated
deployment/rollback simulation remain required. No claim is made that the current live deployment
has these protections. Deploying the containment would preserve existing memberships in its normal
paths but suspend new bot-controlled admissions; the previous binary's removal behavior makes
rollback unsafe without additional controls.
