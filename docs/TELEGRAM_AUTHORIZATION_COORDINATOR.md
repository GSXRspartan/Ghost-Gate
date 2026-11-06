# Telegram authorization coordinator (M4-B1)

This is a standalone persistence component, not a Telegram admission protocol. It has no HTTP,
Telegram, browser, wallet, or administrator-registry integration. Real admission remains disabled.

## Trust boundary

The future server must authenticate the bot and obtain numeric user/chat IDs and policy from
trusted sources before calling `issue`. It must check the current gate policy, network, chain
evidence and Tari wallet signature before calling the crate-private
`mark_verified_by_trusted_verifier`. That method is a trusted internal operation, not a wallet
verifier or an authentication mechanism. Do not expose it to browser requests. The coordinator
does not independently validate the wallet, authenticate Telegram, authenticate receipts, or
prevent a compromised process with database write access from changing records.

The coordinator issues independent 32-byte random session IDs and challenge nonces. Records
contain numeric user/chat IDs, gate, policy hash, network, resource, threshold, nonce, issue and
expiry times, and the output recorded by the trusted verifier. `redeem` requires the exact
server-expected context and output. The caller must derive those expected values independently,
not accept them as authoritative merely because a browser supplied them.

## Transaction and recovery semantics

- `create_new` uses exclusive file creation and initializes schema version 1 in a SQLite
  `BEGIN IMMEDIATE` transaction. It refuses existing files, including empty or incompatible files.
- `open_existing` opens in SQLite `mode=rw`, refuses missing/empty files, checks SQLite integrity,
  application ID, schema version and required columns, and does not reset or migrate state.
- `issue` inserts a CREATED record atomically. SQLite enforces a unique session ID.
- Verification and redemption use `BEGIN IMMEDIATE` and a conditional `UPDATE` matching session,
  exact context, expected prior state, and output. SQLite commits the update as one transaction;
  concurrent processes cannot both redeem the same VERIFIED record. Expiry is checked after the
  write lock is acquired. A failed condition leaves the record unchanged.
- Explicit expiration is an atomic conditional update to EXPIRED. A record at or beyond expiry
  cannot be verified or redeemed, even before the EXPIRED state is persisted. REDEEMED and EXPIRED
  are terminal. A refused mismatched request does not destroy another user's valid record.
- SQLite `synchronous=FULL` is set per connection. Durability depends on the OS and filesystem
  honoring SQLite locking, atomicity and sync guarantees. The system clock must be trustworthy;
  wall-clock rollback across operations is not independently detected. A crash between exclusive
  file creation and schema initialization can leave an empty/uninitialized file; startup fails
  closed and never deletes or repairs it automatically.

The prior bridge replay store is separate and retains its own age-based locking behavior. It is
not used as this coordinator's transaction boundary. Do not mix database implementations or
versions against the same file without a separately reviewed migration.

## Filesystem requirements

Use a dedicated local SQLite database on a filesystem with reliable SQLite file locks and durable
sync semantics. Do not place it on network, shared Windows/WSL, or otherwise unverified filesystems.
On Unix, create a service-owned directory with mode `0700`; `create_new` creates the database with
mode `0600`. The process umask and directory ACL must also protect SQLite journal, WAL and shared
memory files. On Windows, configure an equivalent restrictive directory and file ACL before use;
the coordinator does not configure Windows ACLs. Do not share the directory with the public web
server or administrator registry. Root/operator backups must protect the database and all
associated SQLite files. Use a SQLite-consistent backup or stop all writers before taking a file
copy; never copy a live database while omitting its journal/WAL state. Do not restore an older
database over newer redemption state: doing so may permit replay. Restore only through an
independently designed monotonic recovery procedure.

Use a fresh dedicated path when explicitly initializing. If initialization fails or an existing
database is corrupt, unavailable, or has an unknown version, stop and preserve the file for
operator investigation. There is no in-memory fallback, automatic repair, migration or deletion.

## Evidence and limitations

Tests use randomly named local temporary directories and synthetic identities. They cover reopen,
verified-state recovery, wrong identity/chat/context/output, unverified and expired denial,
single-use redemption, threads and separate processes racing against independent SQLite
connections, abrupt process exit during a transaction, and missing/empty/corrupt/incompatible
storage. These tests do not prove behavior on a particular production filesystem, power failure,
malicious disk edits, clock rollback, the full wallet protocol, or Telegram authorization.
