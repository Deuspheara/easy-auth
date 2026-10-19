# Experimental passkey signup core

The optional core/PostgreSQL signup flow creates an account without email, but
only after registration **and** an independently verified assertion. It is not yet
mounted by an HTTP router or the standalone service. Anonymous Chromium signup,
verified-mailbox attachment and AUTH-20's stronger-account management/recovery
remain required before ordinary activation. No real-device or production claim.

## Shared-core sequence

Enable `easy-auth-core/passkeys` and `easy-auth-postgres/passkeys`, migrate through
`0010_passkey_signup.sql`, and explicitly compose `PasskeySignup::new` with the
trusted realm, configured `PasskeyService` and PostgreSQL repository. The service
uses the same exact RP/origin and high-level verifier as existing enrollment/login.
Generate a browser-binding `Secret` on the server; never accept a proposed user,
realm, origin, RP or private ceremony state from the client.

1. `begin(display_name, browser, source)` chooses random prospective-user and
   transaction UUIDs and persists a registration-stage row. It returns native
   creation options requesting residence and required UV. Send only those public
   options and the transaction ID to the browser.
2. `finish_registration(browser, source, transaction, credential)` verifies the
   browser's registration through the high-level service. One atomic stage change
   freezes the verified candidate and an account-bound assertion challenge, and
   clears the registration state. It returns public request options. There is
   still no durable user, account credential, authenticated session or success audit.
3. `finish(browser, source, transaction, assertion)` verifies genuine private-key
   proof, required UP/UV, RP/origin/context, challenge, owner, counter and backup
   state. Under the pending-row lock, the transaction rechecks exact state/candidate
   snapshots and inserts an email-free `passkey_required` user, its updated key,
   a fresh passkey-method session and `passkey_signed_up` audit fact. Final one-use
   consumption checks database time after **all** potentially blocking writes,
   including audit. Any failure rolls back every insert and consumption together.

The returned session `Secret` is available only after commit. Use the existing
session validation to retrieve the opaque user, `email: null` and display label.
Later account-bound login reuses the stored credential normally; modal discovery
depends on an actually resident credential. Registration residence is a browser
requirement, not independently verified server metadata.

The provisional UUID is not an existing-account selector. A collision with an
existing owner or a credential already owned anywhere under the same RP rejects
signup without logging into, linking, merging or transferring that account/key.
The display name is bounded presentation text, not identity or authorization.
See [optional mailbox and account policy](optional-mailbox.md).

## State, expiry and abuse bounds

Signup has a dedicated table and explicit registration/assertion stages; existing
enrollment and authentication ceremonies cannot complete it. Private registration
and assertion encodings remain server-side, bounded to 32 KiB and 1 MiB; candidates
are at most 64 KiB and IDs at most 1024 bytes. Types redact Debug and expose no
general response serialization for private state or verified proof objects.

The two-minute expiry starts at persistence and is **not extended** at the stage
change. Each stage has one successful transition; one signup has one committed
account/session outcome. A lost final response cannot reuse the ceremony, but a
committed credential can authenticate again. Failed persistence/audit permits a
valid retry while the same pending proof is live. Expired/failed signup may leave
an authenticator-side credential with no server account; remote key deletion is
not claimed.

Starts allow 10/browser and 20/source per realm per fixed ten-minute window.
Both completion stages share 20/browser and 40/source admission, committed before
state lookup and protocol verification, including absent/malformed attempts.
Source is abuse metadata, not an authentication factor. There are at most three
pending rows per browser and 256 per realm. A realm-scoped advisory lock serializes
capacity checks and creation. Each start reclaims that realm's expired rows;
expiry alone does not physically erase rows while the realm is idle. Retained
pending state stays bounded. Broader operational retention and load evidence
remain release work.

## Evidence and remaining boundaries

Real PostgreSQL tests cover signed two-stage completion, later account-bound
authentication, stage/browser/realm/RP binding, exact snapshots, replay/concurrency,
identity/key collisions, rollback, pending/admission limits, schema upgrade and
expiry during observed unchanged-row, key-uniqueness and final-audit waits.

The pinned test-only SoftToken explicitly rejects residence. Its fixture first
asserts that production options request residence, then changes only the software
client's residence hints. It leaves private server state, challenge, RP, required
UV and production verification intact. These are real signed **nonresident**
proof/transaction tests, not native residence or discovery evidence. The missing
anonymous platform/roaming Chromium flow must use the original production options.

HTTP signup composition/contracts and browser tests are the next AUTH-53 boundary.
Mailbox attachment still requires fresh passkey control plus a separate verified
target-mailbox proof without weakening account policy. General lifecycle/recovery,
other browsers and real devices remain open. See [ADR 0009](../architecture/adr/0009-passkey-first-identity.md).
