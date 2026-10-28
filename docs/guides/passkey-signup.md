# Experimental passkey signup

The optional core/PostgreSQL signup flow creates an account without email, but
only after registration **and** an independently verified assertion. Explicit
experimental Axum composition now exposes this flow, with real Chromium platform/
roaming virtual-authenticator signup and subsequent account-bound/discoverable login.
Verified contact attachment now has shared-core/PostgreSQL and experimental HTTP
implementation with database and captured-mail tests, plus native Chromium
platform/USB signup-to-SMTP confirmation evidence. Stronger-account
management/recovery remains required before ordinary standalone/server activation. No real-device or
production claim.

## HTTP composition and contract

Enable `easy-auth-axum/passkey-signup`. Compose the existing trusted realm,
`PasskeyService`, PostgreSQL repository, `Auth` and `BrowserConfig`, then construct
`PasskeyEnrollment`, `PasskeySignIn` and `PasskeySignup` with that same realm/service/
repository. Pass their Arcs to `experimental_passkey_signup_router(auth, browser,
enrollment, sign_in, signup)`. Startup rejects realm/origin disagreement in any
service. The normal server/router and earlier experimental constructors do not
automatically acquire signup routes. The browser fixture is a runnable composition
example, with its own disposable database; it is not a deployment server.

| POST path | JSON | Success |
| --- | --- | --- |
| `/v1/passkeys/signup/start` | `{display_name}` | 200 `{transaction_id,options}` with creation options; sets/reuses the independent HttpOnly passkey binding |
| `/v1/passkeys/signup/registration` | `{transaction_id,credential}` with native registration JSON | 200 `{transaction_id,options}` with assertion options; no account/session cookie |
| `/v1/passkeys/signup/finish` | `{transaction_id,credential}` with native assertion JSON | 204 with fresh HttpOnly session cookie after atomic verified completion |

Every POST requires the exact configured Origin and JSON, with a 32 KiB encoded
body bound. Outer objects reject unknown/duplicate fields, including owner/email/
RP inputs and attempts to disable resident options. Core decoded proof buffers
remain separately bounded. Only public options and transaction ID are returned;
private verification state stays server-side. The full merged [OpenAPI snapshot](../architecture/openapi-passkey-signup.json)
is served at `/openapi.json`; previous base/enrollment/authentication schemas are
preserved.

All three routes reject requests carrying **any** session cookie, including expired,
unknown, malformed or duplicate credentials. Call `POST /v1/logout` first to clear
an old cookie. This prevents signup from silently replacing an existing session.
Both completion stages also require the original passkey binding. The binding is
`__Host-auth-passkey` under HTTPS and `auth-passkey` in explicit localhost development,
with HttpOnly, SameSite=Lax, Path=/, no Domain, Max-Age=120 and Secure under HTTPS.
Registration completion neither refreshes the two-minute database expiry nor issues
a session. User retrieval becomes available only after the final verified assertion.

Errors use existing redacted codes/statuses: 400 invalid JSON/input, 401 rejected
session/binding/proof/stage/expiry/replay, 403 Origin, 413 body bound, 415 media,
429 admission/capacity, 503 unavailable and 504 timeout. No failed or rolled-back
operation emits a signup success fact. One-use is per pending transaction; separate
legitimate signup ceremonies have separate server-owned prospective identities.

## Shared-core sequence

Enable `easy-auth-core/passkeys` and `easy-auth-postgres/passkeys`, migrate through
`0011_email_attachment.sql`, and explicitly compose `PasskeySignup::new` with the
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
proof/transaction tests, not native residence or discovery evidence. Separately,
Chromium platform/internal and roaming/USB signup now uses the ORIGINAL production
resident options, without a seeded session, and proves later account-bound and
modal resident discovery. Eleven native signup cases include registration context/
RP/UV, assertion UP/UV/signature, replay, cross-browser/session confusion and an
actually signed cross-origin iframe context; valid controls still complete. They
are part of the 31-case [browser suite](../../tests/browser/passkeys/README.md).

The [contact attachment API](email-attachment.md) requires fresh passkey control
plus a separate verified target-mailbox proof without weakening account policy.
Its PostgreSQL/HTTP tests use controlled storage sessions and captured mail. A
separate [native SMTP suite](../../tests/browser/passkeys/attachment/README.md) now
proves anonymous platform/USB signup, real SMTP confirmation, preserved account
identity/policy and later passkey login. General lifecycle/recovery,
other browsers and real devices remain open. See [ADR 0009](../architecture/adr/0009-passkey-first-identity.md).
