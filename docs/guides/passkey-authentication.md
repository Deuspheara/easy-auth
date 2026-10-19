# Experimental passkey sign-in

AUTH-19 provides optional account-bound and resident-credential sign-in through the
shared core, PostgreSQL and an explicit Axum router. Ordinary embedded/server
composition remains disabled while stronger-account management/recovery policy and
passkey-first enrollment are unfinished. This is alpha functionality, not an audited
identity service or an MFA/AAL compliance claim.

Enable `easy-auth-axum/passkey-authentication`. Construct `PasskeyEnrollment` and
`PasskeySignIn` with the same server-owned realm, `Arc<PasskeyService>` and
`Arc<Postgres>`, then pass both to `experimental_passkey_router(auth, browser,
enrollment, sign_in)`. Construction rejects mismatched realms or exact origins.
The router includes the ordinary API and experimental enrollment; its complete
[OpenAPI snapshot](../architecture/openapi-passkeys.json) is served at `/openapi.json`.
The enrollment-only feature/router remains available independently.

## Browser contract

POST `/v1/passkeys/authentication/start` with exact Origin, JSON and one of:

```json
{"mode":"discoverable"}
```

```json
{"mode":"conditional"}
```

```json
{"mode":"account_bound","account_id":"00000000-0000-0000-0000-000000000001"}
```

The last UUID is illustrative. Use an actual opaque owner ID from a remembered,
previously authenticated profile or an application-owned private account selector.
Only that account's credentials are selected; the hint never authenticates its
owner. This API does not resolve email addresses to credential lists. A new browser
with a nonresident key still needs that account-selection context. Avoid exposing
auth user IDs through public directories solely to implement this selector.

Start returns 200 `{transaction_id, options}` and sets/reuses a two-minute HttpOnly
`__Host-auth-passkey` binding cookie (development: `auth-passkey`). Convert
`options.publicKey` with `PublicKeyCredential.parseRequestOptionsFromJSON`, then
call `navigator.credentials.get` with the public key options. Pass through
`options.mediation` when present; conditional UI needs an appropriate autofill UI
and browser support. Modal discovery omits that hint. Account-bound options contain
an allow-list; resident discovery has an empty one and requires the browser's owner
handle. Native modal discovery is tested; actual conditional-autofill UI is not yet
in the browser matrix.

POST `/v1/passkeys/authentication/finish` with the same browser cookie and Origin:

```json
{"transaction_id":"00000000-0000-0000-0000-000000000002","credential":{}}
```

Replace the illustrative UUID and empty object with the start result and actual
`credential.toJSON()`. Successful completion returns 204 and a fresh Secure,
HttpOnly, SameSite=Lax session cookie with the existing seven-day absolute and
30-minute idle rules. No session secret appears in response JSON. Replay, invalid
proof, wrong browser/owner/realm, stale state and expiry return the same redacted
401. Unknown input fields/modes are 400; rejected Origin is 403; request size is
413; admission is 429. Experimental bodies are bounded to 32 KiB, decoded proof
buffers to 16 KiB. Ordinary endpoints retain their 8 KiB bound.

The shared browser binding survives one completion so other pending ceremonies
can finish. Logout revokes/clears the authenticated session; the short-lived binding
is cleared by current/all-session revocation or expires independently. Source IP
is an admission input, not an authentication factor.

For optional resident enrollment, send `{label, discoverable:true}` to enrollment
start, or use core `PasskeyEnrollment::begin_discoverable`. This explicitly requests
`residentKey=required`; ordinary enrollment still supports nonresident keys. It
does not mark unsigned `credProps` or successful creation as independently verified
residence metadata. An actual browser discovery assertion proves the usable path.

## Persistence and security policy

High-level webauthn-rs validates the key, signature, challenge, exact origin/RP,
UP, required UV and counters. The application additionally rejects signed
`crossOrigin=true`, any `topOrigin`, malformed context and duplicate context fields;
the pinned assertion path does not perform that context check. It preserves exact
ceremony and credential bytes and rechecks them under user/key/ceremony locks.
Expiry is checked in a new statement after any row wait. Consume, credential and
last-use update, new session and typed audit are one transaction, including rollback.

Nonzero counters must increase. Two zero counters are allowed; a nonzero-to-zero
reset is rejected. Backup eligibility is immutable; backup state may change for a
previously eligible credential. Each challenge has one winner; snapshot checks
prevent overwriting intervening credential changes. Start a fresh ceremony after
a stale attempt. Separate valid ceremonies can create separate sessions. Private state stays in
PostgreSQL, bounded to 1 MiB; there are at most three pending ceremonies per browser,
with separate start/finish budgets of 20/browser and 40/source per ten minutes.

Session method provenance records real email/password/passkey proof and preserves
unknown historical methods and rotation time/method. It does not yet enforce
stronger-account recovery or sensitive-action policy. Normal activation remains
gated; email-free bootstrap belongs to AUTH-53 and management/recovery to AUTH-20.
Other browsers, real devices/provider-backed passkeys and operational retention
remain release work. See the [source review](../research/passkey-authentication.md)
and [browser evidence](../../tests/browser/passkeys/README.md), including the explicit
trusted-storage setup used for the signed zero-counter acceptance test.
