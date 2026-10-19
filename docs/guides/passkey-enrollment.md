# Passkey enrollment implementation boundary

AUTH-18 is complete. The optional core/PostgreSQL enrollment path persists
and verifies registration ceremonies. An explicit experimental HTTP composition
and Chromium virtual-authenticator tests are implemented; normal embedded/server
composition does not enable it. Experimental [passkey sign-in](passkey-authentication.md)
now includes native assertions and modal residence checks. [Passkey-first signup](passkey-signup.md)
also has native/SMTP evidence; credential management and reviewed stronger-account
recovery remain M03 requirements.

## Core and persistence

Enable `easy-auth-postgres/passkeys` to compile the adapter and core feature.
Construct a `PasskeyService` with one exact HTTPS origin and RP display name; RP ID
is the origin hostname. `for_local_development` permits only explicit localhost
development, including the configured port. Provide the shared `Postgres` adapter
and server-owned realm to `PasskeyEnrollment::new`. The feature-specific repository
port keeps protocol persistence out of HTTP and avoids expanding the email/password
repository with conditional methods.

`begin` requires an authenticated session secret, a separate browser-binding secret,
a trusted source identifier and a user-supplied credential label. The adapter
selects the owner from the realm/session; clients cannot nominate a user or RP.
The label is bounded to 256 UTF-8 bytes and rejects empty/control-character input.
The returned transaction UUID and public creation options are safe browser inputs;
the paired private state stays exclusively in PostgreSQL. `begin_discoverable` (HTTP
`discoverable:true`) explicitly requests resident-key creation without treating
creation or unsigned client extension results as verified residence metadata.
No session secret,
browser secret or state belongs in a URL or application log.

`finish` loads only the current session/browser/realm-bound transaction, verifies
the authenticator response with the high-level library, and then revalidates under
user-before-session locks. It compares the exact verified state encoding, checks
ownership and credential limits, locks the pending state, inserts the unique
credential and records the typed `passkey_enrolled` audit fact, then performs final
expiry/freshness validation and consumption in the same transaction.
A failed insert or audit rolls everything back. Successful completion returns an
opaque credential UUID, not a new authenticated session.

The public response envelope must use type `public-key`, with canonical credential
ID/raw ID matching the ID verified from attested data. Credential IDs are at most
1024 bytes; ceremony payload buffers are bounded to 16 KiB in the verifier. An HTTP
adapter still needs its own total encoded-body bound, CSRF/origin checks and cookie
policy; the core buffer bound does not replace transport protections.

The final PostgreSQL transaction keeps the owner, initiating session and pending
ceremony locked through credential/audit writes. Final one-use consumption checks
exact ceremony binding/state and current database time **after** those writes,
including credential-uniqueness and audit waits. It independently rechecks original
session authentication freshness, idle/absolute expiry and revocation. Deadline
failure rolls back the new key, audit fact and consumption together. Policy is
validated under the held owner/session locks; rotation never refreshes proof time.

## Limits and lifecycle

| Policy | Implemented boundary |
| --- | --- |
| Fresh authentication | Within five minutes, rechecked after acquiring locks |
| Session validity | Not revoked; existing 30-minute idle and seven-day absolute policies |
| Enrollment lifetime | Two minutes, enforced by database wall time at load and commit |
| Pending ceremonies | At most three per realm/user; expired owned rows removed on a new start |
| Credentials | At most ten per realm/user/RP, rechecked under the owner lock |
| Start admission | Ten per user and forty per source per realm/ten-minute window |
| Finish admission | Twenty per user and forty per source per realm/ten-minute window |

Failed verification spends the committed finish budget. Source identifiers are
admission inputs, not authentication factors: derive them from trusted transport
context and do not trust a body field or unconfigured forwarded header. Admission
uses shared PostgreSQL state across replicas. Ordinary account deletion cascades
credentials and pending state, removes owned admission buckets and deidentifies
audit attribution. Source admission remains independent abuse metadata. Revoke-all
also cancels pending enrollment; other session revocations make its bound ceremony
unusable immediately on subsequent validation. Expiry denies use, but does not
promise immediate physical erasure; operational retention is still a release gate.

The unique `(rp_id, credential_id)` constraint spans accounts and realms sharing an
RP. Exclusion lists improve browser behavior but cannot enforce ownership by
themselves. Stored credentials preserve the library's public-key/counter/backup
state, alongside label, RP and creation time. No manufacturer/hardware guarantee
follows from ordinary no-attestation enrollment.

Enrollment preserves the initiating session's existing assurance and authentication
time. It does not silently upgrade a mailbox session to passkey assurance. Normal
server composition stays disabled until sign-in and the stronger-account policy
prevent mailbox/password recovery from bypassing a stronger account. Passkey-first
accounts require a real account-model/enrollment change, not a placeholder email.

## Verification and remaining work

Run the real database cases with:

```sh
cargo test --locked -p easy-auth-postgres --features passkeys --test lifecycle passkeys::
```

Tests generate real signed packed-attestation fixtures using the pinned
`webauthn-authenticator-rs` software token. Its simulated UV is test-only. They
exercise valid registration plus wrong challenge/origin/RP/UV, an unsigned
attestation missing UP, corrupted packed signatures, contradictory envelope IDs,
replay, ownership/session/browser/realm mismatch, expiry, rollback, duplicate RP
ownership, concurrent last-slot completion, deletion and freshness/expiry changes
after an observed PostgreSQL lock wait. Positive controls retain the valid response
for each protocol negative. No custom cryptographic primitive or verifier is used.

The separate [Chromium suite](../../tests/browser/passkeys/README.md) exercises
actual `navigator.credentials.create` with platform/internal and roaming/USB virtual
authenticators through the experimental HTTP endpoints. Its eight cases cover
registration/replay, tampered client challenge/origin, RP scoping, required UV,
an actual cross-origin POST and another browser missing the binding cookie.
Each case has a successful registration control; aggregate credentials and audit
facts must match, pending state must be empty, and the disposable database must be
removed. This establishes that specific virtual-browser boundary, not real-device,
Safari/Firefox or recovery interoperability. AUTH-19 extends the suite with native
assertions and modal resident discovery, documented in the sign-in guide.

The `passkey-enrollment` Axum feature exports an explicitly named experimental
router. It validates matching configured realm/origin, retains the base API and
serves a combined OpenAPI document. Start sets/reuses an HttpOnly binding cookie;
finish returns only the credential UUID. It is not wired into the ordinary server.
See the [concrete HTTP contract](../architecture/api-contract.md#explicit-experimental-passkey-enrollment),
[ADR 0008](../architecture/adr/0008-passkey-verification-boundary.md),
the [source review](../research/passkey-enrollment.md) and
[dependency notices](../security/third-party-licenses/webauthn.md).
