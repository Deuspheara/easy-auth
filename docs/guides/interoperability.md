# Interoperability evidence

| Feature | Automated evidence | Manual/external evidence | State |
|---|---|---|---|
| Email proof and sessions | Real PostgreSQL, Axum HTTP, concurrent consumption, rollback, expiry, tenant isolation, bounded session inventory, individual/all-session revocation and deterministic login/revocation ordering tests | Local SMTP through Mailpit smoke script | Alpha slice implemented |
| Password enrollment/sign-in | Argon2/profile/Unicode/corpus/capacity tests; real PostgreSQL enrollment race, rollback, stale credential and realm tests; HTTP generic rejection and disabled configuration | Real SMTP email-to-password smoke in standalone and embedded protected-route example | Opt-in headless alpha; authenticated password change incomplete |
| Password recovery | Bound/versioned proof, replay/expiry/purpose, concurrent reset, rollback and notification lease/retry/exhaustion tests | Actual SMTP and non-secret notification worker in both compositions | Alpha mailbox recovery; stronger-factor recovery not approved |
| Email change/account deletion | Both-address proof, freshness/rotation, uniqueness races, rollback, cleanup/deidentification and cross-user/realm tests | Actual SMTP confirmations/notices in both compositions | Alpha lifecycle; application data/backup deletion outside auth scope |
| Embedded vs standalone | Same Auth use cases/router; compiled custom protected-route example | Fresh contributor walkthrough pending | Implemented shared composition |
| Passkey registration | Real PostgreSQL attack/concurrency/rollback corpus; experimental HTTP boundary/contract; eight real Chromium virtual-authenticator cases | No real-device evidence | Experimental opt-in only; ordinary composition disabled |
| Passkey sign-in and modal discoverability | Real signed protocol/database corpus, experimental HTTP contract and native Chromium platform/USB assertions, resident discovery, signed context/backup/counter checks | No real-device evidence | Explicit experimental composition; ordinary activation gated |
| Stronger-account management and recovery | Not implemented yet | None | AUTH-20; ordinary activation blocked |
| Verified contact attachment | 15 PostgreSQL binding/race/rollback/expiry/migration tests, 3 captured-mail HTTP cases and 2 native platform/USB signup-to-real-SMTP confirmation cases | No real-device or other-browser evidence | Experimental signup composition only; ordinary activation gated through AUTH-20 |
| Email-free passkey signup | Two-stage core/PG proof and concurrency/rollback/expiry corpus; strict opt-in HTTP; 11 Chromium anonymous resident platform/USB signup cases plus later bound/discoverable login | No real-device evidence | Experimental; full stronger-account lifecycle/recovery unfinished |
| Google/Apple web/native | None yet | None | M04 required; unavailable |
| Enterprise OIDC client | None yet | None | M05 required; unavailable |
| SAML SP | None yet | None | M06 hard validator/security blocker; unavailable |
| Outbound OIDC issuer | None yet | None | M07 release blocker; unavailable |

A Rust HTTP router test is not a real-browser WebAuthn test. The default suite needs no external production credentials. Full release requires virtual authenticators plus platform/roaming real devices, actual Apple/Google web/native checks, local Keycloak OIDC/SAML and independent outbound OIDC client tests. Entra/Okta configuration docs are not proof of tested interoperability.

## Recorded registration browser run — 2026-10-19

[Sanitized run record](../../tests/browser/passkeys/results/2026-10-19/chromium.json)
from producer `05ed2cd0e8292662a7654ffc847945e554ab6ec3`: Playwright 1.62.1,
Chromium 151.0.7922.34, Node 24.21.0, Rust 1.95.0, arm64 macOS and PostgreSQL
17.11. All 149 recorded source hashes match that committed producer. The fixture
was freshly built from that source and its executable hash is recorded; this is
not a reproducible-binary-build claim.

| Environment/boundary | Evidence | State |
| --- | --- | --- |
| Chromium virtual CTAP2 internal/platform | Actual `navigator.credentials.create`, JSON round trip, HTTP/PostgreSQL registration and replay rejection | Passed |
| Chromium virtual CTAP2 USB/roaming | Actual registration, replay rejection and browser-binding isolation | Passed |
| Challenge/origin/RP/UV/CSRF | Tampered client data rejected with valid controls; browser rejects unrelated RP; server rejects bad UV; actual cross-origin POST returns 403 through CDP network observation | Passed in the recorded cases |
| Firefox and Safari | No run | Untested |
| Real platform or roaming devices/provider-backed passkeys | No manual run | Untested; M03 gate |

Eight named cases each finish a valid registration control: eight stored
credentials, eight audit facts and no remaining pending state. The fixture's exact
disposable database was removed, with an independent PostgreSQL check finding no
browser-fixture databases afterward. Identity/session setup uses the repository's
verified fixture transaction; this browser run does not replace SMTP/signup tests.
No browser storage, trace, cookie, protocol payload or virtual private key is
stored in the record. [Reproduction instructions](../../tests/browser/passkeys/README.md).

## AUTH-19 assertion browser boundary

The [sanitized assertion run](../../tests/browser/passkeys/results/2026-10-19/chromium-authentication.json)
uses committed producer `235a2c300915cd05a0d6d6f92f39ccfd141e63ef`, freshly built on
arm64 macOS with Node 24.21.0, Rust 1.95.0 and PostgreSQL 17.11. All 184 source
fingerprints were independently checked against that commit, and the executable
hash matches the recorded binary. This is source/run provenance, not a reproducible
binary or independent-audit claim. An independent PostgreSQL catalog read found
zero browser-fixture databases after removal.

The expanded suite uses pinned Playwright 1.64.1 / Chromium 156.0.8078.4. Twenty
cases exercise real HTTP/PostgreSQL registration and assertions, including internal
and USB nonresident account-bound login, modal resident discovery with a native
owner handle, UP/UV/signature rejection, replay, missing binding, signed cross-origin
iframe rejection, BE-upgrade rejection, eligible BS update and real signed zeros.
It requires twenty credentials/enrollment audits, thirteen authentication audits
and sessions, twenty-three admitted finish attempts and exact database cleanup.

The zero case first rejects zero against stored nonzero metadata, then explicitly
arranges trusted stored-zero metadata for an unused native-created test credential
through one private fixture stdin command. Actual key/signature/session code stays
unchanged; its two signed zero assertions use separate one-use challenges. This
does not establish counterless native enrollment, real hardware, other browsers or
conditional-autofill UI. [Fixture details](../../tests/browser/passkeys/README.md).

## AUTH-53 anonymous signup boundary — 2026-10-19

The expanded native suite passes 31 Chromium virtual-authenticator cases: the
previous 20 plus 11 anonymous signup cases. New contexts carry no seeded session
and retain the ORIGINAL resident/required-UV options. Platform/internal and roaming/
USB keys complete registration, a separate signed assertion, protected null-email
user retrieval, then account-bound and modal discovery sign-in. Other new cases
cover registration challenge/origin/RP/UV, signed assertion UP/UV/signature, replay,
wrong browser/existing-session confusion and genuine signed cross-origin context.
Counts are 31 credentials, 20 enrollment audits, 11 email-free passkey-required users/
signup audits, 17 authentication audits, 28 total passkey sessions, 27 authentication
finish admissions, 33 signup finish admissions and zero pending rows. The prior
counterless test's one trusted storage setup remains limited to its old seeded
account; anonymous signup has no such setup or preissued session. No private key
is exported. Physical authenticators, other browsers, verified contact attachment
and stronger-account recovery remain separate gates.

The [canonical signup record](../../tests/browser/passkeys/results/2026-10-19/chromium-signup.json)
records producer `d217189ac92c0bc599ff304ab072551835ad1ee9`, 224 verified source
hashes, the actual executable hash and successful exact database cleanup.

## Native SMTP contact attachment — 2026-10-19

The separate two-case [canonical record](../../tests/browser/passkeys/results/2026-10-19/chromium-email-attachment.json)
uses Chromium156.0.8078.4/Playwright1.64.1 with PostgreSQL17.11 and Mailpit1.27.11.
It proves anonymous native platform/USB signup through actual configured SMTP
contact confirmation, owner/provenance preservation, session rotation, occupied
address and independent-browser rejection, and subsequent bound/discoverable login.
All268 source hashes match immutable producer c13d7de; the binary hash is recorded.
No seeded sessions, key metadata mutation or capturing mail adapter is used. Its
owned DB and three messages are removed. This resolves the earlier attachment
checkpoint; physical devices, other browsers and AUTH-20 recovery remain open.
See the [reproduction guide](../../tests/browser/passkeys/attachment/README.md).
