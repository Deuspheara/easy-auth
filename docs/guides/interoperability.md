# Interoperability evidence

| Feature | Automated evidence | Manual/external evidence | State |
|---|---|---|---|
| Email proof and sessions | Real PostgreSQL, Axum HTTP, concurrent consumption, rollback, expiry, tenant isolation, bounded session inventory, individual/all-session revocation and deterministic login/revocation ordering tests | Local SMTP through Mailpit smoke script | Alpha slice implemented |
| Password enrollment/sign-in | Argon2/profile/Unicode/corpus/capacity tests; real PostgreSQL enrollment race, rollback, stale credential and realm tests; HTTP generic rejection and disabled configuration | Real SMTP email-to-password smoke in standalone and embedded protected-route example | Opt-in headless alpha; authenticated password change incomplete |
| Password recovery | Bound/versioned proof, replay/expiry/purpose, concurrent reset, rollback and notification lease/retry/exhaustion tests | Actual SMTP and non-secret notification worker in both compositions | Alpha mailbox recovery; stronger-factor recovery not approved |
| Email change/account deletion | Both-address proof, freshness/rotation, uniqueness races, rollback, cleanup/deidentification and cross-user/realm tests | Actual SMTP confirmations/notices in both compositions | Alpha lifecycle; application data/backup deletion outside auth scope |
| Embedded vs standalone | Same Auth use cases/router; compiled custom protected-route example | Fresh contributor walkthrough pending | Implemented shared composition |
| Passkey registration | Real PostgreSQL attack/concurrency/rollback corpus; experimental HTTP boundary/contract; eight real Chromium virtual-authenticator cases | No real-device evidence | Experimental opt-in only; ordinary composition disabled |
| Passkey sign-in, discoverability, passkey-first accounts and recovery | None yet | None | Remaining M03 work; unavailable |
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
