# Interoperability evidence

| Feature | Automated evidence | Manual/external evidence | State |
|---|---|---|---|
| Email proof and sessions | Real PostgreSQL, Axum HTTP, concurrent consumption, rollback, expiry, tenant isolation and logout tests | Local SMTP through Mailpit smoke script | Alpha slice implemented |
| Password enrollment/sign-in | Argon2/profile/Unicode/corpus/capacity tests; real PostgreSQL enrollment race, rollback, stale credential and realm tests; HTTP generic rejection and disabled configuration | Real SMTP email-to-password smoke in standalone and embedded protected-route example | Opt-in headless alpha; authenticated password change incomplete |
| Password recovery | Bound/versioned proof, replay/expiry/purpose, concurrent reset, rollback and notification lease/retry/exhaustion tests | Actual SMTP and non-secret notification worker in both compositions | Alpha mailbox recovery; stronger-factor recovery not approved |
| Email change/account deletion | Both-address proof, freshness/rotation, uniqueness races, rollback, cleanup/deidentification and cross-user/realm tests | Actual SMTP confirmations/notices in both compositions | Alpha lifecycle; application data/backup deletion outside auth scope |
| Embedded vs standalone | Same Auth use cases/router; compiled custom protected-route example | Fresh contributor walkthrough pending | Implemented shared composition |
| Passkeys | None yet | None | M03 required; unavailable |
| Google/Apple web/native | None yet | None | M04 required; unavailable |
| Enterprise OIDC client | None yet | None | M05 required; unavailable |
| SAML SP | None yet | None | M06 hard validator/security blocker; unavailable |
| Outbound OIDC issuer | None yet | None | M07 release blocker; unavailable |

A Rust HTTP router test is not a real-browser WebAuthn test. The default suite needs no external production credentials. Full release requires virtual authenticators plus platform/roaming real devices, actual Apple/Google web/native checks, local Keycloak OIDC/SAML and independent outbound OIDC client tests. Entra/Okta configuration docs are not proof of tested interoperability.
