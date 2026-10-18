# Interoperability evidence

| Feature | Automated evidence | Manual/external evidence | State |
|---|---|---|---|
| Email proof and sessions | Real PostgreSQL, Axum HTTP, concurrent consumption, rollback, expiry, tenant isolation and logout tests | Local SMTP through Mailpit smoke script | Alpha slice implemented |
| Embedded vs standalone | Same Auth use cases/router; compiled custom protected-route example | Fresh contributor walkthrough pending | Implemented shared composition |
| Passkeys | None yet | None | M03 required; unavailable |
| Google/Apple web/native | None yet | None | M04 required; unavailable |
| Enterprise OIDC client | None yet | None | M05 required; unavailable |
| SAML SP | None yet | None | M06 hard validator/security blocker; unavailable |
| Outbound OIDC issuer | None yet | None | M07 release blocker; unavailable |

A Rust HTTP router test is not a real-browser WebAuthn test. The default suite needs no external production credentials. Full release requires virtual authenticators plus platform/roaming real devices, actual Apple/Google web/native checks, local Keycloak OIDC/SAML and independent outbound OIDC client tests. Entra/Okta configuration docs are not proof of tested interoperability.
