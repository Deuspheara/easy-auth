# Changelog

## Unreleased

- Bounded owned-session inventory and fresh-authenticated individual/all-session revocation, including pending-proof cancellation and concurrent-login ordering guarantees (AUTH-15).

- Maintainability rules and feature-organized core, PostgreSQL, HTTP, server and integration-test modules, preserving existing authentication behavior and contracts (AUTH-52).
- Initial research, architecture and threat model.
- Shared Rust email/session alpha slice, generated OpenAPI, SMTP and embedded/standalone examples; 13 automated tests plus local SMTP/browser checks.
- Opt-in verified password enrollment and sign-in: NFC/long Unicode input, local compromised-password policy, bounded Argon2id, shared admission and transactional session replacement (AUTH-12).
- Purpose-bound password recovery with transactional credential/session/proof invalidation and durable, leased non-secret notifications (AUTH-13).
- Both-address verified email changes and confirmed account deletion, authenticated-at provenance, scoped cleanup/deidentified audit and shared non-secret security notices (AUTH-14).
- No production release, SAML, passkey, social or OIDC compliance claim.
