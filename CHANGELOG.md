# Changelog

## Unreleased

- Experimental passkey registration through the high-level verifier, atomic PostgreSQL ceremonies, explicit Axum opt-in, a concrete OpenAPI extension and reproducible Chromium platform/USB virtual-authenticator checks. Ordinary server enrollment remains disabled pending passkey sign-in and stronger-account policy (AUTH-18).

- Reproducible native PostgreSQL adoption probes with pinned RustAuth/lucid-auth sources, resolved feature graphs, binary/RSS measurements and post-return revocation checks under sustained other-user load; corrected RustAuth's maintenance status in the research and build decision (AUTH-5).

- Typed lifecycle audit facts with owned actor/session attribution, historical provenance, transactional deletion redaction and an explicit two-identity linking policy; logout lock order aligned with audit ownership checks (AUTH-16).

- Bounded owned-session inventory and fresh-authenticated individual/all-session revocation, including pending-proof cancellation and concurrent-login ordering guarantees (AUTH-15).

- Maintainability rules and feature-organized core, PostgreSQL, HTTP, server and integration-test modules, preserving existing authentication behavior and contracts (AUTH-52).
- Initial research, architecture and threat model.
- Shared Rust email/session alpha slice, generated OpenAPI, SMTP and embedded/standalone examples; 13 automated tests plus local SMTP/browser checks.
- Opt-in verified password enrollment and sign-in: NFC/long Unicode input, local compromised-password policy, bounded Argon2id, shared admission and transactional session replacement (AUTH-12).
- Purpose-bound password recovery with transactional credential/session/proof invalidation and durable, leased non-secret notifications (AUTH-13).
- Both-address verified email changes and confirmed account deletion, authenticated-at provenance, scoped cleanup/deidentified audit and shared non-secret security notices (AUTH-14).
- No production release, SAML, passkey, social or OIDC compliance claim.
