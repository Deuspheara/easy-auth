# Changelog

## Unreleased

- Initial research, architecture and threat model.
- Shared Rust email/session alpha slice, generated OpenAPI, SMTP and embedded/standalone examples; 13 automated tests plus local SMTP/browser checks.
- Opt-in verified password enrollment and sign-in: NFC/long Unicode input, local compromised-password policy, bounded Argon2id, shared admission and transactional session replacement (AUTH-12).
- Purpose-bound password recovery with transactional credential/session/proof invalidation and durable, leased non-secret notifications (AUTH-13).
- No production release, SAML, passkey, social or OIDC compliance claim.
