# Changelog

## Unreleased

- Reject passkey enrollment when challenge/session deadlines expire during final
  database writes; consume only after key/audit insertion and roll back expired
  work for both mailbox and passkey-required accounts (AUTH-53).

- Native platform/USB passkey signup through real SMTP contact confirmation,
  preserved identity/provenance, rotated sessions and subsequent passkey login;
  separate owned-database/Mailpit browser suite also runs in CI (AUTH-53).

- Experimental verified contact attachment for email-free passkey-required accounts:
  independent mailbox proof plus fresh passkey session, preserved identity/policy,
  atomic session rotation and typed audit, with PostgreSQL race/rollback/expiry and
  HTTP captured-mail tests. SMTP/native attachment evidence remains pending (AUTH-53).

- Experimental anonymous passkey signup HTTP routes and complete OpenAPI, with
  session-confusion guards and eleven Chromium resident platform/USB signup cases,
  later bound/discoverable login and native negative proofs. Verified-mailbox
  attachment and full stronger-account recovery remain in progress (AUTH-53).

- Optional core/PostgreSQL email-free signup with separate registration/assertion
  stages, bounded pending state, one-use atomic account/key/session/audit creation
  and final post-write expiry checks. HTTP/native signup and mailbox attachment
  remain in progress (AUTH-53).

- Optional verified mailbox and display-label model, nullable user API/OpenAPI,
  explicit passkey-required account policy, no-email session controls and locked
  denial of weaker login/reset/lifecycle paths. Anonymous signup and contact
  attachment remain in progress (AUTH-53).

- Experimental passkey HTTP sign-in and atomic PostgreSQL challenge/key/session/audit transactions, with owner/realm/browser binding, counter/backup/context policy and explicit session methods. Twenty Chromium cases cover registration, real assertions and modal resident discovery; stronger-account policy and passkey-first enrollment remain unfinished (AUTH-19).

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
