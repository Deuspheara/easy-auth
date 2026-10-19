# Threat model — alpha design, before credential flows

Created 2026-10-18. Not a security audit. Assets: user identity, credential verifiers, active sessions, provider secrets/signing keys, email delivery and audit integrity. Actors: unauthenticated remote attacker, malicious browser origin, malicious configured/unconfigured IdP, compromised mailbox, compromised application/tenant, operator and stolen database/backup. Trust boundaries: browser/HTTP, core/persistence, outbound provider network, SMTP, configuration and application authorization.

| Threat | Required control | Evidence/release gate |
|---|---|---|
| Email account takeover / enumeration | Browser-bound single-use high-entropy proof; generic start response; no email auto-link; email compromise acknowledged | Expiry, mismatch, enumeration-shape and replay tests; stronger methods later |
| Login CSRF, CSRF, fixation | Exact Origin on every browser POST, HttpOnly host cookies, deliberate SameSite, fresh secret per authentication | Missing/null/wrong Origin, old cookie and duplicate-cookie tests |
| Session theft/replay | Only verifier in DB, idle+absolute expiry, DB validation, logout/revoke-all; TLS | DB expiry and immediate subsequent-request revocation tests; active bearer theft remains usable until revoked |
| Refresh theft | Atomic rotation and family reuse detection; secure native storage | Native release blocked pending replay tests |
| OAuth code injection/mix-up/state or nonce reuse | Connection+client+browser-bound expiring transaction, S256, issuer/nonce/audience/signature checks; atomic consume | M04/M05 wrong-state/nonce/issuer/audience/provider/replay corpus |
| Open redirect | Exact registered redirect allowlist; never redirect to arbitrary user input | M07 invalid redirect tests |
| Discovery/metadata SSRF | Explicit admin connections; HTTPS; DNS/IP/port allowlists, no redirects, bounded response, block private/link-local/metadata addresses unless explicit local test policy | M05 DNS rebinding/redirect/private-network tests |
| SAML signature wrapping/XXE/replay | Reviewed XML/signature engine; use only verified content; reject DTD/external entities/duplicate IDs, pinned certs, correlation and all conditions | Hard M06 blocker until signed fixture and attack corpus passes |
| RP/origin manipulation | Server-owned exact RP/origin, high-level webauthn-rs, UV, server-persisted single-use challenges | Core/PG/HTTP negatives and twenty Chromium virtual-authenticator registration/assertion cases; other browsers, real devices and stronger-account recovery remain gates |
| Unsafe linking / recovery downgrade | Fresh proof of both identities; no matching-email merge; last-credential and recovery policies; notifications/audit | M02/M03/M04 negative linking tests |
| Tenant isolation / privilege escalation | Realm on every query/constraint; trusted router realm; no app membership/permissions in auth core | Cross-realm FK/query tests; app independently authorizes actions |
| Brute force / spraying / mail abuse | Shared admission by realm+email and source IP; overall resource bounds; no trusted forwarded IP by default | Concurrent rate tests and load/retention plan |
| Secret leakage / compromised config | Redacted errors/logging, secret types, bounded audit events, least-privilege roles, protected keys, no query tokens | Log review/secret scan; M09 rotation and incident drills |
| Resource exhaustion | 8 KiB initial request bound, timeouts, bounded DB pool/SMTP and challenge admission | Oversize/timeout tests; M09 load evidence |
| Malicious connection disable/rollover race | Recheck connection status at commit; issuer/key binding; cert/key overlap policies | M05/M06/M07 concurrency and rollover tests |

A database writer or compromised server can mint/change identities; verifier hashing protects against read-only database theft, not a compromised verifier. Mailbox-only authentication has limited assurance and must not serve as an invisible bypass for stronger credentials. A stolen live cookie is a bearer credential. In-flight requests may finish after revocation; critical application actions require domain-level authorization/transaction policies.

AUTH-53's [email-free identity design](../architecture/adr/0009-passkey-first-identity.md)
now has optional core/PostgreSQL signup: pending-only identity allocation, separate
verified assertion, exact proof snapshots and atomic one-use completion. Final
expiry follows all writes, including session/audit waits. Realm/browser caps and
durable admission bound pending resources. Experimental HTTP signup rejects any
existing session cookie, requires exact Origin and browser binding, and has native
resident platform/USB proof and signed-context negatives. Contact attachment now
requires an original fresh passkey session plus an independent one-use mailbox
proof. Both stages recheck freshness after potentially blocking writes; final
consumption follows session/audit writes. Target-email before owner/session locks
serialize mailbox signup and competing attachments. Tests cover both race orderings,
occupied-address denial, exact session/browser/realm binding, rollback and expiry
during observed waits. UUID, passkey-required policy and original method/time are
preserved; preissued mailbox proofs are canceled and weaker fallback stays denied.
HTTP tests capture proof delivery. Separate native platform/USB tests now use the
real configured SMTP adapter with owned local Mailpit recipients, proving explicit
confirmation, independent binding rejection, fragment removal/no GET mutation,
rotation/revocation and later passkey login. Database facts verify unchanged
authentication method/time and stronger policy. Ordinary composition stays gated through AUTH-20 and remaining M03 evidence.

AUTH-18's optional enrollment boundary now rechecks fresh session/browser/realm
binding and exact verified state under locks, then atomically consumes the ceremony,
inserts an RP-wide unique credential and audits enrollment. Limits bound pending
state, credentials and verification admission. Protocol failures do not become
success events; audit failure rolls back credential and state changes. Deletion
cascades credential/state and clears owned admission/audit attribution. Final enrollment consumption now checks ceremony expiry and original live/fresh
session time after credential/audit writes, including unchanged pending-row and
RP-wide uniqueness waits. Regression tests reproduce the former audit-wait gap
and prove rollback for both mailbox and stronger-account policy. A separate
AUTH-54 audit tracks analogous final-write surfaces in older mailbox workflows;
those paths are not claimed verified by the enrollment fix. Upstream
payload tracing is suppressed within synchronous verifier calls. No ordinary HTTP
composition enables this boundary yet. Experimental authentication and method
provenance now exist; stronger-account recovery policy, real-device/other-browser
evidence and passkey-first
accounts remain required. See the [enrollment guide](../guides/passkey-enrollment.md).

The explicit experimental HTTP composition checks realm/origin alignment at startup,
uses the same exact-Origin middleware and redacted errors, and sets an independent
HttpOnly host binding cookie. Its 32 KiB body limit and core buffer bounds do not
apply to ordinary routes, which retain 8 KiB. Chromium virtual-authenticator cases
now cover actual registration, server rejection of bad UV/client data, browser RP
scoping, replay, a true cross-origin request's HTTP 403 and missing browser binding.
These checks neither enable ordinary server enrollment nor establish real-device,
passkey authentication or recovery assurance.

AUTH-19 now has optional core/PostgreSQL authentication: admission precedes lookup,
private ceremonies bind browser/realm/RP/purpose, and verified proofs carry exact
ceremony/credential snapshots. User -> credential -> ceremony locking and a new
post-lock expiry statement prevent stale or expired proof commits. Consume, key
update, session issuance and fixed-schema audit commit atomically; tests cover
replay, rollback, competing snapshots, expiry during unchanged-row waits and deletion.
Session methods are explicit and rotation preserves provenance. AUTH-53 now uses
account policy to reject weaker sessions and mailbox/password fallback, including
preissued proofs and policy changes during observed user-lock waits. Fresh
passkey session controls work without email; inventory omits unusable weaker-method
sessions. Stronger-account recovery and general lifecycle remain AUTH-20 work.
Experimental
HTTP now has native platform/USB assertions and modal resident discovery, plus
signed cross-origin context rejection and backup/counter evidence. The context
projection rejects topOrigin and true/null/duplicate crossOrigin; the pinned
library assertion path omits those checks. A private fixture explicitly arranges
stored-zero metadata for the native counterless acceptance test, without changing
its public key or verifier/session code. Stronger-account policy, passkey-first
enrollment and real-device/other-browser gates still disable ordinary composition. See the [authentication review](../research/passkey-authentication.md).

The alpha now includes opt-in password enrollment and sign-in (AUTH-12). Fresh verified sessions, a configured blocklist, bounded Argon2id, shared admission, transactional enrollment/session replacement and stale-hash rechecks are required; see ../guides/passwords.md. AUTH-13 adds browser/purpose-bound password recovery, credential versions, atomic session/proof invalidation and durable non-secret notifications. AUTH-14 adds both-address verified email changes, fresh-session/mailbox-confirmed deletion, authentication-time provenance, scoped cleanup and audit deidentification. AUTH-15 adds bounded owned-session inventory, fresh-authenticated individual/all-session revocation, proof cancellation and transactional audit. Deterministic database lock tests cover concurrent logins/revoke-all and freshness revalidation after waiting. AUTH-16 adds typed, fixed-schema audit attribution with composite ownership constraints, in-transaction recording, explicit historical provenance and scoped deidentification. Logout follows user-before-session lock order. Provider linking still requires fresh current-account proof plus a separately verified identity transaction; no matching-email merge or linking-success event is enabled. Stronger-factor recovery, queue monitoring/retention and authenticated password change remain incomplete. Linking, native tokens, external callbacks and issuer routes remain excluded. Full initial release remains blocked on their milestones. Baselines and external normative references are in ../research/protocol-dependencies.md. Every implementation ticket must state tests and residual risks; update this document when boundaries change.
