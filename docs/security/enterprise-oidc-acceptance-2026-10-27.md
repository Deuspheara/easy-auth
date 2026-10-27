# Enterprise OIDC milestone acceptance — 2026-10-27

AUTH-27 requires explicit tenant connections, safe discovery/JWKS rotation and
policy-driven JIT/claims passing local IdP and adversarial tests. This review
checks those requirements and all five completed children, including supported
browser composition and provider-only deletion. It establishes bounded M05
engineering acceptance, not feature-complete release, protocol certification,
registered-provider interoperability, production readiness or independent approval.

## Requirement-to-evidence review

| Requirement | Current source and assertions | Acceptance and limits |
| --- | --- | --- |
| Explicit realm/connection/client/issuer trust | [Core policy](../../crates/auth-core/src/oidc/policy.rs), [identity policy](../../crates/auth-core/src/oidc/identities/policy.rs), [persisted policy](../../crates/auth-postgres/src/oauth/identity_policy.rs), [issuer cases](../../crates/auth-postgres/tests/lifecycle/oidc/identities/issuers.rs), [authorization cases](../../crates/auth-postgres/tests/lifecycle/oidc/identities/authorization.rs) | Exact trusted configuration and bounded issuer allowlist; no token-selected tenant, wildcard issuer or email-selected owner. Full workspace cases cover realm/client/issuer/revision separation and case-sensitive subject ownership. |
| Discovery/egress/cache safety (AUTH-28) | [Retrieval](../../crates/auth-core/src/oidc/documents/retrieval.rs), [address cases](../../crates/auth-core/src/oidc/tests/addresses.rs), [metadata cases](../../crates/auth-core/src/oidc/tests/metadata.rs), [production TLS builder](../../apps/auth-server/src/oidc_http/client.rs), [transport cases](../../apps/auth-server/src/oidc_http/tests/transport.rs) | Whole-answer public-address/port checks, pinned transport, exact issuer, bounded bodies/time/cache and no redirect/proxy/stale fallback. Private/link-local/IPv6/mixed answers, oversized metadata and malformed documents retain positive controls. Native work retains cancellation leases; this is not a universal availability guarantee. |
| Code/S256, typed claims/signature and bounded key rotation (AUTH-29) | [Verification flow](../../crates/auth-core/src/oidc/verification/flow.rs), [claims](../../crates/auth-core/src/oidc/verification/claims.rs), [actual-signature rotation cases](../../crates/auth-core/src/oidc/verification/tests/rotation.rs), [refresh cases](../../crates/auth-core/src/oidc/tests/refresh.rs), [owned backend](../../tests/browser/oidc/README.md) | Required issuer/audience/nonce/azp/algorithm checks; one bounded unknown-key refresh, no refresh for ordinary known-key signature failure. Fresh Keycloak code/claim/rotation/replay negatives pass. Keycloak no-store headers do not establish the forced-refresh branch; separate genuine-signature/cache tests do. |
| Policy-driven JIT/claims and atomic authority (AUTH-30) | [Owner resolution](../../crates/auth-postgres/src/oauth/identities/ownership.rs), [completion](../../crates/auth-postgres/src/oauth/identities/completion.rs), [resolution cases](../../crates/auth-postgres/tests/lifecycle/oidc/identities/resolution.rs), [concurrency](../../crates/auth-postgres/tests/lifecycle/oidc/identities/concurrency.rs), [faults](../../crates/auth-postgres/tests/lifecycle/oidc/identities/faults.rs) | Explicit default-deny/allow; current policy and exact signed subject, no matching-email merge or fabricated contact/freshness. Realm/deadline/disable/deletion race, rollback and one-owner cases pass in the qualified real-PG suite. Fresh Keycloak proves deny/allow, known owner without optional profile, matching-email non-merge and held-proof revision/disable refusal. |
| Provider-only lifecycle (AUTH-55) | [Deletion decision](../architecture/adr/0017-provider-account-deletion.md), [PG cases](../../crates/auth-postgres/tests/lifecycle/oidc/identities/provider_deletion/), [HTTP profile](../../tests/browser/oidc/README.md#real-provider-to-http-deletion-acceptance) | Actual recent signed time, exact owner/source/purpose, destructive confirmation, atomic erasure/deidentified audit and live cooldown. Fresh six-case HTTP run distinguishes token 503 from authentication 401 and rejects wrong subject/replay. Its genuine signed bootstrap is fixture-only, not a public-login claim. |
| Supported embedded/standalone browser delivery (AUTH-56) | [Shared factory](../../apps/auth-server/src/application/oidc.rs), [HTTP handlers](../../crates/auth-axum/src/oidc/web/handlers.rs), [startup cases](../../crates/auth-postgres/tests/lifecycle/oidc/identities/startup/), [public flow](../../tests/browser/oidc/web/README.md), [ADR0018](../architecture/adr/0018-oidc-web-composition.md) | Fresh two-mode public start/callback/finish/session/logout/deletion/cooldown passes without seeded authority or a bootstrap endpoint. Pending callbacks and committed sessions survive actual factory restarts; all six process instances stop normally. Normal-binary startup has separate refusal/stable-revision evidence. |

The old parent checkpoint predates AUTH-55/56. Its missing supported routes and
provider-only deletion are now covered by those concrete boundaries and fresh
runs. Public provider-contact attachment and account-policy transition remain
unsupported; this review does not claim them implemented or enable a weaker
fallback. Explicit social linking and Apple provider-grant revocation have separate
tickets and real-provider acceptance. No business groups/permissions, dynamic
tenant templates or public provider-administration API is added.

## Fresh owned execution

Exact clean source: `6c38aafee76bd9ca532122127d1f7adea2b7510a` on
`feat/auth-27-acceptance-review`. The [sanitized receipt](enterprise-oidc-acceptance-2026-10-27.json)
records fixed producer hashes, source-manifest digests, all named outcomes, finite
protocol/database observations, cleanup, image identity and historical CI metadata.
The detailed per-file receipts remain local; every recorded file hash was compared
with the unchanged checkout before accepting each result.

| Profile | Passed cases | Distinct observed boundary |
| --- | ---: | --- |
| Normal startup | 13 | Default-feature refusal, concrete routes in both modes, stable revision/no authority at startup, protected confidential file, TLS/override/partial/mismatch/disabled-source refusal |
| Real Keycloak backend | 23 | Actual code/S256/RS256, nonce/audience/signature/replay/rotation, deny/allow/no-merge, live policy/source refusal, genuine fresh deletion and cooldown |
| Real provider-to-HTTP deletion | 6 | Protected actual signed bootstrap, nonmutating callback/cancel, wrong recent signed subject, controlled token 503, explicit deletion/replay and valid signed cooldown refusal |
| Public browser standalone + embedded | 18 | Nine cases per mode; public login waits for actual audit commit, protected session, ambient-switch refusal, logout/old bearer replay, owner reuse, fresh deletion/cooldown and real restarts |

These profiles overlap policy coverage and must not be presented as independent
security approvals. Backend proxy totals remain 19 token posts/18 successful token
responses with one deliberate signature corruption and one captured-token replay.
HTTP deletion records 5/4 and one controlled 503. Public web records 12/10, all 12
requests Basic-authenticated, two controlled 503s and no signature/token substitution.
Each public-mode final database has no user/session/identity/pending/contact/notice
authority, four deidentified audits and one live cooldown. All three profile
providers, their private files, all owned databases and application processes were
removed normally; no emergency cleanup or unexpected native diagnostics passed.
The enclosing PostgreSQL/Mailpit containers and exclusive volumes were removed too.

Build/run the maintained profiles as described in their linked READMEs, sequentially
with the documented locked features and fixed producer copies. Use Node 24, pinned
Playwright/Chromium and the exact Keycloak image. This review used new disposable
PostgreSQL/Mailpit with random loopback ports and no host mounts. The legacy startup
support reads SMTP defaults from `.env.example`; the private driver replaced only
the in-memory SMTP host/port with its newly owned listener before running unchanged
startup assertions. No retained preview SMTP/DB or provider account was used.

Owned examples substitute only a concrete certificate/address transport while
reusing production TLS/GET/POST/readers and shared factory/settings. Chromium
certificate tolerance and hostname mapping remain process-local fixtures. They
prove neither a normal-binary public-root positive TLS flow nor arbitrary provider,
native OS, physical-device or browser-matrix interoperability. No trace, callback,
provider credential, raw assertion, cookie, user ID or private tracker content is
published in the receipt.

## Workspace, historical child gates and maintainability

The fresh workspace qualification at
`92a8a2a4ad9d7d2664a2666d1ecf2657bf4a2d32` is recorded in the
[research validation evidence](research-acceptance-verification-2026-10-27.md#fresh-validation):
formatting, strict default/all-feature workspace/all-target Clippy, 171 default and
1,197 reported all-feature passes (1,196 primary plus the isolated logging child),
676 real-PG lifecycle cases, zero failed/ignored, compiled advisory gate and
all-feature cargo-deny with inactive RSA/existing warnings retained. Git comparison
confirms all authentication, build, test, schema, native, script, CI and security
policy inputs are identical through this review. This is reused exact-input
evidence, not a new claim that those full commands ran again for this document.
The OIDC profiles above are fresh executions at 6c38aaf.

All five recorded child hosted runs were freshly read from the primary GitHub API;
each exact source matches and each is completed/success. Full commit/run pairs
are in the receipt: AUTH-28/run39326434266, AUTH-29/39343190737,
AUTH-30/39355085483, AUTH-55/39365720693 and AUTH-56/39379861505. They corroborate
historical child acceptance, not a new hosted result for this branch. No CI rerun,
merge waiver or deployment is inferred.

This increment changes evidence and focused documentation only. Source inspection
retains domain modules, narrow private boundaries, shared core/PG policy and thin
HTTP/factory composition. No runtime API, dependency, schema, transaction order,
protocol assertion or implementation responsibility changes; no structural refactor
or new size exception is bundled. The receipt is factual data, not a new test
framework or persisted credential store. The 73 protected original-file hashes,
original changed-path set and empty original index are checked separately.

## Remaining release gates

M05's local IdP/adversarial and supported-delivery criteria have bounded evidence.
All six methods plus outbound issuer remain required for feature-complete release.
Registered Google/Apple/manual OS/device work, provider-contact/policy-transition
capabilities, independent security review and production operations are not
qualified by this milestone review. Preserve every ADR0032 SAML trust/lifecycle/
advisory check and the waiver's limited meaning. Outbound OIDC remains a hard
release gate. No PR, merge, release, deployment or upstream contact is authorized
or performed by this review.
