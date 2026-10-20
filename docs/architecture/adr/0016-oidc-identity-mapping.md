# ADR 0016: Scoped OIDC identity mapping and explicit provisioning

Date: 2026-10-20. Status: accepted for AUTH-30's optional core mapping and trusted
PostgreSQL policy storage. Identity resolution, provisioning, linking and session
issuance below remain requirements, not implemented behavior. AUTH-30 remains In Progress.

## Context

AUTH-29 returns a signed external subject, not a local user. Provider email must
not become local verified contact or select an existing account. Email-free local
accounts currently require passkey policy; labeling a provider-only account that
way would misrepresent its method and make future fallback policy unsafe.
OIDC [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
and [stability rules](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability)
distinguish issuer/subject identity from email and presentation attributes.
Application roles and memberships remain outside authentication.

## Implemented mapping boundary

The explicit core `oidc-identities` feature depends on `oidc-verification`.
Trusted composition constructs immutable `OidcIdentityPolicy` for the exact
persisted OAuth connection: realm, connection, local client, revision, issuer,
provider client, redirect and mix-up defense. Different snapshots reject.
An explicit allowlist has one to eight distinct HTTPS issuer strings, validates
with the existing issuer parser and must contain the configured issuer exactly.
Wildcards are rejected. This tenant policy does not authorize fetching other
issuers or accepting a token-selected issuer.

JIT defaults to `Deny`; `Allow` requires deliberate administrative opt-in. This is
configuration for future resolution, not a database provisioning gate yet. Deny
must eventually prevent creating an owner while permitting an existing bound
subject under otherwise valid policy.

Display mapping explicitly selects signed `sub`, `name` or `preferred_username`.
There are no scripts, JSON paths, role rules, email mapping, alternate-field
fallbacks or UserInfo requests. Subject remains the identity key. Optional profile
strings must be at most 256 UTF-8 bytes, nonblank and free of controls to be retained.
Absent/null/unusable presentation data does not invalidate signed identity; selecting
that missing field for required mapping rejects. Duplicate recognized profile fields
reject before normalization. The new feature gates profile recognition, preserving
the verification-only behavior for unrecognized presentation attributes.

`map` consumes `VerifiedOidcIdentity` into opaque `OidcMappedIdentity`. It retains
the full trusted policy, original subject/purpose/deadline and provider attributes.
Neither proof implements Clone or Serialize; Debug is redacted. Display metadata
does not grant ownership. Provider email stays separate from verified local contact;
missing `auth_time` stays missing and `iat` never becomes authentication time.
Mapping creates no user/session and grants no linking, freshness or MFA authority.
No HTTP route, user-policy enum or ordinary composition changes here.

## Implemented policy storage

The PostgreSQL `oidc-identities` feature adds trusted administrative
`configure_oidc_identity_policy`. It allocates a fresh connection revision, reuses
the existing transactional configuration write/cancellation, then stores the
typed policy before committing. Failure rolls back revision, pending cancellation
and policy together. Reapplying stale input allocates another revision and never
clears an existing disable; re-enable still requires explicit latest configuration.
Use the returned policy when composing subsequent flows.

Additive migration 0017 stores policy by realm/connection/local-client, with a
composite registry FK, revision, bounded non-null issuer array, closed display
claim and closed default-deny JIT mode. Exact URL spelling, uniqueness and issuer
membership are validated by the core constructor before trusted writes. Ordinary
OAuth reconfiguration/disable can leave a stale policy row: that row must not
authorize resolution without matching current enabled configuration and revision.
No policy lookup or final identity commit is implemented yet. Migration preserves
existing users, sessions, configuration and pending OAuth state and creates no
implicit policy. Policy storage does not provision a user or audit a login.

## Required persistence and lifecycle work

Atomic identity resolution remains mandatory. Its final commit must recheck enabled
configuration, exact policy and original deadlines after all waits. External
ownership must include realm, connection, local client and exact issuer. Identical
claims in another tenant/client cannot select a local owner. Matching even a
provider-verified email never merges accounts. Explicit linking requires original
fresh account proof plus the new external proof and preserves stronger policy.
Explicit linking/unlinking belongs to AUTH-25. AUTH-30's eventual sign-in
resolution must reject linking-purpose proofs until that separate boundary exists.

Serialize subject uniqueness, owner resolution/provisioning and identity/session/
audit commit together. Retain configuration-before-owner-before-session and
email-before-owner ordering. Revalidate snapshots and original caps after waits,
then read database clock without table locks after writes. Pool/observation failures
cannot count as authorization rejection. No database lock spans network or crypto.

Provider-only accounts require explicit account policy and session provenance,
without fabricated contact, passkey labels or implicit password/mailbox recovery.
Provider login alone cannot satisfy passkey-required policy. Missing authentication
time cannot authorize fresh sensitive actions; current provider configuration must
remain relevant to provider sessions.

Deletion versus anonymous JIT must prevent a pre-deletion proof silently recreating
authority. The exact serialization/retention rule will accompany its migration and
observed PostgreSQL evidence. Test deletion, rollback, disabled/reconfigured
callbacks, subject races, cross-tenant claims, JIT denial and valid controls.
These safeguards remain acceptance requirements, not claims of implementation.

## Evidence and limits

Core scenarios use established-library signatures and consumed OAuth fixtures.
The cross-registration matrix includes fresh revisions in every case, so it does
not independently prove every database key dimension. PostgreSQL policy tests cover
revision/cancellation, rollback, concurrent disable, realm/client isolation and
migration/schema constraints. Identity resolution, disabled-callback races and
JIT denial remain required before ticket completion.
No new dependency, custom cryptography, provider activation, independent audit,
protocol conformance or production-readiness claim is introduced.
