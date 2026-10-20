# ADR 0016: Scoped OIDC identity mapping and explicit provisioning

Date: 2026-10-20. Status: accepted for AUTH-30's optional core/PostgreSQL mapping,
policy storage, JIT resolution and provider sessions. AUTH-30 remains In Progress
pending complete verification/publication and owned-provider acceptance. Explicit
linking/unlinking remains AUTH-25; ordinary provider activation is not enabled.

## Context and identity boundary

A signed external subject is not a local user. Provider email must not become local
verified contact or select an account. OIDC [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
and [stability rules](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability)
distinguish issuer/subject identity from email and presentation. Issuer and subject
are case-sensitive; authentication time is separate from token issuance. Application
roles and memberships remain outside authentication.

The explicit core/PostgreSQL `oidc-identities` features depend on token verification.
Trusted composition constructs immutable `OidcIdentityPolicy` for the exact persisted
OAuth configuration, including realm, connection, local client and revision. The
allowlist contains one to eight distinct exact HTTPS issuer strings and must include
the configured issuer. Wildcards and token-selected issuers are rejected. Multiple
tenants use separately configured exact-issuer connections/services with an explicit
trusted allowlist; a common/wildcard issuer template is not implemented.

JIT defaults to `Deny`. The final transaction permits an already-bound subject under
current policy, but creating an owner requires explicit persisted `Allow`. No email
matching or automatic merge occurs, even for a provider-asserted verified address.
The owning identity key includes realm, connection, local client, exact issuer and
subject. Columns use explicit C collation so database locale cannot change equality.
Changing issuer does not transfer an identical subject to a previous issuer's owner.

## Mapping and optional profile data

Display selection explicitly chooses signed `sub`, `name` or `preferred_username`.
There are no scripts, JSON paths, role rules, email/alternate-field fallbacks or
UserInfo fetches. Optional profile strings are retained only when nonblank, free of
controls and at most 256 UTF-8 bytes. Duplicate recognized claims reject before
normalization. Verification-only builds still ignore unrecognized profile fields.

`map` consumes `VerifiedOidcIdentity` into opaque `OidcMappedIdentity`. Neither proof
has a public constructor, Clone or Serialize; Debug is redacted. The mapped proof
retains original subject/purpose/deadline, exact trusted policy and provider attributes.
Its `display_name()` returns `Option<&str>`: an absent/unusable selected field stays
absent without fallback. New-user provisioning rejects absence; an existing subject
preserves stored presentation and can authenticate without optional profile data.
This refines the new feature-branch API from the earlier mapping checkpoint, which
rejected a known subject too early when the optional field was absent. A signed
PostgreSQL regression reproduced that Unauthorized result before correction; the
new-owner denial and no-fallback assertions remain mandatory.

Mapping grants nothing alone. `OidcSignIn::finish` consumes the mapped proof and
generates a local secret, returning `(User, Secret)` only after repository commit.
Both use case and repository reject linking-purpose proof. Signature, nonce, exact
issuer/audience and original OAuth state remain AUTH-29/AUTH-22 prerequisites.

## Trusted configuration and final transaction

`configure_oidc_identity_policy` applies a fresh configuration revision, cancels old
pending state and writes policy atomically while preserving disable. Migration 0017
stores the full scoped registry key, revision, bounded issuer array and closed
mapping/JIT modes. Its constructor validates URL spelling/uniqueness/membership.
Reapplying configuration always allocates a new revision, including after restart;
this invalidates old provider sessions as well as pending/verified callbacks.
There is no revision-restoration fallback. Use the returned policy/configuration.

Migration 0018 adds external identity records, provider session provenance, typed
OIDC audit shape and deletion cooldown metadata. Final resolution takes configuration
then policy shared locks and compares the complete current typed policy. A scoped
advisory lock serializes subject creation. Existing-owner lock order is optional
email -> owner -> identity; a vanished owner rejects without falling through to JIT.
A new owner receives an opaque UUID, null email/verification time, selected display
metadata and explicit `provider_required` policy. Identity, session and fixed-schema
`oidc_authenticated` audit commit together. No provider profile/token is in audit.

The original verified-proof cap is checked after initial locks and again after all
potentially blocking writes. Failure rolls back user, identity, session and audit;
consumed OAuth state is not restored. Configuration/policy locks span this local
transaction, never provider I/O or signature verification. A callback holding the configuration
lock may commit before a waiting disable; subsequent session validation rejects it
once disable commits. A disable that commits first rejects the waiting callback.
The final clock check precedes commit and cannot bound commit/response latency.

## Account and session policy

`AuthenticationPolicy::ProviderRequired` serializes as `provider_required`. A session
has method `oidc`, a composite realm/identity/owner foreign key and original connection
revision. Missing provider `auth_time` is explicitly unknown (`-infinity` in storage,
null in session inventory); issuance time and local creation never become freshness.
A valid old authentication time remains old. Provider amr/acr do not imply local
passkey authentication, certified MFA/AAL or application permissions.

Validation/inventory and sensitive session revocation acquire provider configuration
then policy before owner/session locks. They revalidate method/source, current account
policy and original idle/absolute/freshness caps after waits. Provider inventory
omits incompatible methods/sources. A genuine sufficiently recent provider auth_time
can authorize owned session revocation; unknown/old time cannot. Logout can always
dispose of the caller's own bearer, including after source disable.

Provider-required accounts cannot use mailbox/password sign-in, password enrollment,
mailbox deletion, passkey sign-in or saved-code passkey recovery as implicit fallback.
Verified local contact does not relax policy. Preverified passkey proofs and retained
recovery codes reject after this policy change. No public policy-transition, provider
contact attachment or provider-only account-deletion endpoint is added. Those
lifecycle/activation capabilities require their own reviewed boundary; account-deletion
race tests use an owned persistence fixture following owner lock and audit erasure.

## Deletion and retention

A database deletion trigger records only the realm and SHA-256 of an unambiguous
connection/client/issuer/subject tuple with a five-minute cooldown, then ordinary
cascades erase identities/sessions. It never takes configuration/advisory locks,
avoiding inversion against a callback waiting for the owner. Existing-owner callbacks
revalidate the locked owner; anonymous callbacks after deletion reject during cooldown.
The original OAuth cap is at most five minutes, so a pre-deletion proof cannot outlive
that cooldown. Fresh requests also wait; after expiry a new flow may create a new UUID.

The SQL hash uses established SHA-256, not custom cryptography or a credential verifier.
No raw subject or erased user reference is retained in cooldown rows, but the hash is
pseudonymous metadata and may be guessable. New-owner JIT prunes at most 32 expired
rows in its realm with SKIP LOCKED before taking an owner lock. Expiry immediately
stops blocking; physical deletion is opportunistic, not guaranteed after five minutes.
There is no autonomous retention sweep yet. Backups/audit timing retain separate
privacy/retention gates. Tests shorten owned proof deadlines and arrange expired
retention metadata explicitly; they do not claim a real five-minute/device wait.

## Verification and limits

Real PostgreSQL scenarios use consumed OAuth state and established-library ES256
signatures. They cover actual JIT denial, no email merge, subject/realm/client/issuer
isolation, case-sensitive storage, concurrent provisioning, both disable/deletion
orders, rollback, final-write expiry, provider freshness and source-lock waits,
migration compatibility and exact schema errors. Observer/pool/SQL failures remain
fatal infrastructure failures, never expected Unauthorized evidence.

The existing pinned josekit becomes a PostgreSQL test dependency; no package version
or production crypto dependency is added. Focused modules keep transaction ownership
and lock order visible. The longer owning transactions and ordered integration tables
are reviewed size exceptions. Owned-provider acceptance, final full-suite results and
hosted CI are recorded in verification evidence; no conformance, independent audit,
ordinary activation or production-readiness claim follows from component tests.
