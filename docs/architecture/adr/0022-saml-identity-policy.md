# ADR 0022: Gated SAML identity policy and exact subject namespace

Date: 2026-10-21. Status: accepted for opt-in core/PostgreSQL configuration and
mapping; [ADR 0023](0023-saml-identity-session-commit.md) extends final
replay/identity/session behavior. Complete lifecycle and production approval remain open.

## Decision and boundary

The explicit `saml-identities` feature builds on `saml-verification`. Keep
`SamlIdentityPolicy` immutable and bound to the full `SamlRegistration`, including
realm, connection, local client, both entity IDs, endpoints and revision. JIT
creation requires explicit `SamlJitPolicy::Allow`; the constructor defaults to
`Deny`. These are trusted administrative values, not callback-selected policy.
A missing persisted policy must fail closed. Policy/map construction is not a
provisioning or local authentication grant.

`map` consumes only the concrete verifier's opaque `VerifiedSamlAssertion` and
requires exact registration equality. It returns noncloneable, nonserializable,
redacted `SamlMappedIdentity`; there is no public proof constructor or alternate
verifier. Original/signed/certificate caps and staged replay reservations stay
inside the original proof. Final storage must recheck full current policy/source
and caps and atomically reject replay, resolve ownership, write session and audit.
This component implements none of that final authority by itself.

The initial verification profile requires persistent NameID of at most 256 Unicode
characters/1024 UTF-8 bytes (Approved Errata 05 E78). Present IdP/SP
qualifiers must equal configured entities; absent qualifiers use those same
trusted namespaces and SPProvidedID is unsupported. Final identity uniqueness must
include **realm, connection, client, configured IdP entity, configured SP entity and
exact persistent subject**. Include the SP entity even when a connection/client ID
is retained across administrative changes, so a new pairwise namespace cannot
select an old owner. No normalization, presentation value, provider email, attribute,
role, current display name or matching local email may select/merge ownership.

Only the verified persistent subject is an optional initial display candidate.
Reuse existing presentation validation (nonblank, at most 256 UTF-8 bytes, no control
characters). Keep exact spelling. Missing/unusable presentation must eventually
block creating a new owner while permitting resolution of an already bound subject
with stored presentation, under the same current source and account policy.
JIT defaults do not change existing provider-required lifecycle restrictions.

## Attribute dependency limitation

The legacy saml-rs name-keyed view remains unchanged for compatibility. Maintained
patch 0005 adds complete ordered scalar records through
`SsoSession::attribute_records()`, preserving NameFormat, duplicates and value
groups from the verifier-selected Assertion. The core verifier requires this
projection, retains zeroizing/debug-redacted `SamlAttribute` records and never
falls back to the legacy aggregate. Absent attributes are a complete empty
projection; unavailable XML-valued/nil projection rejects the application profile.
No application XML parser, raw-DOM bridge or verifier replacement is introduced.
[ADR 0028](0028-saml-attribute-and-authentication-facts.md) records the contract.

Maintained patch 0004 preserves typed NameID qualifiers through the built-in
producer; ordinary signed round trips and real-PG verifier scenarios cover exact,
absent, mismatched and unsupported alias cases. Broader actual IdP qualified
profile acceptance remains separate.

The current identity policy still exposes no attribute-selected metadata, roles,
email/contact assignment, fallback or automatic linking. Attribute projection is
now available, but it is not permission to interpret provider email as mailbox
ownership or to use attributes as identity keys. Real-PG cases prove default-deny,
exact subject stability, distinct subjects despite equal email, and foreign-realm
mapping rejection. Optional future attribute-selected presentation policy needs
its own explicit administrative contract; it is not part of this projection API.

## Persistence and migration

Migration 0023 adds only revision-bound SAML mapping policy with a closed deny/allow
JIT value and composite realm/connection/client foreign key. It creates no identity,
session, replay row or provider route. Existing immutable migrations remain intact.
The migration leaves existing registration, certificate, request hashes and original
caps unchanged and creates no policy for them by implication.

`configure_saml_identity_policy` takes full trusted policy plus explicit leaf pins.
One transaction rotates registration revision, cancels pending requests, replaces
pins and inserts policy while retaining prior disable. The existing pin replacement
was extracted and regression-tested before this behavior. Any registration revision
change, including pin-only replacement or disable, deletes old mapping policy in the
same transaction. A policy writer restores only its explicit new definition.

`saml_identity_policy` requires the exact current enabled registration under its
existing row lock. A returned snapshot is not continuing authority; the final
identity transaction must compare current policy again. Storage errors are
Unavailable, missing/disabled/stale definitions Unauthorized. No database lock spans
XML/signature verification. The API introduces no HTTP policy or persistence rule
in core, no new workspace crate and no generic identity engine.

## Evidence and unfinished work

Real PostgreSQL scenarios cover original-schema upgrade, failed-policy-insert
rollback of registration/pins/cancellation, disable retention, pin-only invalidation,
competing configuration writers, identical IDs across realms, and actual-signature
mapping with no local user/session/audit writes. Mapping rejects mismatched revisions
and preserves absent optional presentation. These are engineering tests and internal
review; they are not an independent security audit or actual IdP interoperability.

AUTH-34 now implements durable response/Assertion replay, the final atomic
identity/session transaction and source-bound validation/inventory/revocation as
recorded in ADR 0023. Purpose-bound deletion and HTTP/browser delivery are now
implemented experimentally under ADRs 0024/0025, with the documented scoped
Keycloak rollover/realm and deletion acceptance. Older-authentication-time wire
component assurance now includes newly issued signed responses with old
authentication; see ADR 0028. AUTH-35 retains broader qualified IdP/profile acceptance
and any future attribute-selected policy; Entra/Okta remain documentation-only. Dependency security approval,
XML/signature/backend review and separate named independent approval remain gates
under [ADR 0021](0021-saml-verification-and-approval.md). Normal SAML stays disabled.
