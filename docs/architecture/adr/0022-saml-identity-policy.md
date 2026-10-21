# ADR 0022: Gated SAML identity policy and exact subject namespace

Date: 2026-10-21. Status: accepted for opt-in core/PostgreSQL configuration and
mapping only; final replay/identity/session/lifecycle and production approval open.

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

The pinned saml-rs `model/extract.rs::attributes_from_extract` creates typed
attributes from a name-keyed aggregate and sets NameFormat to `None`. The typed
IdP producer also does not render supplied NameID qualifier attributes. Source
review and pure typed policy tests do not establish unambiguous qualified attribute
or qualifier extraction over the wire. Do not add a custom XML parser, raw-DOM
bridge, custom signer or verifier change to conceal these gaps.

Accordingly this initial mapping exposes no attribute-selected metadata, roles,
email/contact assignment, attribute fallback or automatic linking. Broader attribute
policy remains an explicit AUTH-35 dependency/acceptance requirement: require a
suitable maintained authenticated projection contract and established-vector/actual
IdP evidence before implementing it. This does not relax issuer/audience/recipient/
correlation/signature/algorithm/certificate checks or activate SAML.

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

AUTH-34 still owns durable response/Assertion replay and the final atomic
identity/session transaction. Source-bound validation, inventory, reauthentication,
revocation/deletion and HTTP/browser handling need their own complete acceptance.
AUTH-35 retains actual Keycloak rollover, supported attribute policy, cross-tenant
final identity behavior and Entra/Okta documentation. Maintained dependency approval,
XML/signature/backend review and separate named independent approval remain gates
under [ADR 0021](0021-saml-verification-and-approval.md). Normal SAML stays disabled.
