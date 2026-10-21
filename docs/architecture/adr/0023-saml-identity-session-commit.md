# ADR 0023: Gated SAML replay, identity and session commit

Date: 2026-10-21. Status: implemented for opt-in core/PostgreSQL engineering;
production dependency, interoperability and independent approval remain open.

## Decision

Extend the explicit `saml-identities` component with `SamlSignIn` and the concrete
PostgreSQL `SamlIdentityRepository` implementation. Consume only the existing
noncloneable mapped proof from concrete signature verification. Neither mapping
nor successful signature verification alone grants local authority. No alternate
verifier, public proof constructor, XML parser or cryptographic implementation is
introduced. Default application composition still exposes no SAML provider or ACS.

Keep one visible completion transaction: lock exact current registration and mapping
policy; check the original and signed admission deadline; reserve both replay IDs;
serialize the complete subject namespace; resolve an existing owner or explicitly
permitted JIT owner; write source-bound session and typed authentication audit;
check the retained deadline again as the final statement; commit. Native signature
verification and external I/O finish before this transaction. Any failure rolls back
all authority writes, including both replay reservations. A session bearer is
returned only after commit.

## Replay and ownership

Migration 0024 adds a durable replay ledger keyed by realm, connection and SHA-256
of each authenticated identifier. Neither client nor registration revision resets
replay. Sort both keys before acquisition. An active conflict rejects; only an
expired reservation can be replaced. Bounded expired-ledger housekeeping is a
separate autocommit statement before authority acquisition, with no source or owner
locks retained. This avoids reversing the reservation/source lock order. Cleanup
does not consume input or grant authority.

Identity uniqueness includes realm, connection, local client, configured IdP entity,
configured SP entity and exact persistent subject. The complete legal tuple can
exceed PostgreSQL's btree entry limit. Use PostgreSQL SHA-256 of an unambiguous JSON
array as a bounded unique index, with a check tying the digest to the fields.
Every owner lookup also compares the complete exact tuple: a digest collision must
fail closed, never resolve another subject. Do not normalize subject case, link by
email or use presentation/attributes to select an owner.

Existing ownership follows the established optional-mailbox lock then user lock,
and rechecks the identity binding. A vanished or changed owner cannot fall through
to JIT. New ownership requires persisted Allow and usable optional presentation;
create a provider-required user with no contact email or email-verification fact.
An existing binding can resolve under Deny even when its subject is too large for
presentation. No provider attribute conveys application authorization.

## Session and lifecycle

Store actual signed AuthnInstant and exact SAML identity/revision provenance.
Clamp the existing database-default absolute lifetime by the proof's separate
signed session upper bound, preserving microseconds. The short request/Assertion
admission cap remains a final commit deadline, not the session lifetime.

Authentication, inventory and fresh revocation require current enabled exact
source/policy under source locks before owner/session locks. Recheck binding after
owner waits. Fresh controls use actual stored authentication time and the existing
five-minute policy; merely creating a new local session establishes no freshness.
Revision replacement or disable invalidates earlier sessions. Builds without the
SAML backend explicitly reject stored SAML authority; own-session logout remains
available. Inventory combines active provider sources under the existing UUID
cursor and global page limit. There is no generic provider plugin framework.

Composite foreign keys bind session, identity and user to one realm. Existing
account erasure cascades SAML identities/sessions, preserves replay reservations,
and installs a hash-only five-minute subject cooldown. This exceeds every original
pending-request lifetime, preventing preverified inputs from recreating an erased
owner. This persistence behavior is not a SAML self-service deletion ceremony;
purpose-bound fresh SAML deletion remains unimplemented.

`AuditEvent::SamlAuthenticated` is an additive closed event with user/session
references, no raw assertion or arbitrary attribute payload. Existing audit event
shapes and erasure constraints remain intact. All published migrations are unchanged.

## Assurance and remaining work

Ordinary integration uses the established library IdP facade and unchanged public
upstream fixture key, with actual sequential signature verification. Database-only
commit races, write-failure rollback and observed lock/deadline waits exercise the
transaction boundary. These are engineering tests, not independent XML/signature
review, a deployed IdP exchange or an audit. Exact results belong in the verification
record; failed setup and corrected controls must not be hidden.

Normal SAML stays disabled. HTTP/browser ACS delivery, real IdP rollover/identity
acceptance, complete purpose-bound lifecycle and the authenticated attribute and
qualifier limitations in ADR 0022 remain open. ADR 0021 still requires an owned
maintained distribution/patch decision, dependency/backend/XML signature review
and named independent security approval. Internal review cannot satisfy that gate.
