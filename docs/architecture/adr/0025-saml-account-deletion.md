# ADR 0025: Purpose-bound SAML account deletion

Date: 2026-10-22. Status: preparation implemented for opt-in engineering;
verified deletion, HTTP/browser delivery and production approval remain pending.

## Decision

Keep deletion separate from SAML sign-in. Add `SamlDeletionRequests` and a separate
repository port without adding required methods to existing sign-in adapters.
Generate a reauthentication request through the established library's `ForceAuthn`
option. This is a request to the IdP, not evidence of freshness. Preparation can
neither authenticate a user nor erase an account.

Migration 0025 adds a closed request purpose and optional initiating user, session
and SAML identity. Existing rows become `sign_in` with all three bindings absent;
their source, revision, proof hashes and original deadlines stay intact. Deletion
requires all bindings. Composite foreign keys enforce exact realm, owner, source,
identity, session and revision agreement, with deletion cascades. Published
migrations are unchanged. Sign-in consumption/cancellation explicitly select
`sign_in`; the deletion counterpart selects only `delete_account`.

Preparation requires the actual current SAML session bearer and full current
registration/policy. Acquire source locks first, then the established optional
contact-email lock, provider-required owner, initiating session and exact identity.
Recheck the owner and active session after waits. Do not select another source or
owner from browser-supplied IDs, email, presentation or attributes. Old or unknown
session authentication time may initiate reauthentication but establishes no
freshness or destructive authority.

Capture the database request deadline before configuration/owner waits. Persist
the earliest request, initiating absolute-session and idle deadline with full
microsecond precision. Both purposes share the existing pending quota and expiry
cleanup. After binding checks and exact one-use consumption, retain that original
deadline in a noncloneable, redacted `SamlPreparedDeletion`. It privately owns the
ordinary response preparation and exposes no conversion to a sign-in proof.
Cancellation uses the same current-owner/private-proof checks. Storage failures
remain Unavailable, rather than successful cancellation or credential rejection.
Check the retained earliest deadline after the final blocking write before commit.

## Required completion boundary

The subsequent implementation must pass the private prepared response to the
unchanged concrete verifier, then map the actual verified assertion under the
exact policy into a distinct opaque deletion proof. No verifier stub, custom XML
bridge or proof constructor may substitute for this boundary. A deletion-purpose
proof must never mint a sign-in session.

Final erasure must recheck current full registration/policy, the active original
owner/session/identity and exact signed subject. Require actual signed AuthnInstant
within the existing five-minute freshness policy and no future authentication.
Neither ForceAuthn, token issuance, request creation nor a newly created local
session supplies freshness. Retain all original request/session, signed assertion,
pin and signed-freshness caps through final commit.

Complete signature verification before SQL authority locks. Reserve authenticated
replay identifiers in the existing stable sorted namespace before owner locks;
reuse the established optional-email/owner/session order and private account
erasure tail. Replay reservation, local erasure, audit deidentification, safe
stored-contact notice and deleted-subject cooldown must commit or roll back
together. The earliest deadline check must follow every potentially blocking final
write. Do not delete remote IdP accounts, invent contact, link by email, or offer a
weaker local or other-provider fallback. Consumed preparation is never restored
after later verification/commit failure.

The HTTP extension must remain explicit opt-in HTTPS composition, with closed
same-origin input, separate protected deletion cookies and destructive confirmation.
The cross-site ACS remains non-authoritative. Selection of a same-origin operation
cannot itself consume, verify, grant or erase. Ordinary server composition must
continue to expose no SAML activation switch.

## Scope and review

Core owns the distinct operation/port/types. PostgreSQL's focused
`account/saml_deletion/` modules own authorization, preparation and consumption.
They share existing source policy, owner locking and deadline operations rather
than introduce a generic provider engine. Longer ordered preparation/authorization
functions retain lock order, explicit bindings, rollback and final checks together.
Feature tests split migration, schema, binding, consumption, isolation and wait
scenarios; no production proof constructor or dependency is added.

The present slice implements preparation only. Revocation or source change rejects
its use; revoked-session pending rows can remain bounded by their original expiry
until cleanup. Full invalidation cleanup, concrete verified deletion, final atomic
erasure, HTTP confirmation and actual IdP reauthentication-to-deletion still need
implementation and evidence. Existing privileged account erasure/cooldown coverage
does not establish this self-service ceremony.

Real PostgreSQL tests cover original-row preservation, purpose/realm/owner/session/
private-proof separation, closed foreign keys, ForceAuthn intent, one-use database
ordering, storage rollback and observed deadline/owner-policy waits. Existing
ordinary library-produced signed inputs establish initiating SAML sessions before
the database-only orderings. These tests are not independent security review.

Normal SAML remains disabled. ADRs 0021–0024 still require maintained source/patch
ownership, dependency/native/XML signature review, qualified identity/profile
acceptance and independent approval. Implemented, tested, internally reviewed and
independently approved are separate states; this ADR grants no production approval.
