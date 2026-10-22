# ADR 0025: Purpose-bound SAML account deletion

Date: 2026-10-22. Status: core/PostgreSQL preparation, verification orchestration and erasure
implemented for opt-in engineering, including explicit HTTPS confirmation routes
and reference client. Actual Keycloak deletion/browser acceptance passes for the
recorded profile; dependency, XML/backend and independent production approval remain pending.

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

## Implemented completion boundary

`SamlDeletionVerifier` passes the private prepared response to the unchanged
concrete verifier, then maps the actual verified assertion under the exact policy
into a distinct noncloneable, redacted `SamlVerifiedDeletion`. No verifier stub, custom XML
bridge or proof constructor may substitute for this boundary. A deletion-purpose
proof must never mint a sign-in session.

`SamlAccountDeletion` delegates to PostgreSQL, which rechecks current full
registration/policy, the active original
owner/session/identity and exact signed subject. Require actual signed AuthnInstant
within the existing five-minute freshness policy and no future authentication.
Neither ForceAuthn, token issuance, request creation nor a newly created local
session supplies freshness. Retain all original request/session, signed assertion,
pin and signed-freshness caps through final commit.

Signature verification completes before SQL authority locks. Reserve authenticated
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

The core/PostgreSQL slice now implements concrete verification orchestration and
final erasure as well as preparation. Revocation or source change rejects its use;
the compiled SAML component now atomically cancels bound pending state on
logout and individual/all-session revocation. The explicit HTTP confirmation implementation has component evidence and the
recorded actual Keycloak/Chromium reauthentication-to-deletion acceptance below.
This establishes that bounded browser ceremony, not broader provider approval.

Real PostgreSQL tests cover original-row preservation, purpose/realm/owner/session/
private-proof separation, closed foreign keys, ForceAuthn intent, one-use database
ordering, storage rollback and observed deadline/owner-policy waits. Existing
ordinary library-produced signed inputs establish initiating SAML sessions before
the database-only orderings. These tests are not independent security review.

Normal SAML remains disabled. ADRs 0021–0024 still require maintained source/patch
ownership, dependency/native/XML signature review, qualified identity/profile
acceptance and independent approval. Implemented, tested, internally reviewed and
independently approved are separate states; this ADR grants no production approval.


## Backend evidence and limits

Fourteen additional ordinary real-PostgreSQL cases exercise actual signed deletion,
no authority before commit, exact signed subject, post-verification logout/policy/
source denial, known ownership under JIT deny, another owner/realm, verified-contact
notice without mailbox fallback, replay retention/cooldown, tail-write rollback,
DB-only competing deletion/sign-in and observed final-audit/owner expiry waits.
Both signature checks finish sequentially before each database-only ordering.
An initial logout-negative expectation omitted the existing SessionRevoked audit;
the corrected case explicitly captures that post-logout state and proves denied
erasure changes none of it. No production check or existing assertion was weakened.

A direct core freshness boundary check borrows a genuinely verified proof and
supplies ordinary timestamp observations: before actual AuthnInstant and at/after
its five-minute cap reject; the admitted boundary points grant nothing. PostgreSQL
uses this same core policy with its own trusted database clock, retains the explicit
not-future check and checks every earliest cap after the destructive tail. This is
not a wire acceptance test for a newly issued response carrying an older AuthnInstant.
The current ordinary IdP producer sets authentication time to issuance; broader
actual-provider SSO/freshness acceptance remains separate. No XML, proof constructor,
cryptographic verifier or database clock was modified to create that control.

The final transaction reserves stable ordered replay keys before owner locks and
uses the existing private erasure tail. Bound-session lookup resolves only the
stored irreversible verifier of the opaque proof's initiating session, then runs
the unchanged active-bearer/source/owner/identity guard and compares every bound ID
under locks. The lookup returns no bearer and itself grants nothing. Locked stored
contact, never a SAML attribute, supplies the optional notice. The longer final
transaction keeps authorization, original/signed/freshness caps, erasure and its
last database-clock check visible in one module below300 lines.


## Session invalidation and indexed access

The compiled SAML backend cancels only deletion-purpose rows bound to the exact
realm/owner/session on logout or individual revocation. Revoke-all cancels that
realm owner's bound deletion rows across sessions, preserving anonymous sign-in,
other owners and other realms. Cleanup shares the existing revocation transaction;
its storage/audit failure rolls back revocation and pending deletion together.
Fresh individual/all-session operations retain their original final deadline check
past cleanup waits. Own logout remains allowed without a fresh provider session.
No source lock is acquired after owner locks. Builds without this optional backend
still reject stored SAML authority; bounded pending state may remain until expiry
or later cleanup, but revocation cannot be reversed by recompiling a backend.

The logout ownership query additionally selects the initiating session ID. Its
existing independent lock observer matches that new projection; all negative
lock-order, session-mutation, idempotence and audit-time assertions stay intact.
Migration0026 adds the realm/owner/session index used by these new equality filters
and parent cascades. It is unfiltered so FK-generated queries can use it too.
An actual upgrade test preserves complete user/session/identity/request rows and
original caps, checks the index definition and completes the original operation.
Published migrations are unchanged. No performance/stress claim is made.


## Explicit HTTP confirmation and non-authoritative delivery

`SamlAccountDeletionWebServices` constructs the concrete preparation, verifier and
final-erasure services from one full policy. `SamlWebServices::with_account_deletion`
rejects mismatched or repeated selection; the existing constructor keeps deletion
absent and its original logout-cookie behavior. Only the selected router adds the
destructive start/finish/cancel/reference paths. Closed inputs require exact Origin,
current initiating SAML session, separate three-cookie proofs and the same explicit
confirmation phrase at start and completion. No source/owner/realm/return selector
is accepted. Successful erasure clears current authentication/proof cookies only
after commit; errors preserve the ambient session. A stale returned nonce does not
clear another operation's cookies. Cancellation grants/erases nothing.

The common cross-site POST ACS remains non-authoritative and cookie/storage-free.
The fixed protected script removes its hidden form, then sends only returned
RelayState to same-origin operation selection. A unique complete private-cookie
match selects fixed sign-in versus deletion UI; ambiguity or an unavailable
profile rejects without consumption, signature work, SQL or grant. Existing-session
rejection remains in actual sign-in finish. Deletion waits for a second typed
confirmation and has no automatic destructive submission. Payload stays in memory,
not URLs/storage, and is discarded on navigation/restoration. Full cookie/origin,
source, purpose, owner, signature, time and atomic-commit checks still gate finish.

Ordinary signed/real-PG component cases cover selected-route/contract separation,
confirmation/Origin/session/closed-input rejection, non-authority before commit,
wrong subject/session, stale nonce preservation, disabled source, cancellation and
storage-fault rollback. Existing sign-in cases pass unchanged. The owned eight-case
Chromium sign-in regression also passes through the new selector, including actual
cross-site Lax-cookie absence, same-origin private proof presence, ambient-session
protection and cleanup. That regression does not establish the new deletion UI or
actual provider deletion ceremony. Both generated contracts are checked against
live publication; normal SAML configuration remains disabled.


## Actual Keycloak deletion acceptance

Seven ordinary browser/PostgreSQL cases now pass through actual Keycloak26.8.1
and the production verifier, mapping, private operation selector and deletion
transaction. Real sign-in establishes the initiating session. A genuine signed
reauthentication return creates no authority before the second typed confirmation;
a wrong phrase changes no database facts, and cancellation retains the owner and
session. Reauthentication as another real provider user rejects deletion. A new
reauthentication as the exact initiating subject succeeds, leaving zero local users,
identities, sessions or pending requests and four durable replay entries. An owned
provider administrative read confirms the remote account still exists.

The developer-only fixture explicitly composes the optional deletion services;
normal application/server composition remains disabled. Clearing only the owned
provider's SSO cookies permits ordinary account selection without disturbing the
application session or proof cookies. No assertion, signature, XML or proof is
edited or fabricated. All signature work is sequential. The original ten-case
rollover/realm suite remains separate and unchanged. CI runs both suites.

The timing observer now reports removed-session counts and null measurements for
erased sessions rather than failing cleanup or treating absent historical rows as
passing timing evidence. The deletion report retains pre-erasure timing facts; the
original live-session suite retains its exact assertions. Cleanup proves normal
fixture exit, database/container removal and no diagnostic/emergency path. This
is not older-AuthnInstant wire coverage, qualified identity/attribute acceptance,
an independent audit or permission to activate SAML.
