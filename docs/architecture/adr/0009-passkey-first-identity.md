# ADR 0009: Email-free identity and proof-completed passkey signup

Status: accepted for AUTH-53, 2026-10-19. Optional-mailbox model/migration,
nullable user contract, initial policy enforcement and the optional core/PostgreSQL
two-stage signup are implemented. Explicit experimental HTTP signup now has native
Chromium platform/roaming resident signup and later login evidence. Verified-mailbox
attachment now has core/PostgreSQL and experimental HTTP tests; actual SMTP/native
attachment evidence remains required. See the [signup guide](../../guides/passkey-signup.md).
AUTH-19's experimental sign-in is verified at `84d11a9`. AUTH-53 remains
In Progress. This decision does not enable ordinary passkey composition or
complete AUTH-20's credential-management and recovery requirements.

## Context

The user ID is the account identity. At the start of AUTH-53, `User.email`, the
protected-user response and `auth_users.email` all required a verified mailbox. Using a generated
email address for a passkey-first user would invent mailbox control and route
session, password and lifecycle operations through an identity the user never
proved. Making the column nullable alone would leave those assumptions unsafe.

Registration and authentication are separate proof boundaries. The existing
registration verifier can produce a credential candidate; it must not itself
establish genuine passkey authentication provenance. Reuse AUTH-19's assertion
verification, counter/backup policy and atomic issuance invariants before an
anonymous signup obtains an account session. Keep application authorization out
of this decision.

## Identity and policy

- Preserve the server-selected random UUID and realm as the identity. A display
  name is bounded presentation text, never a unique identifier or lookup key.
- Add a nullable verified mailbox with paired nullable verification time. Either
  both are present or both are absent. Retain realm/email uniqueness for present
  mailboxes; permit multiple email-free users. Never manufacture placeholder email.
- Make the core and HTTP optional-email contracts explicit. A present email stays
  a string; an absent email is `null`. Update generated schemas and document the
  alpha Rust type change before publishing behavior. Existing IDs, verification
  timestamps, credentials and session provenance survive migration unchanged.
- Persist a closed account policy independently of whether email exists. Existing
  users retain mailbox policy; new email-free users require passkey proof. Adding
  a verified address does not change that policy. Unknown policy fails closed.
- Registration of an additional key on a mailbox account does not automatically
  activate stronger policy. AUTH-20 owns that transition, including proof of a
  usable key, last-credential handling and an independently safe recovery path.

Passkey-required policy must be checked under the user lock before credential or
identity mutation and session issuance. Protected-user lookup and session inventory
must reject a session whose method does not satisfy current policy. Legacy unknown
provenance, email proof, password proof and a recent rotation cannot become passkey
proof. Rotation preserves the initiating method and authentication time.

Email/password sign-in and password recovery cannot issue or replace credentials
for passkey-required users, even after email attachment. Recheck policy after lock
waits; preflight checks or a previously issued mailbox challenge are insufficient.
For users without email, mail-only operations reject safely. Owned-session listing,
logout and fresh passkey-authorized revocation must still work without email.
Implement real user/source admission for sensitive actions rather than sending a
UUID or display name through the email-keyed password admission interface.

## Anonymous signup transaction

1. Start accepts a display name and browser binding, never a proposed owner, realm,
   email, RP ID or origin. The server chooses both prospective user and transaction
   UUIDs. Persist bounded private registration state with purpose, realm, RP,
   browser/source admission and a short database-owned expiry. Request a resident
   credential and required UV using the existing high-level service.
2. Registration completion verifies the bound state and records a trusted candidate
   credential only in pending signup storage. Construct an account-bound assertion
   for that server-owned candidate through AUTH-19's high-level service. Atomically
   advance the pending stage and freeze its exact candidate and assertion state.
   Neither stage creates `auth_users`, a durable account credential or a session.
3. Assertion completion admits the attempt before verification. Verify the actual
   signature, challenge, required UP/UV, exact RP/origin, client context, handle,
   candidate and private-state snapshots. The verified proof carries the original
   stored bytes; a client assertion cannot choose an owner or another ceremony.
4. One transaction revalidates pending purpose/stage/browser/realm and exact proof
   snapshots, inserts the email-free passkey-required user and its updated
   credential, consumes the signup and issues a fresh passkey-method session with
   fixed-schema audit facts. Re-evaluate expiry in a fresh statement after all
   potentially blocking locks/inserts. Audit or persistence failure rolls back
   identity, key, consumption and session together.

An owner collision or RP-wide credential ownership collision rejects signup; it
never logs into, links or merges an existing account. One pending signup has at
most one committed account/session outcome. A lost final response does not make
the ceremony reusable; the credential can authenticate normally after a committed
signup. A failed/expired signup can leave an authenticator-side credential without
a server account; document that limit rather than claiming remote key deletion.

Use a dedicated pending-signup table and explicit stages. Do not overload normal
authentication/enrollment transactions or create a generic workflow framework.
Cap pending rows per browser, admit start and completion by browser/source, bound
encoded state and candidate sizes, and define expired-row cleanup. No persistent
user is allocated merely because an anonymous browser started registration.

## Adding a mailbox

Email attachment is a separate account operation, not sign-in, email change or
account linking. Require a genuinely fresh passkey-method session plus a separate
one-time, browser/realm/owner/purpose-bound proof of the normalized target mailbox.
An occupied address is rejected without credential transfer or account merge.
Initiation must not reveal target ownership through its public response.

At final completion acquire target-email advisory lock, then owner and session
locks; recheck policy, freshness, absent current email, target availability, proof
binding and expiry. Preserve the UUID and passkey-required policy, record verified
mailbox time, invalidate old sessions/proofs and rotate the caller while preserving
its original method/time. Commit safe audit facts in the same transaction. Mailbox
proof does not refresh passkey authentication or become a recovery credential.

Serialize attachment with mailbox signup using the same email lock. If signup
already owns the address, attachment fails; if attachment wins, mailbox sign-in
must reject that account's passkey-required policy. Concurrent attachment to a
different target must revalidate the absent-email snapshot after the user lock.
An email-free operation holding a user lock must not then acquire an email lock;
that would reverse the established order. General stronger-account email changes,
deletion, recovery, cancellation and last-key policy remain AUTH-20 work.

## Verification and rollout

Keep published migrations immutable; add explicit migrations and test upgrades
from the existing mailbox schema, constraints and preserved data. Retain real
PostgreSQL owner/session lock-wait, expiry, rollback, replay, uniqueness and
cross-realm coverage. Run default and all-feature workspace suites sequentially.

Native Chromium platform and roaming virtual-authenticator cases must begin
anonymously, show no account/session before assertion, obtain a user with
`email: null`, and then authenticate through both account-bound and modal resident
discovery flows. Cover invalid registration/assertion context, RP/challenge/UV/
signature, browser and ceremony confusion. Test no-email session controls, weak
fallback denial before/after attachment, occupied-mailbox races and optional-email
serialization. Record actual browser/source versions and cleanup; virtual devices
do not establish real-device or other-browser interoperability.

Extend the existing core/passkeys, PostgreSQL/passkeys and experimental HTTP
feature folders with focused signup and email-attachment modules. Reuse the
existing protocol verifier and safe cookie/SMTP boundaries. Separate structural
extractions from behavior changes. Default server composition stays gated through
AUTH-20 and the remaining M03 evidence. No production-readiness, MFA/AAL or
conformance claim follows from this design.

## Alternatives and consequences

Rejected: placeholder mailbox identities, nullable email without policy enforcement,
registration-only authenticated sessions, email-based merge, automatic mailbox
recovery after attachment and a new generic transaction engine. The extra assertion
adds a browser ceremony but gives issuance actual private-key proof. Pending-only
identity allocation reduces abandoned-account state. Explicit policy creates
additional transaction and migration work, but keeps optional contact information
from silently changing authentication authority.
