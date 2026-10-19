# Optional mailbox and account policy

AUTH-53's identity/storage boundary supports users without email. Anonymous
passkey signup and verified-mailbox attachment are still being implemented;
this model change does not expose either workflow or enable ordinary passkey
composition. AUTH-20's stronger-account lifecycle/recovery remains a release gate.

## User contract

`GET /v1/session` returns required `id`, `realm_id`, `email` and `display_name`
fields. The last two are nullable. Existing mailbox accounts retain their IDs
and string email; `display_name` is initially `null`. An email-free account has
`email: null` and a bounded display label. Never use that label as identity,
authorization, a unique account selector or HTML; render it as text. No fake
mailbox is stored or returned.

Rust `User.email` is now `Option<String>`, with `display_name: Option<String>`
and a typed `authentication_policy`. This is an explicit alpha API change for
embedded consumers. Handle absence instead of substituting a placeholder email.
The HTTP user response does not expose policy or authentication-method metadata.
All three generated OpenAPI snapshots declare the nullable fields as required.

## Authority is separate from contact

Existing users retain `mailbox` policy. Email-free users require
`passkey_required` policy. This policy is persisted independently of contact
information: the presence of a verified mailbox does not make it a login or
recovery credential for a stronger account. There is no public policy-toggle API.
Additional passkey enrollment on a mailbox account does not silently upgrade it.

For passkey-required users, protected-user verification and inventory require a
passkey-method session. Inventory omits otherwise unexpired sessions whose method
does not satisfy policy. Email, password and legacy-unknown methods cannot be used
as passkey proof. Fresh owned-session revocation works without email and checks
the method/time again after the user lock. Logout can always revoke the caller's
own bearer. Rotation does not refresh authentication time or method.

Email/password login, password enrollment/reset and the current mailbox-based
email-change/deletion operations reject stronger accounts, including existing
proofs issued before a policy change. These checks run in the final transaction,
after relevant locks. Rejecting mail-only lifecycle operations does not complete
stronger-account deletion/recovery; AUTH-20 must implement those workflows.

Authenticated sensitive actions without email have separate durable budgets:
10 per realm/user and 40 per realm/source per fixed ten-minute window. Existing
mailbox actions retain their email/source budgets. Source identity comes from
trusted connection context. Custom `Repository` implementations must implement
`admit_user_action`; there is no permissive default.

## Migration and deployment

Migration `0009_optional_mailbox.sql` preserves existing user IDs, email verification
times, credentials, sessions and unknown-method provenance. It allows absent
email only with absent verification time, a bounded nonblank display label and
passkey-required policy. Present mailboxes remain realm-unique; distinct users may
have absent email and identical display labels. Existing mailbox insertion keeps
its verification-time default; trusted email-free creation must explicitly write
both email fields as NULL.

Deploy the schema and binary together across all alpha replicas. Older workers
do not enforce stronger-account policy or understand nullable user fields; mixed
versions are unsupported. Do not provision email-free accounts manually as a
replacement for the pending proof-completed signup flow. The public signup path
will require both registration and a genuine assertion before identity/session
creation, and mailbox attachment will require fresh passkey and mailbox proof.
See [ADR 0009](../architecture/adr/0009-passkey-first-identity.md).

Real PostgreSQL tests cover upgrade preservation, nullable/uniqueness constraints,
weak-method and fallback denial, preissued proofs, post-lock policy changes,
no-email session controls and NULL-to-email snapshot races. An HTTP/storage
fixture verifies exact null serialization and route rejection; it is not evidence
of anonymous signup or native private-key proof. Those remain AUTH-53 acceptance
work, alongside the existing browser/device interoperability gates.
