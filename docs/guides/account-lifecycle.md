# Email changes and account deletion

These headless APIs work for email-only and password accounts. They derive the user and realm from the configured router/current session; callers cannot nominate a different account. Every POST requires the exact configured Origin. Each operation requires a genuine login within five minutes, checked again in the mutation transaction; using or rotating a session does not refresh that time.

After migration 0004, existing sessions still verify normally but cannot authorize sensitive operations until a fresh email/password login. The migration intentionally does not guess authentication time from session creation. Password-enrollment rotation preserves authentication time. Deploy the new binary and schema together across all replicas; mixed old/new workers and sensitive-operation implementations are unsupported during this alpha transition.

These mailbox-policy operations reject email-free and passkey-required accounts,
even with a fresh passkey session or proofs issued before a policy change. This
prevents a weaker lifecycle path while stronger-account operations remain
unfinished. Optional contact attachment is a separate experimental workflow; see the
[attachment guide](email-attachment.md) and [optional-mailbox model](optional-mailbox.md).

## Change email

1. Sign in freshly. POST `/v1/account/email/start` with `{email}` and your session cookie. A 202 sets a distinct HttpOnly email-change binding cookie and sends separate confirmation links to the current and proposed mailboxes. An occupied proposed address follows the same request/delivery path and will not be merged or overwritten at completion. No address changes yet.
2. Open each email in the requesting browser and click **Confirm this address**. `/email-change#token=…` removes the fragment before POST `/v1/account/email/confirm` with `{token}`. The initiating session and binding cookie must still be valid. The first proof returns 202; the second returns 204. Either confirmation order is accepted. Each proof is single use; both expire within five minutes, and the session must remain within its original five-minute authentication window. Restart after a fresh sign-in if the window closes.
3. Final confirmation preserves the opaque user ID and updates the verified address. All current sessions and pending account/email/reset proofs for the affected identity are invalidated. Cookies are cleared; sign in with the new address. Existing password credentials remain attached to the same user. A durable notice goes to the established old address, without naming the new address or including a credential.

A token from the wrong purpose, browser, realm, user or initiating session fails closed. Replaying a proof fails. An expired/stale/occupied final change has a generic 401 response, without identifying another account. Unique constraints and ordered locks prevent two users taking the same address concurrently. This is not account linking; an occupied address needs a separately reviewed linking/merge policy, currently unavailable.

## Delete authentication account

1. Sign in freshly. POST `/v1/account/delete/start` with `{"confirmation":"delete my account"}` and the current session cookie. A 202 sets the deletion-binding cookie and sends a separate proof to the current verified address. This request alone deletes nothing.
2. Open `/account-delete#token=…` in the requesting browser. The reference page explains the scope and requires typing **delete my account** before POST `/v1/account/delete/finish` with `{token,confirmation}`. The same fresh session and deletion cookie are mandatory. GET never consumes the proof. A successful 204 clears authentication cookies and removes the account transactionally.
3. The deleted account's passwords, sessions and pending account actions are removed through scoped relations; pending sign-in/reset proofs and owned email admission keys are removed explicitly. Its queued subject-linked notices are canceled, and its live audit subjects become NULL. Another tenant or user is unaffected. A subject-free, non-secret deletion notice is queued to the established address.

An already-authorized application request may finish after deletion; consuming applications retain authority over their own records and must implement their own deletion/access policy. This API does not delete business data, backups or already-delivered mail. The same address may register again with a new opaque user ID after a new email proof; the old identity or application privileges are not resurrected.

## Audit, notices and privacy limits

Live audit history retains realm, time and bounded event kind but removes the deleted subject UUID. This is deidentification in the live auth store, not a legal/compliance or irreversible-anonymity guarantee. Operators need separate backup/log/retention policies.

The shared queue is now `auth_security_notifications`; kind is a fixed allowlist. Email-change notices keep their user relation and are canceled if that user is deleted. The deletion notice has `user_id=NULL` and temporarily retains the established recipient so it can be delivered after deletion. Delivered notices are deleted. Failed notices remain visible after eight claims for explicit operator action; monitoring/redrive/retention are still M09 release requirements. An SMTP request already in flight may deliver after deletion and cannot be recalled. Do not expose recipients or queue rows through a public API.

Embedded adapters now implement `email_change`, `account_deletion`, `email_changed` and `account_deleted` in addition to existing mail operations. The worker calls `Auth::deliver_security_notice()` and dispatches exactly three known non-secret notice kinds. No generic event bus or credential outbox is introduced. See [recovery delivery behavior](password-recovery.md) for leases, retries and shutdown limits; update old SQL/worker names to the shared queue API.

The rate budget is shared with password/recovery actions: 10 attempts per owner email and 40 per source per fixed ten-minute window. Proofs and cookies are purpose-specific, browser-bound and verifier-only at rest. Current assurance is mailbox/password based; stronger-factor lifecycle policies and independent security review remain release gates. The conservative email normalization policy is unchanged.

## Verify

With the local services and password-enabled example configuration:

```sh
python3 scripts/smoke.py --lifecycle
# Or run the embedded example, then:
python3 scripts/smoke.py --embedded --lifecycle
```

The script creates only disposable synthetic accounts, checks actual SMTP confirmations/notices, stable identity across email change, old-session rejection, password continuity and confirmed deletion. PostgreSQL tests cover competing address changes, scope/binding/expiry, rollback, cleanup, audit deidentification and migration from the prior schema. See [ADR 0005](../architecture/adr/0005-account-lifecycle.md) and the [OWASP authentication baseline](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#changing-a-users-registered-email-address).

Audit deidentification also removes actor/affected-session references introduced by migration 0006. User/session/audit mutations and the deletion notice remain one transaction; [audit semantics](audit-events.md).
