# Password recovery

The opt-in password service supports browser-bound recovery. Enable the AUTH-12 password policy/corpus first; disabled password configuration returns 503 for valid reset operations. This flow changes an existing password only. It neither creates an account nor enrolls a password for an email-only account.

1. POST `/v1/password/reset/start` with `{email}` and the exact configured Origin. The server returns generic 202 and sets an HttpOnly reset-binding cookie. Every normalized email follows the same mail path; a reset request never revokes sessions or changes credentials.
2. Open the reset email in that browser within ten minutes. The trusted configured origin supplies `/reset#token=…`. The page removes the fragment before submitting it. GET never consumes the proof; no token is accepted in a query parameter. Cross-device completion is intentionally unsupported.
3. Confirm a new password in the reference form, or POST `/v1/password/reset/finish` with `{token,password}`, reset cookie and Origin. The same NFC, length, blocklist and Argon2 policy as enrollment applies. Successful completion returns 204 and clears reset/session cookies. It revokes all prior sessions and outstanding reset/sign-in proofs for that user/realm, queues a notification and requires a normal sign-in. It does not return a bearer credential or automatically authenticate.

Reset and email sign-in cookies have different names (`__Host-auth-reset` / `__Host-auth-browser` in HTTPS production; loopback development omits the prefix). Both are HttpOnly, SameSite=Lax, Path=/, and have no Domain. Reset cookies expire in ten minutes. Duplicate cookies, wrong browser/realm/purpose, missing or expired proof, replay and stale credential versions fail closed. Old password and session checks fail after the reset commits; already-authorized in-flight application actions may finish.

Start is generic for known, unknown and email-only accounts, including its template and delivery work. SMTP deliverability and small database/runtime differences mean perfectly equal network latency is not promised. A mailbox without a password receives an informational request link that cannot change credentials. Per-email/source admission is shared with password login/enrollment (10/40 per ten-minute fixed window); valid finish attempts also consume admission before hashing. Invalid random proofs do not run Argon2. Bodies, timeouts and hashing capacity remain bounded as described in the [password guide](passwords.md).

## Notifications and embedding

A successful reset commits a dedicated PostgreSQL notification row containing the established recipient and safe event identifiers. No password, hash, bearer or reset proof enters the notification queue, audit record or logs. The subject is `Your password was reset`; its text describes session invalidation and how to respond to an unauthorized change, without a sign-in link. Request-delivery failure leaves an expiring proof but no cookie returned; it does not change credentials. Notification-delivery failure after completion does not undo the reset or return a misleading reset failure.

The standalone binary and embedded example run `easy_auth_server::notification_worker(auth.clone())` alongside HTTP. Applications composing the core themselves must call `Auth::deliver_password_reset_notice()` repeatedly from one bounded worker, keep its handle and stop it at shutdown. `EmailDelivery` implements distinct `sign_in`, `password_reset` and `password_changed` operations. The last method must not send a credential. Claim/ack is realm scoped and stale leases cannot acknowledge newer delivery work.

Claims last 30 seconds; delivery has a ten-second core timeout. Failures back off 30 seconds, then double per attempt. A canceled worker's lease expires for another replica to reclaim. There are at most eight claims automatically; exhausted rows are retained for operator review. SMTP acceptance is not mailbox receipt. Duplicates are possible when a delivery succeeds but acknowledgment is lost. Future production monitoring, retention and authenticated operator redrive tooling remain M09 gates.

An operator can inspect aggregate backlog without returning recipients:

```sql
SELECT realm_id,
       count(*) FILTER (WHERE attempts < 8) AS pending,
       count(*) FILTER (WHERE attempts = 8) AS exhausted,
       min(created_at) AS oldest
FROM auth_password_reset_notifications GROUP BY realm_id;
```

Investigate persistent failures and correct SMTP before an explicitly authorized redrive. Do not expose this table or its recipients to public API users. Delivered rows are deleted; undelivered rows survive restarts. Account deletion later must cancel related delivery work; the composite user FK already cascades. A production retention/incident policy is still required.

This is email/password recovery at the alpha's existing mailbox assurance level. It is not a complete account-compromise remedy or a recovery policy for passkeys/MFA/provider accounts. Future stronger authentication must explicitly restrict mailbox bypass/recovery before deployment. See the [recovery decision](../architecture/adr/0004-password-recovery.md) and [OWASP baseline](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

## Verify locally

With PostgreSQL, Mailpit and the server running with the development corpus:

```sh
python3 scripts/smoke.py --recovery
# Or run the embedded example, then:
python3 scripts/smoke.py --embedded --recovery
```

The smoke uses synthetic per-run passwords, actual SMTP and the background worker. It checks old-password/session rejection, new sign-in, preserved user identity and a non-secret notification. Automated PostgreSQL tests also cover expiry, wrong purpose/realm/browser, concurrent resets, stale versions, transaction rollback, lease ownership, retry and exhaustion. Default CI uses no external provider credentials.
