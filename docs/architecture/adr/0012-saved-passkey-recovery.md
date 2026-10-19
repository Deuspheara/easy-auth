# ADR 0012: Saved-code passkey recovery

Status: experimental saved-code configuration implemented in AUTH-20, 2026-10-19.
The delayed recovery protocol below is a proposal, pending implementation and
independent security review. Ordinary enablement and stronger-policy activation
are not approved by this document. No AAL, MFA, conformance or production claim.

## Threat and authority

An account without identity proofing cannot safely recover through an invented
identity check. A mailbox or password must not become an implicit substitute for
a passkey-required account. A surviving key already supports authentication and
replacement enrollment. All-keys-lost recovery needs a separately saved secret.

Use the existing `Secret` primitive: 256 random bits from the established OS RNG,
canonical printable encoding, SHA-256 verifier, redacted Debug and zeroization.
This adds no cryptography or dependency. The saved code is a bearer credential:
anyone who steals it may attempt recovery. It is not phishing resistant. Store it
offline and separately from passkeys; confirmation cannot prove that a user has
actually retained an offline copy. The existing [NIST event-management guidance](https://pages.nist.gov/800-63-4/sp800-63b/events/)
informs the saved-code lifecycle and notification review. This proposal does not
satisfy its AAL2 recovery requirements merely by using one saved code.

## Implemented configuration boundary

`PasskeyRecoverySetup` is explicit optional core/PostgreSQL configuration. It has
no HTTP endpoint, recovery login, account-policy mutation or ordinary server
composition. A genuine passkey-method session must remain within its original
five-minute authentication, idle and absolute deadlines. The configured RP must
have an owned key with actual assertion-use evidence. Mere registration, known
weaker methods, legacy timestamps and rotation do not suffice.

Preparation generates a code and returns it once only after the pending setup
commits. The adapter stores only its verifier, exact realm/owner/RP/session and
opaque setup ID, with a ten-minute pending lifetime. There is at most one pending
setup per owner/RP. Re-preparing replaces only that pending setup; an existing
confirmed code remains intact. The application must present the code through a
protected non-cacheable boundary, never a URL, email, log or persistent browser
storage, and prompt for offline retention and reentry.

Confirmation checks exact session/setup/code binding under owner-before-session
locks, then replaces the active verifier/version and consumes the pending setup.
It records `passkey_recovery_configured` with actor ownership and queues a fixed
`passkey_recovery_changed` notice to an existing verified contact in that same
transaction. Final database wall time caps every write, including consumption,
audit and notification. Failure retains the former confirmed code and makes valid
pending confirmation retryable. Replays and competing confirmations have one
winner. The existing sensitive user/source admission budget remains durable even
when confirmation fails. Active saved codes have no age expiry in this schema;
rotation replaces them, and the proposed recovery consumption is not implemented.

The active version is intended to invalidate requests authorized by an older
configuration. Setup does not revoke working keys/sessions or change policy. User
deletion cascades pending/active code storage and erases audit attribution. Session
revocation immediately makes its pending setup unusable. Physical cleanup of
expired/revoked pending rows remains an operational retention concern; the one-row
per owner/RP bound prevents accumulating repeated preparations.

`EmailDelivery::passkey_recovery_changed` is required. SMTP sends no code, credential
or sign-in/cancellation link. Failed delivery retains leased retry work. Email-free
accounts have no fabricated contact or independent email alert; audit remains
available through the consuming application's authorized operational path. This
configuration boundary alone does not establish usable all-keys-lost recovery.

## Proposed recovery protocol — not implemented

1. Admit by trusted source before lookup and by realm/account before verification.
   Require the saved code and an explicit public account identifier; never resolve
   ownership by a matching email. Bind the claim to configured realm/RP, current
   saved-code version, a separate HttpOnly browser secret and purpose-specific state.
   A code authorizes one claim only; a different browser cannot replay it. Specify
   same-browser retry after a lost response without creating another claim or
   storing a raw claim secret. Reject cross-purpose use as ordinary authentication.
2. Keep existing keys usable while a claim waits. Queue start notices to the existing
   verified channel and record audit. Proposed minimum delay: 24 hours after SMTP
   acceptance when a verified channel exists; delivery failure must not silently
   count as notification. Persist a delivery receipt for the exact claim/version.
   Email-free accounts need an explicit reviewed offline-only policy and honest
   absence of independent alerts; a waiting period does not compensate for that
   absence. No new address may be supplied during recovery to redirect notices.
3. Allow deliberate cancellation by genuine fresh existing-key authentication and
   by the exact claiming browser capability. Cancellation invalidates the claim and
   its provisional key, never revives a used code. Generation rotation invalidates
   prior claims. Cancellation races and delayed delivery must fail closed under
   the same owner lock. Specify claim expiry (proposed seven days), bounded pending
   state and durable failed-attempt budgets. Neither a queued notice nor a worker
   retry may restart or extend authorization deadlines.
4. After delay, use a short-lived private registration ceremony for one replacement
   key, followed by an actual signed assertion. Keep the candidate out of ordinary
   credential inventory/sign-in until final completion. Recheck exact owner/code
   generation/claim/browser/RP/state, absence of cancellation, notification receipt,
   delay and original deadlines after waits and final writes. Enforce RP-wide key
   uniqueness and existing protocol negatives through the reviewed verifier.
5. Commit replacement, code consumption, invalidation of prior keys/sessions/bound
   proofs, typed audit and completion notice atomically. Issue a passkey-method
   session only from the new key's actual fresh assertion; neither saved-code
   presentation nor waiting grants that method. Require replacement saved-code
   preparation/confirmation from the new key. Resolve lost-response retry without
   returning a new unrestricted grant or exposing a stored raw secret.

Stronger-policy activation must wait for implemented, reviewed recovery and real
private-key proof. Before ordinary enablement, test rollback, one-use/race behavior,
version changes, tenant/owner/browser/RP isolation, notification failure/receipt,
clock/lock expiry and cancellation, plus native and physical-device/browser flows.
These are remaining acceptance work, not a claimed property of configuration.
