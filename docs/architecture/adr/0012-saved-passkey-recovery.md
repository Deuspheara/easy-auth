# ADR 0012: Saved-code passkey recovery

Status: experimental saved-code configuration, claim scheduling/cancellation and
core/PostgreSQL replacement-key completion implemented in AUTH-20, 2026-10-19.
Explicit experimental HTTP transport and reference pages are implemented. Native
Chromium recovery uses actual signatures/SMTP plus an owned elapsed-time fixture;
physical-device/other-browser evidence and independent security review remain open. Ordinary enablement and stronger-policy activation
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

`PasskeyRecoverySetup` is explicit optional core/PostgreSQL configuration. The
separate experimental HTTP constructor now exposes prepare/confirm only; it adds
no recovery login, account-policy mutation or ordinary server composition. A genuine passkey-method session must remain within its original
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
rotation replaces them. A claim now consumes/reserves its code once at start;
replacement-key completion is now an explicit experimental core/PostgreSQL service.

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

## Explicit HTTP configuration

`passkey-recovery-setup` adds `experimental_passkey_recovery_setup_router`, preserving
older constructors and documents. Startup requires aligned realm/origin for all
services. POST `/v1/passkeys/recovery/code/prepare` accepts only `{}` and returns
`{id,code}` once after pending persistence. POST `/v1/passkeys/recovery/code/confirm`
accepts only `{id,code}` and returns 204 after commit. Both require the current
session cookie and exact Origin, reject query selectors, retain the 8 KiB JSON
boundary and use no-store/generic errors. Neither issues/rotates a session cookie.
GET cannot prepare a code. Private response serialization exposes only this code
at the transport boundary; Secret remains globally nonserializable and redacted.

Native platform/USB tests configure before contact attachment using actual signup
assertion proof, retain no browser storage, and then rotate configuration after a
separate real-SMTP contact proof. Existing management cases keep their own accounts
and all assertions, avoiding dilution of the shared admission policy. This proves
configuration transport; they do not exercise the replacement service below.

## Implemented claim scheduling and cancellation

The optional `PasskeyRecoveryClaims` core/PostgreSQL boundary exposes begin,
resume/status and cancellation only. The separate explicit HTTP composition below
wraps these operations; this service issues no replacement credential or session. Public readiness metadata is not verified
proof and must never authorize an application session or key binding.

A correct current saved code reserves one claim under owner/code locks. The claim
binds realm/owner/RP/code generation and a separately generated browser-secret
verifier. The server returns an opaque public claim ID and non-secret timing
metadata, never a raw browser capability. Same-browser begin retry returns the same
claim without changing its expiry or emitting duplicate audit/notice. A separate
resume operation retrieves that bound claim without its response ID or resubmitting
the code, so loss of the initial response does not lose progress. A different
browser cannot use the consumed code to resume or start another claim.

The fixed experimental policy is a 24-hour delay and seven-day claim lifetime.
Both use database time; the original delay is persisted with the claim. If a verified
contact exists at start, its fixed notice is queued atomically with reservation
and typed audit. The delay stays unset until successful SMTP acknowledgement under
the exact current, unexpired queue lease. Receipt completion locks owner, claim and
notice in that order, validates generation/cancellation, and rechecks original
claim and lease deadlines after final writes. The first receipt fixes the delay;
failed/stale/expired leases and late acknowledgements cannot create or restart it.
SMTP acknowledgement is transport acceptance, not proof the owner read the message.

For email-free accounts the delay starts at claim creation, with no independent
alert. Metadata states that limitation explicitly. This does not make saved codes
phishing resistant or compensate for absence of an independent notification channel.
Existing keys remain usable during the wait. Receipt delay may extend beyond the
original expiry after a long transport outage; recovery then stays unavailable.
Retries never extend that expiry or silently substitute another channel.

Cancellation is available before completion through the exact bound browser, a
genuine fresh passkey session, or the retained reserved saved code. The last path
lets an alerted owner who lost all keys deny a fraudulent claim. It grants denial
only: it cannot resume a different browser, reopen a code, bind a key or sign in.
The notice instructs the owner to use the service with an existing key or retained
code, never send the code by email. Messages contain no code/capability/link.
Cancellation invalidates queued start work and records typed attribution; a
session actor exists only for genuine-key cancellation. The code stays consumed.
New confirmed configuration invalidates old claims and their queued notices;
preparation alone preserves them. In-flight SMTP may arrive after cancellation,
but acknowledgement cannot restore authority. User deletion cascades code/claim/
notice state and erases historical claim attribution.

Source admission precedes lookup for every operation (40 per ten minutes). Code
verification also has a ten-attempt account budget. Continuation has a separate
ten-attempt owner/RP/browser budget: code guessing against a public account ID
cannot suppress a valid browser's progress. Its key includes the owner and RP even
when a browser capability is reused. Genuine-key cancellation uses independent
sensitive-action admission. Saved-code cancellation uses source admission only;
an account/submitted-code budget could be pre-exhausted before a claim to suppress
an alerted owner's denial. This high-entropy proof can only cancel, never grant
access. None of these paths remove source/resource bounds or weaken code-verification
limits. Account erasure removes its known account/current-capability buckets;
unlinked invalid-capability and source abuse metadata remains separately retained.

The application must retain its independently generated browser secret before
beginning and keep it through the wait. If that capability is lost, a consumed code
can cancel but cannot transfer recovery to another browser. After cancellation or
expiry, another claim requires newly configured proof under a working key; there
is no mailbox/password fallback. These explicit usability/compromise limits require
independent review and clear consent/instructions before activation.

## Implemented private replacement-key protocol

`PasskeyRecoveryReplacement` is a separate optional core/PostgreSQL service. It
accepts an explicit public owner/claim target and the already-bound browser secret;
it has no existing-session authority or client-selected realm/RP. Every database
stage validates the current claim, code generation, browser, cancellation/completion,
original expiry and elapsed delay/required receipt under the owner lock. It never
trusts the public `ready` metadata as an authorization grant. Admission uses the
same bounded source and owner/RP/browser continuation policy before loading state.

After eligibility, begin persists one private registration per claim and returns
only public options/transaction ID. A two-minute original ceremony deadline covers
both registration and assertion; restarting replaces only the candidate and cannot
extend the claim. Expired private rows are logically unusable and bounded to one
per claim; physical retention/cleanup remains operational work. Registration uses
the existing reviewed verifier, requests browser
residence and retains required origin/RP/challenge/UP/UV/context checks. It advances
the exact persisted registration snapshot to one private candidate plus an
account-bound assertion challenge. Neither stage creates a normal key, session,
authentication fact or policy upgrade. Candidates are absent from ordinary inventory
and sign-in lookup. Production does not weaken residence options for software tests.

Completion requires an actual signature from that candidate, then locks and
compares exact assertion and credential snapshots. RP-wide credential uniqueness
is checked before deleting existing keys, including keys owned in another realm.
For verified-mailbox owners it first acquires the email lock from a snapshot,
then locks the owner and revalidates that nullable email. This preserves the
email-before-owner order of proof consumers while allowing atomic proof removal.
Owner -> claim -> candidate order remains explicit after that optional email lock.

One transaction installs the proven candidate, removes all previous owner passkeys
across RPs, revokes old sessions, invalidates owner-bound enrollment/authentication/
contact/change/deletion/code-setup state and current-mailbox sign-in/reset proofs,
and removes other-RP saved-code configurations/claims. Discoverable proof completion
still rechecks the live key under the owner lock. It issues one `passkey`-method
session from the new assertion, records `passkey_recovered` with an owned issued
session and historical claim target, queues a fixed completion notice to an existing
verified contact, removes private candidate state and marks the claim completed.
The minimum original claim/ceremony deadline is checked after every final write.
Any storage error, wait-induced expiry or snapshot/collision failure rolls all of
this back, retaining the prior keys/sessions and retryable candidate.

The reserved code stays consumed; completion, cancellation, status and receipt
paths cannot revive that claim. Replaying completion never returns a stored bearer
or creates another session. If the successful response is lost, normal sign-in with
the newly installed key recovers access to the same account. After sign-in, configure
and confirm a replacement saved code; the old one cannot start another recovery.
Account authentication policy and contact ownership stay unchanged by this flow.
Email-free accounts receive no fabricated completion email. Custom delivery
adapters must implement `passkey_recovery_completed`, with the same non-secret,
retryable queue semantics as other notices.

This core/PostgreSQL implementation has software-authenticator transaction evidence,
not physical-device interoperability or independent policy approval. The reference
pages below now have native Chromium coverage; wider usability/device evidence and
safe activation remain required.

Stronger-policy activation must wait for implemented, reviewed recovery and real
private-key proof. Before ordinary enablement, test rollback, one-use/race behavior,
version changes, tenant/owner/browser/RP isolation, notification failure/receipt,
clock/lock expiry and cancellation, plus native and physical-device/browser flows.
These are remaining acceptance work, not a claimed property of configuration.


## Explicit experimental recovery HTTP

`passkey-recovery` exports `experimental_passkey_recovery_router` with named
`PasskeyRecoveryServices`. Startup validates all seven services against the trusted
realm and exact origin, reusing prior route builders/documents. Older constructors
retain their routes and full schemas. Ordinary server composition remains disabled.
The additive [full contract](../openapi-passkey-recovery.json) describes ten new
POST operations; no account/email resolver, GET grant, query selector or CORS
fallback is introduced. Outer JSON is closed, ordinary bodies retain 8 KiB, and
registration/assertion responses alone permit 32 KiB with the same core bounds.
All operations use the shared exact-Origin/no-store/redacted-error boundary.

Before consuming a saved code, the anonymous browser must successfully POST `{}`
to `/v1/passkeys/recovery/browser`. It establishes/reuses an independent HttpOnly,
Secure `__Host-auth-passkey-recovery` cookie (explicit loopback development has a
separate unprefixed name). Rebinding retains the same capability and refreshes
cookie retention only, never a database deadline. Clients must perform this step
immediately before starting a claim and retain the cookie through the wait. Claim
start requires it and does not return another capability, so a lost start response
can resume using only the public account ID and the already-established browser.
No code or browser secret enters URLs, returned metadata or browser storage APIs.
Clearing/losing that cookie can make a reserved claim unusable as already documented.

Claim start/resume/status/browser cancellation and all replacement operations reject
any session cookie, including expired/unknown ones: explicitly log out first. This
prevents recovery from silently replacing another browser account session. Other
purpose cookies cannot substitute for the recovery binding. Reserved-code denial
needs no browser cookie and grants no access. Genuine-key cancellation is instead
POST `/v1/passkeys/recovery/claims/cancel-with-key` with `{}` and a genuinely fresh
session. It selects the current owner/RP claim under the existing locks; an alerted
owner need not know a claimant-only UUID or saved code. The original explicit-ID
core cancellation remains supported. Custom claim repositories must implement
`cancel_current_passkey_recovery_with_key` with equivalent admission/ownership and
deadline semantics. No anonymous status lookup is added for this usability fix.

Only committed actual replacement assertion completion sets a fresh session cookie.
It clears stale auth/action cookies while retaining the independent recovery cookie,
which may bind another account's claim. Terminal database state prevents replay.
Neither binding, delay metadata, registration, cancellation nor any error sets a
session. Wrong/stale/cancelled proofs and persistence failures return generic errors
without success cookies; a lost successful finish response uses normal key sign-in.
The reference pages below supply explicit consent/instructions. Physical-device/
other-browser interoperability and independent policy approval remain separate gates,
not properties established by software tests or this experimental constructor.


## Reference pages and native evidence

Only the recovery constructor serves `/passkey-recovery` and
`/passkey-recovery/setup`, plus their same-origin module assets. They inherit CSP,
no-store/no-referrer and the existing browser boundary. Static GET serving prepares
no code or claim and issues no session. Earlier constructors remain unchanged.

The setup page requires explicit offline-retention consent, shows a prepared code
once, asks for reentry/retention confirmation, clears it after confirmation/navigation
and displays the authenticated public account ID to retain with the offline copy.
It does not claim to prove offline retention. A fresh working-key sign-in and
current-request cancellation use separate deliberate actions. The recovery page
requires explicit sign-out, code-consumption consent, manual same-browser resume/
status and a separate replacement confirmation. It explains the 24-hour delay,
seven-day cap, missing email-free alerts, SMTP/browser-loss limits and permanent
code consumption on cancellation. It never infers authority from device time or
metadata; every mutation still uses the unchanged backend proof boundary.

Proofs enter only POST bodies or HttpOnly cookies, never page URLs or browser
storage. The client strips unused URL query/fragment state, uses text/value DOM
properties, aborts page-scoped network/native work on navigation and clears secret
fields. It neither logs server errors/proofs nor loads third-party scripts. Lost
start responses resume using the existing cookie; lost finish responses direct the
owner to normal sign-in with the newly installed key and new saved-code configuration.
Browser JSON WebAuthn support is feature-detected and fails closed without fallback.

The owned native fixture uses the real server SMTP adapter and resident platform/
USB browser signatures. It has no seeded sessions/keys or HTTP clock endpoint.
Its local stdin command can backdate claim/linked timing only after an actual
required worker receipt, preserving original expiry and all production policy.
This proves browser/proof/transaction behavior across an arranged elapsed wait;
it does not establish a real 24-hour test run, physical hardware, a security audit
or general browser interoperability. Fixture executables must never be deployed.
