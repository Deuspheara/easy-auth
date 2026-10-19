# Experimental passkey management

AUTH-20 is in progress. Optional core/PostgreSQL and explicit experimental HTTP
management provide bounded inventory, rename and removal. All-keys-lost recovery,
stronger-policy activation and ordinary server enablement remain incomplete.
Those and required physical-device/browser evidence remain acceptance gates.
See [ADR 0011](../architecture/adr/0011-passkey-management-and-recovery.md).

Construct `PasskeyManagement` with a trusted realm, the existing configured
`PasskeyService`, and a `PasskeyManagementRepository`. Both embedding and standalone
composition must use these same use cases. Requests cannot select an account owner.

Every operation requires a live session from genuine passkey authentication within
five minutes. Mailbox/password/legacy sessions, future/stale authentication and
expired/revoked sessions fail with Unauthorized, regardless of whether the owner
has a mailbox or uses passkey-required policy. Rotation does not extend freshness.

Inventory returns at most ten credentials in the configured realm/owner/RP, ordered
by public UUID. Fields are `id`, `version`, `label`, `created_at_ms` and nullable
`last_used_at_ms`. No WebAuthn identifier, stored credential, owner or private
ceremony bytes are exposed. Inventory does not refresh authentication time.

Rename accepts the exact current version and a nonblank, bounded, control-free
label. It returns a new version; concurrent/stale metadata requests cannot silently
overwrite one another. Removal also requires the current version and leaves another
key in that realm/account/RP which has actually authenticated. Sign in with an existing key to authorize additional enrollment, then
sign in with the replacement before removing the prior working key. Merely creating
a credential is not evidence that its owner can use it. Last-proven-key removal
is denied for both mailbox and passkey-required accounts.

Removal revokes all owned sessions, including its caller, and cancels session-bound
enrollment/contact/lifecycle and account-bound sign-in ceremonies. Sign in again
with a remaining working key. An already verified assertion for a removed key must
still fail its final owner/key/ceremony checks. Account policy, UUID and contact
are unchanged; this operation never enables mailbox/password fallback.

Mutations share the existing per-user/source sensitive-action admission budget;
failed operations still spend admission. Owner-before-session-before-key locks
serialize changes, and final database-time checks follow all potentially blocking
writes. Expiry rolls back key metadata/removal, session/proof changes, audit and
notice together. The final check precedes commit/response latency.

Typed `passkey_renamed`/`passkey_removed` audit facts retain the public target UUID,
owner and actor session. Target UUIDs are historical identifiers without a live-key
foreign key; subject erasure clears them with all other attribution. Fixed non-secret
`passkeys_changed` notices use only an existing verified contact and the durable
leased/retry queue. `EmailDelivery::passkeys_changed` is a required delivery port;
implementations must report unavailable delivery honestly. The real SMTP adapter
implements it. No raw credential, label, recovery secret or sign-in link enters a
notice. Email-free users have no fabricated notification address or implied email
recovery; recovery notification limits remain explicit unfinished AUTH-20 work.

Migration 0012 adds management versions and bounded target/audit/notice schema.
Existing key encodings, metadata, owner IDs and session provenance are preserved;
upgrade does not invent successful key use. Published migrations remain immutable.

## Experimental HTTP contract

Enable `easy-auth-axum/passkey-management` and explicitly construct
`experimental_passkey_management_router` with aligned Auth, BrowserConfig,
enrollment, sign-in, signup and management services. Every service must share the
configured realm/origin; mismatches fail startup. Earlier constructors and the
ordinary server do not expose these management endpoints. Its full
[OpenAPI document](../architecture/openapi-passkey-management.json) includes all
prior base/enrollment/authentication/signup/contact routes unchanged.

| Route | Input | Committed result |
| --- | --- | --- |
| `GET /v1/passkeys` | Session cookie; no query fields | 200 `{passkeys:[...]}`; at most ten public metadata records |
| `POST /v1/passkeys/rename` | `{id,version,label}` plus session and exact Origin | 200 `{version}`; label/version changed |
| `POST /v1/passkeys/remove` | `{id,version}` plus session and exact Origin | 204; all auth/action cookies cleared after removal/session invalidation |

Management uses an 8 KiB body limit, closed JSON objects, existing host-cookie
parsing and generic errors. Invalid/stale/foreign/last-working-key targets and
weak/stale method authority return the same 401. Invalid fields/labels/queries
return 400, wrong Origin 403, large/wrong-media bodies 413/415, admission 429 and
storage or delivery-queue persistence failures 503. SMTP delivery happens after
commit through the leased worker; a later transport failure remains retryable and
does not change a committed management response. All responses use no-store/CSP and the shared
browser boundary. A rejected or rolled-back operation returns no success cookies.
There is no management-cookie, arbitrary owner/RP selection, HTTP policy engine
or application permission system.

The native SMTP fixture now exercises management using independent resident
platform and USB virtual authenticators. CDP presence selection models choosing
one device; it neither exports private keys nor modifies stored credentials.
The server's original exclusion/residence/required-UV options remain intact.
It verifies actual removed-key signatures are rejected and the same challenge can
still complete with a surviving key. Four fixed notices pass through the real
SMTP worker. Virtual-device results do not establish physical-device or other-
browser interoperability, recovery safety or general activation readiness.


## Experimental saved-code configuration

The optional `PasskeyRecoverySetup` core service and
`PasskeyRecoverySetupRepository` adapter prepare and confirm a saved recovery code.
A separate experimental HTTP constructor now exposes configuration. There is no
recovery authentication endpoint; this must not be advertised as a working
all-keys-lost recovery flow. It never changes
account policy or ordinary server enablement. See
[ADR 0012](../architecture/adr/0012-saved-passkey-recovery.md) for the implemented
configuration, claim and private replacement boundaries plus the remaining review
and HTTP/activation gates.

`prepare(session, source)` requires actual fresh passkey-method authority and an
owned key with assertion-use evidence in the configured RP. It returns a pending
ID and a `Secret` exactly once after persistence. Show the code only through a
protected non-cacheable boundary; have the user save it offline and reenter it.
Do not log, serialize implicitly, email, put it in URLs or persistent browser
storage. `confirm(session, source, id, code)` must use the exact initiating session
and pending ID/code before both original authentication and setup deadlines.

Only verifiers are stored. Re-preparing replaces one pending setup but preserves
the active code; confirmation atomically replaces the active version, consumes the
pending setup, records actor-owned audit and queues a fixed verified-contact notice.
A rejected or failed confirmation retains the old code and pending retry. Known
weaker/legacy/stale/future/revoked methods, foreign owners/realms/RPs/sessions and
wrong/replayed codes fail closed. Failed attempts consume the shared sensitive
admission budget. Rotation changes neither session method/time nor account policy.

`EmailDelivery::passkey_recovery_changed` is a required delivery-port addition.
The SMTP adapter supplies a purpose-specific message without credentials or links;
failed delivery remains queued for retry. Email-free users have no fabricated
address or independent email alert. Physical-device/browser and independently
reviewed delayed recovery/activation remain acceptance gates. Migration 0013 is
additive and creates no saved codes for existing accounts.


For the dedicated local notice transport check, start the documented PostgreSQL and
Mailpit services, then run `cargo build --locked -p easy-auth-server --bin easy-auth`
and `python3 scripts/smoke_recovery_notice.py`. The script creates an owned random
database/recipient and queues configuration/start/cancellation/completion fixtures through the normal worker;
its dummy verifier/claim rows do not represent authorization or a recovery login.
It verifies SMTP content, acknowledgement and the full receipt delay, removes
only its four exact owned messages and
drops its database. CI supplies its PostgreSQL service container explicitly through
`EASY_AUTH_SMOKE_POSTGRES_CONTAINER`; database URLs must remain loopback test URLs.


### Explicit HTTP saved-code configuration

Enable `easy-auth-axum/passkey-recovery-setup` and construct
`experimental_passkey_recovery_setup_router` with aligned Auth, BrowserConfig,
enrollment, sign-in, signup, management and recovery-setup services. Earlier
constructors and ordinary embedding/server composition expose neither new route.
The [full OpenAPI document](../architecture/openapi-passkey-recovery-setup.json)
preserves every prior route/schema and adds:

| Route | Closed JSON input | Result |
| --- | --- | --- |
| `POST /v1/passkeys/recovery/code/prepare` | `{}` | 200 `{id,code}` once after pending persistence |
| `POST /v1/passkeys/recovery/code/confirm` | `{id,code}` | 204 after atomic confirmation/audit/notice commit |

Both require the current session cookie and exact configured Origin. Inputs cannot
nominate an owner/realm/RP, query fields are rejected, bodies are limited to 8 KiB,
and the code uses the canonical existing 43-character Secret encoding. Invalid
fields/query return 400, weak/stale/foreign/replayed authority or incorrect code
401, rejected Origin 403, oversized/wrong-media body 413/415, admission 429 and
persistence failure 503. Errors are generic and never echo a code or request body.

Prepare responses use no-store/CSP, contain no private verifier/state and set no
new cookie. The response contains the raw recovery code: show it once through a
protected interface for offline retention and confirmation. No later endpoint
returns it. Confirmation and failures also issue no session/action cookies and
never activate policy. Existing sessions remain unchanged; confirmation after a
session rotation must restart setup under the new genuine fresh session. SMTP
transport failure after commit remains queued/retryable and does not undo the
configuration response. Email-free confirmation sends no fabricated email.


## Experimental recovery claim state

`PasskeyRecoveryClaims` currently provides core/PostgreSQL `begin`, `resume`,
`status`, `cancel`, `cancel_with_key`, `cancel_current_with_key` and `cancel_with_code`.
This service issues no key or session; the explicit HTTP wrapper is described below. These methods must not be advertised
as working all-keys-lost login. See [ADR 0012](../architecture/adr/0012-saved-passkey-recovery.md).

Begin supplies the explicit public account ID, saved code and a separate browser
secret retained before the request. A code authorizes one browser-bound claim in
the configured realm/RP. Same-browser retry preserves its ID/times and single audit/
notice; resume can recover a lost response ID using the bound browser without
rechecking the code. Status returns metadata only, with a 24-hour wait and original
seven-day expiry. With a verified contact, the wait starts only after a current
unexpired SMTP lease is acknowledged. Email-free claims start their wait at creation
and explicitly have no independent notification. SMTP failure never becomes a
successful receipt, fallback channel or extended claim deadline.

A bound browser or genuine fresh key can cancel. An alerted owner without a key
may also use the retained saved code to cancel only the existing claim, including
from a different browser. No cancellation reopens the code or authenticates a user.
Keep the code until completion/cancellation instructions are resolved; never email
it. New confirmed code configuration invalidates older claims, while preparing
an unconfirmed replacement preserves them. Loss of the original browser capability,
expiry or cancellation may require a working key to configure new recovery proof;
there is no hidden mailbox/password recovery. Activation awaits independent review
of these limits and native/physical-device recovery evidence.

Source admission remains 40 attempts per ten minutes. Begin also spends a ten-attempt
account code-verification budget; continuation spends a separate ten-attempt
owner/RP/browser budget. A known account ID cannot exhaust a valid browser's budget.
Fresh-key cancellation has independent sensitive-action admission. Deny-only
saved-code cancellation has source admission without an account/code counter that
could be pre-exhausted to protect a fraudulent claim. `EmailDelivery` additionally
requires `passkey_recovery_started` and `passkey_recovery_cancelled`; the real SMTP
adapter supplies fixed non-secret messages, and failure remains retryable. A receipt
proves SMTP acceptance rather than human receipt or independent security review.


## Experimental replacement completion

After claim eligibility, a separately constructed `PasskeyRecoveryReplacement`
accepts `PasskeyRecoveryTarget { user_id, claim_id }`, the retained browser secret
and trusted source. `begin` returns private-registration public options and a
transaction UUID; `finish_registration` verifies the response and returns an
assertion challenge for the provisional key. `finish` requires its actual signed
assertion and returns a new session secret only after atomic completion. All stages
revalidate claim generation/delay/receipt/binding/deadlines in PostgreSQL; a `ready`
status response is never permission by itself. The candidate is not a normal key.

Completion replaces all previous owner passkeys across RPs and revokes old sessions
and bound proofs; other-RP recovery codes are invalidated. The current code stays
consumed. Contact and account policy are unchanged. A verified contact receives the
fixed `passkey_recovery_completed` notice; email-free owners have no fabricated
alert. `EmailDelivery` requires the corresponding method for custom adapters.

Lost completion response: sign in normally using the newly installed key, then
configure/confirm a new saved code. Completion replay returns no bearer or second
grant. A failed transaction preserves the previous keys and candidate for a valid
retry within the original two-minute ceremony and seven-day claim caps. Restarting
candidate registration invalidates its prior challenge and does not reset the claim.

The explicit HTTP transport below is available, with no reference recovery page
yet. Independent policy review, native recovery/browser/device verification, usable
consent/instructions and safe ordinary activation remain required.


## Experimental recovery HTTP

Enable `easy-auth-axum/passkey-recovery` and call
`experimental_passkey_recovery_router(auth, browser, PasskeyRecoveryServices { ... })`
with the seven explicitly aligned passkey services. Older constructors and ordinary
embedded/standalone composition retain their existing routes. Use the
[full HTTP contract](../architecture/openapi-passkey-recovery.json) and
[endpoint table](../architecture/api-contract.md); no reference recovery page or
production activation is provided by this feature.

1. Explain the bearer-code, fixed delay, notification and browser-loss limits before
   consuming proof. A reserved code cannot restart after cancellation/expiry. Retain
   an independent offline code and, where possible, multiple working keys. Retain
   the public account UUID from authenticated `GET /v1/session` alongside the code;
   the configuration preparation ID is a different pending identifier. Do not
   offer mailbox/password fallback or claim that email-free accounts get alerts.
2. Explicitly log out any existing session. Immediately before starting recovery,
   POST `{}` to `/v1/passkeys/recovery/browser` and await its cookie response. It
   establishes/reuses `__Host-auth-passkey-recovery`, HttpOnly/Secure/Path=/ and
   SameSite=Lax, with seven-day retention. Explicit loopback development uses
   `auth-passkey-recovery`. Rebinding preserves the capability and never extends
   a claim. Keep this browser/cookie through the wait; do not copy it into URLs,
   JavaScript storage, email or logs.
3. POST `{account_id,code}` to `claims/start`. Use the public opaque account ID,
   never an email resolver. Only the browser cookie is authority to resume the
   reserved claim; metadata includes its public UUID/times and notification flag.
   On a lost start response, POST `{account_id}` to `claims/resume`, preserving the
   cookie. Status uses `{account_id,claim_id}` and grants no permission by itself.
4. While waiting, existing keys remain usable. An alerted owner can sign in freshly
   with a key and POST `{}` to `claims/cancel-with-key`; no claimant-only UUID or
   saved code is needed. Bound browsers can use `claims/cancel`; retained codes can
   use `claims/cancel-with-code` from an anonymous browser. These deny only and never
   reopen the code. Email alerts contain no credential or cancellation link.
5. Once eligible, POST the public account/claim target to `replacement/start`, then
   send the actual `navigator.credentials.create` response to `replacement/registration`
   and its separately signed `navigator.credentials.get` result to `replacement/finish`.
   Send `transaction_id` with both responses. Core still validates delay/receipt,
   generation, exact browser/owner/RP, proof and original deadlines at every stage.
   Registration cannot sign in, and cancellation/rotation invalidates candidates.
6. Only committed final assertion sets a fresh session. Old owner keys/sessions/
   proofs are invalidated. The independent recovery cookie is retained for any
   other account's claim; terminal state prevents replay. If the successful response
   is lost, sign in normally with the installed replacement key. Configure and
   confirm a new offline code afterward; the reserved code stays consumed.

All ten new operations are POST-only, require exact Origin, reject query selectors
and closed-body extras, and use no-store/generic errors. Anonymous operations reject
even expired/unknown session cookies, so they cannot silently switch accounts.
Cancel-with-key is the deliberate authenticated exception and infers ownership
only from its genuinely fresh session. A failing response never sets a success
cookie. Custom claim repositories additionally implement
`cancel_current_passkey_recovery_with_key` with the same locked policy; the existing
explicit-ID core cancellation API remains supported.
