# Threat model — alpha design, before credential flows

In-progress optional Apple capture retains credentials only after the same
initiated response passes signed identity/nonce/source verification. Opaque
mapped/capture types expose no raw-token upload or proof constructor. Atomic
final completion encrypts against actual resolved realm/source/client/identity/
grant binding; the provider client is inside the authenticated payload too.
Missing vault, audit failure, source disable and original-cap expiry roll back
local authority and capture together. Local unlink/account erasure queue encrypted
jobs through a schema trigger; local user/contact/subject data is not copied into
the ledger. Explicit workers claim finite source-scoped leases before network I/O,
compare authenticated provider-client binding, reuse the protected signer and send
only to fixed Apple HTTPS through the reviewed pinned/TLS adapter. Only empty200
can produce an opaque confirmation. Final lease/version/time checks after waits
prevent stale acknowledgment; lost responses retry after bounded backoff. Errors
retain ciphertext with finite categories, never raw provider details. Explicit
bounded realm maintenance erases expired unconfirmed ciphertext and later terminal
metadata; it must be scheduled even without active source workers. No automatic
TTL or real-provider qualification is established. Explicit Axum capture/link selection keeps matching concrete authorization and
final commit services together; default builders still discard credentials.
Missing protection cannot select fallback, and raw grants never reach HTTP output.
Original cookies, purpose, Origin, cross-site delivery and local owner checks remain
unchanged. Owned Chromium/PG checks now exercise both selected paths through local unlink,
finite provider failure, actual backoff and confirmed erasure; a separately built
capture/linking-disabled probe preserves ciphertext through ordinary repository
account erasure. These checks use offline provider ports and establish no live
Apple registration, OS delivery or provider revocation. A job or elapsed token lifetime never establishes remote revocation.

Explicit social web linking requires trusted concrete selection, exact-Origin
closed JSON and four independent host-only private Link cookies per provider.
Displayed owner UUIDs only reject an unexpected session; original purpose/session
proof and final core/PG checks confer authority. Google GET and Apple's state-only
same-origin presentation hint cannot consume/exchange/mutate. Apple cross-site
delivery remains cookie/storage-free. Unique state hints prevent ambiguous UI;
callback-aware cancellation prevents stale pages clearing newer proof. Scripts
remove/scrub returns, fence late responses across navigation/restoration, discard
raw input before finish and never retry credential completion. Local unlink remains
distinct from the explicitly selected background Apple grant revocation component.

Explicit social linking uses a separate Link purpose and original fresh owner/
session with a signed nonce-bound provider result; matching email/profile never
selects a local owner. Default sign-in/deletion cannot consume a linking proof.
Current target/source policy, exact subject uniqueness and earliest original caps
are rechecked under locks after provider I/O and final writes. Explicit-linked
storage permits only the existing mailbox policy's optional provider source;
historical JIT records and passkey requirements gain no fallback. Local-only
credential mutations still reject provider methods even with recent signed time.

Unlink requires a genuinely fresh retained method and rejects removal of its own
OIDC source. Reciprocal attempts serialize on owner and revalidate retained source
after waits. Only removed-source sessions are revoked/detached; their historical
method/revision/timestamps/audit rows remain. Detached source rows cannot be
unrevoked or validated. Scoped cooldown blocks old verified callbacks from
reattaching/JIT replacement. Link/unlink/audit/verified-local-contact notice enqueue
commit atomically; notices use no provider recipient. Remote grant revocation,
native linking, ordinary activation and real-provider qualification remain gated.
See [ADR0044](../architecture/adr/0044-explicit-social-identity-linking.md).

The optional Apple backend signs only fixed ES256 team/client/audience claims
from one protected P-256 key with a finite operator window. Five-minute secrets
are capped at key retirement; signing capacity remains owned through cancellation.
No arbitrary signing endpoint, default key, retired-key fallback or raw diagnostic
is exposed. Native library memory copies are not claimed erased.

The explicit Apple profile fixes issuer/endpoints/Post authentication and RS256,
retains private browser/state/nonce/provider-source/client/realm/revision and original caps,
and requires an actually verified signed nonce after one-use code redemption.
Its documented provider-specific wire contract does not pretend to offer S256;
generic OIDC/Google retain that requirement. Native raw/SHA256-hex convention and
web/native kind are immutable trusted composition, never inferred from a token or
selected by a callback. Changing that policy requires trusted reconfiguration,
a new revision and replacement services. A native code result is not proof of
OS delivery; actual Authentication Services and registered-client checks remain.

Only the Apple profile accepts exact signed boolean/text verification flags and
missing/empty managed email. Generic/Google reject text at the original signed
parsing stage. Unsigned initial names stay separate from identity/mapping, require
text rendering and may disappear on later consent. No email matching, invented
freshness, stronger-account fallback or local authority follows from presentation.
A front-channel token cannot replace initiated backend code exchange. Final mapped
identity/session commit still rechecks policy/subject/deadline under existing locks.

No ordinary Apple startup or session-cookie policy is changed. Explicit `apple-web`
uses one32KiB form-urlencoded cross-site handoff that reads no cookies/storage and
cannot consume state, exchange tokens or commit a session. Escaped inert template
data is removed immediately by fixed same-origin script; navigation/restoration
and pre-finish discard prevent automatic repeat. A deliberate same-origin finish
retains exact Origin/private Lax cookies/core verification and final atomic commit.
Stale/malformed state cannot clear newer proof; callback cancel also checks its
returned state. Any ambient session cookie prevents silent account replacement.
Client IP keys committed abuse admission, not immutable identity. Owned browser
fixtures exercise actual cross-site cookie omission and same-origin return; they
establish no real Apple registration or OS behavior. Linking/deletion remain rejected
by this sign-in component. Grant custody/revocation, real web/native acceptance
and a usable account lifecycle remain required before activation. See
[ADR0043](../architecture/adr/0043-apple-code-flow.md).

The [reference UI](../architecture/adr/0042-reference-account-ui.md) consumes only
selected-interface booleans and current account policy metadata. Compiled features,
contact email, view query and UI visibility grant no method, fresh proof or fallback.
The closed presentation selector hides unselected methods; inbox/resend follows an
actual start on this page and uses only the in-memory email. No query supplies a
resend address or recovery proof. Explicit resend retains existing admission limits. Issuer/
label text never becomes markup or a navigation target. Existing HTTP and storage
checks remain authoritative after every click. Password inputs are cleared after
attempts/navigation; native errors retain fixed categories, and credential POSTs
are never automatically retried. Navigation aborts and view generations reject
late rendering, with current-owner checks before sensitive actions. This does not
create a browser-wide atomic account epoch. Fixed template style insertion uses
only the exact CSP-allowlisted combined Basecoat/token/layout stylesheet hash; style attributes, other inline
styles, third-party resources and embedded frames remain denied. Explicit form
POST methods prevent GET-query credential leakage if module initialization fails.
Explicit passkey management can offer native reauthentication only after the API
rejects freshness. Confirmation explains normal logout of this browser; cancellation
preserves its session. The new assertion is account-bound to the confirmed owner,
with current view/owner checks before logout and an actual same-owner session read
after the single finish. Only inventory GET follows successful verification; no
credential completion retry or weaker fallback is introduced. Return-to-page
metadata reads avoid active operations, discard stale views and clear unfinished
forms on observed owner change; browser-wide account switching is still not atomic.
Optional Motion mini loads independently of authentication and only animates
committed view wrappers. Owned handles cancel on view/account invalidation and
pagehide; completion cleans individual opacity/transform CSSOM properties without
restoring a style attribute. Reduced motion/forced colors retain static content.
No animation, completion callback or timer establishes authentication or moves
focus. Real-browser CSP checks remain required for each selected library version.
The fixed licensed Inter asset is served locally with same-origin font permission;
there is no remote font origin, runtime palette input or new script permission.

The read-only linked-provider inventory in [ADR0041](../architecture/adr/0041-linked-provider-inventory.md)
uses the existing source-aware active-caller transaction and configured realm.
Only the locked owner's public identity UUID, protocol and immutable issuer are
projected; subjects, provider claims, email, credentials and verifiers stay private.
The protocol-plus-UUID cursor cannot select another owner or realm. Metadata does
not establish current trust, enable a source, link identities or grant a fallback.
Final retained-session deadline checks and rollback remain mandatory after the
read; current source disable/revocation rejects old caller proof. UI output must
use text, with no issuer-derived navigation or HTML. Public password-service
presence is composition metadata, never permission to use a weaker method.

Current SAML activation policy: [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md) permits explicitly configured
normal SAML by maintainer direction, waiving independent review. Default-off,
trusted persisted configuration and every protocol/security check remain required.
Earlier source-disabled stage descriptions below are superseded only as to
activation policy; their assurance gaps remain unverified, not independently approved.


AUTH-55's implemented preparation purpose binds a current provider-required
owner/session and exact configuration/policy revision under source-before-owner
locks. Old/unknown authentication time may initiate reauthentication but grants
no deletion; idle/absolute expiry, revocation and policy/source changes still deny.
Sign-in/linking purposes cannot substitute for it, and its verified proof cannot
mint a session through either sign-in layer. Maximum-age/login request parameters
are not authentication evidence. The optional final transaction now requires the
initiating session's exact subject/source and genuine recent signed `auth_time`,
retaining the earliest proof/session/freshness cap through destructive writes.
Final expiry or storage failure restores account/audit/notice/cooldown state;
consumed OAuth state stays consumed. No verified contact means no invented notice.
The opt-in HTTP/browser composition uses exact-Origin POSTs, independent HttpOnly
proof cookies, session-derived owner and two destructive confirmations. Its callback
GET is static and never consumes proof. Owned Keycloak-to-HTTP acceptance now covers the real routes/pages; ordinary
activation stays gated.
See [ADR 0017](../architecture/adr/0017-provider-account-deletion.md).

AUTH-30's optional core mapping consumes only a verified signed identity bound to
the exact trusted realm/connection/client/revision and explicit issuer allowlist.
Display selection has no email/alternate-field fallback. JIT configuration defaults
to deny; mapping grants no local identity/session. Trusted policy persistence uses
a fresh revision and cancels old pending state in the same transaction; faults roll
back both. Disable is preserved. The final sign-in transaction locks configuration/
policy, serializes the exact scoped subject and rechecks original authority after
all writes before committing user/identity/session/audit together. JIT deny blocks
new owners; matching provider email cannot select an existing account. Provider
sessions retain exact identity/revision and optional true auth_time; current source
checks precede owner/session locks and cannot invent freshness. Provider-required
policy rejects mailbox/password/passkey/recovery fallback even with verified contact.
Deletion installs a scoped five-minute cooldown without raw subject/user reference;
expired pseudonymous hashes are pruned opportunistically, not on an autonomous timer.
Linking, provider-only lifecycle endpoints, ordinary activation and final acceptance
remain gated. [ADR 0016](../architecture/adr/0016-oidc-identity-mapping.md)
distinguishes implemented mapping from those unimplemented safeguards.

AUTH-22's optional core/PostgreSQL OAuth transaction boundary binds realm,
connection/client revision, purpose, original linking owner/session and independent
state/browser/nonce/PKCE verifiers. Required-issuer versus unique dedicated callback
defense is explicit; a present wrong issuer is always rejected. Raw PKCE is retained
only by protected transient transport, not persisted in SQL or sent in authorization
URLs. No HTTP transport exists yet. One-use state consumption grants only exchange
context, never an identity/session. Configuration disable and final deadlines are
checked under locks after blocking writes; actual provider identity commit must
recheck them again after network exchange. Account policy, external token signature/
nonce validation, final identity/session atomicity, reviewed egress and real-provider
checks remain release gates. See [ADR 0013](../architecture/adr/0013-oauth-state-transactions.md).

Created 2026-10-18. Not a security audit. Assets: user identity, credential verifiers, active sessions, provider secrets/signing keys, email delivery and audit integrity. Actors: unauthenticated remote attacker, malicious browser origin, malicious configured/unconfigured IdP, compromised mailbox, compromised application/tenant, operator and stolen database/backup. Trust boundaries: browser/HTTP, core/persistence, outbound provider network, SMTP, configuration and application authorization.

| Threat | Required control | Evidence/release gate |
|---|---|---|
| Email account takeover / enumeration | Browser-bound single-use high-entropy proof; generic start response; no email auto-link; email compromise acknowledged | Expiry, mismatch, enumeration-shape and replay tests; stronger methods later |
| Login CSRF, CSRF, fixation | Exact Origin on every browser POST, HttpOnly host cookies, deliberate SameSite, fresh secret per authentication | Missing/null/wrong Origin, old cookie and duplicate-cookie tests |
| Session theft/replay | Only verifier in DB, idle+absolute expiry, DB validation, logout/revoke-all; TLS | DB expiry and immediate subsequent-request revocation tests; active bearer theft remains usable until revoked |
| Refresh theft | Atomic rotation and family reuse detection; secure native storage | Native release blocked pending replay tests |
| OAuth code injection/mix-up/state or nonce reuse | Connection+client+browser-bound expiring transaction, S256, issuer/nonce/audience/signature checks; atomic consume | M04/M05 wrong-state/nonce/issuer/audience/provider/replay corpus |
| Open redirect | Exact registered redirect allowlist; never redirect to arbitrary user input | M07 invalid redirect tests |
| Discovery/metadata SSRF | Explicit admin connections; HTTPS; DNS/IP/port allowlists, no redirects, bounded response, block private/link-local/metadata addresses unless explicit local test policy | M05 DNS rebinding/redirect/private-network tests |
| SAML signature wrapping/XXE/replay | Reviewed XML/signature engine; use only verified content; reject DTD/external entities/duplicate IDs, pinned certs, correlation and all conditions | Hard M06 blocker until signed fixture and attack corpus passes |
| RP/origin manipulation | Server-owned exact RP/origin, high-level webauthn-rs, UV, server-persisted single-use challenges | Core/PG/HTTP negatives and twenty Chromium virtual-authenticator registration/assertion cases; other browsers, real devices and stronger-account recovery remain gates |
| Unsafe linking / recovery downgrade | Fresh proof of both identities; no matching-email merge; last-credential and recovery policies; notifications/audit | M02/M03/M04 negative linking tests |
| Tenant isolation / privilege escalation | Realm on every query/constraint; trusted router realm; no app membership/permissions in auth core | Cross-realm FK/query tests; app independently authorizes actions |
| Brute force / spraying / mail abuse | Shared admission by realm+email and source IP; overall resource bounds; no trusted forwarded IP by default | Concurrent rate tests and load/retention plan |
| Secret leakage / compromised config | Redacted errors/logging, secret types, bounded audit events, least-privilege roles, protected keys, no query tokens | Log review/secret scan; M09 rotation and incident drills |
| Resource exhaustion | 8 KiB initial request bound, timeouts, bounded DB pool/SMTP and challenge admission | Oversize/timeout tests; M09 load evidence |
| Malicious connection disable/rollover race | Recheck connection status at commit; issuer/key binding; cert/key overlap policies | M05/M06/M07 concurrency and rollover tests |

A database writer or compromised server can mint/change identities; verifier hashing protects against read-only database theft, not a compromised verifier. Mailbox-only authentication has limited assurance and must not serve as an invisible bypass for stronger credentials. A stolen live cookie is a bearer credential. In-flight requests may finish after revocation; critical application actions require domain-level authorization/transaction policies.

AUTH-53's [email-free identity design](../architecture/adr/0009-passkey-first-identity.md)
now has optional core/PostgreSQL signup: pending-only identity allocation, separate
verified assertion, exact proof snapshots and atomic one-use completion. Final
expiry follows all writes, including session/audit waits. Realm/browser caps and
durable admission bound pending resources. Experimental HTTP signup rejects any
existing session cookie, requires exact Origin and browser binding, and has native
resident platform/USB proof and signed-context negatives. Contact attachment now
requires an original fresh passkey session plus an independent one-use mailbox
proof. Both stages recheck freshness after potentially blocking writes; final
consumption follows session/audit writes. Target-email before owner/session locks
serialize mailbox signup and competing attachments. Tests cover both race orderings,
occupied-address denial, exact session/browser/realm binding, rollback and expiry
during observed waits. UUID, passkey-required policy and original method/time are
preserved; preissued mailbox proofs are canceled and weaker fallback stays denied.
HTTP tests capture proof delivery. Separate native platform/USB tests now use the
real configured SMTP adapter with owned local Mailpit recipients, proving explicit
confirmation, independent binding rejection, fragment removal/no GET mutation,
rotation/revocation and later passkey login. Database facts verify unchanged
authentication method/time and stronger policy. Ordinary composition stays gated through AUTH-20 and remaining M03 evidence.

AUTH-18's optional enrollment boundary now rechecks fresh session/browser/realm
binding and exact verified state under locks, then atomically consumes the ceremony,
inserts an RP-wide unique credential and audits enrollment. Limits bound pending
state, credentials and verification admission. Protocol failures do not become
success events; audit failure rolls back credential and state changes. Deletion
cascades credential/state and clears owned admission/audit attribution. Final enrollment consumption now checks ceremony expiry and original live/fresh
session time after credential/audit writes, including unchanged pending-row and
RP-wide uniqueness waits. Regression tests reproduce the former audit-wait gap
and prove rollback for both mailbox and stronger-account policy. A separate
AUTH-54 audit tracks analogous final-write surfaces in older mailbox workflows;
those paths are not claimed verified by the enrollment fix. Upstream
payload tracing is suppressed within synchronous verifier calls. No ordinary HTTP
composition enables this boundary yet. Experimental authentication and method
provenance now exist; stronger-account recovery policy, real-device/other-browser
evidence and passkey-first
accounts remain required. See the [enrollment guide](../guides/passkey-enrollment.md).

The explicit experimental HTTP composition checks realm/origin alignment at startup,
uses the same exact-Origin middleware and redacted errors, and sets an independent
HttpOnly host binding cookie. Its 32 KiB body limit and core buffer bounds do not
apply to ordinary routes, which retain 8 KiB. Chromium virtual-authenticator cases
now cover actual registration, server rejection of bad UV/client data, browser RP
scoping, replay, a true cross-origin request's HTTP 403 and missing browser binding.
These checks neither enable ordinary server enrollment nor establish real-device,
passkey authentication or recovery assurance.

AUTH-19 now has optional core/PostgreSQL authentication: admission precedes lookup,
private ceremonies bind browser/realm/RP/purpose, and verified proofs carry exact
ceremony/credential snapshots. User -> credential -> ceremony locking and a new
post-lock expiry statement prevent stale or expired proof commits. Consume, key
update, session issuance and fixed-schema audit commit atomically; tests cover
replay, rollback, competing snapshots, expiry during unchanged-row waits and deletion.
Session methods are explicit and rotation preserves provenance. AUTH-53 now uses
account policy to reject weaker sessions and mailbox/password fallback, including
preissued proofs and policy changes during observed user-lock waits. Fresh
passkey session controls work without email; inventory omits unusable weaker-method
sessions. Stronger-account recovery and general lifecycle remain AUTH-20 work.
Experimental
HTTP now has native platform/USB assertions and modal resident discovery, plus
signed cross-origin context rejection and backup/counter evidence. The context
projection rejects topOrigin and true/null/duplicate crossOrigin; the pinned
library assertion path omits those checks. A private fixture explicitly arranges
stored-zero metadata for the native counterless acceptance test, without changing
its public key or verifier/session code. Stronger-account policy, passkey-first
enrollment and real-device/other-browser gates still disable ordinary composition. See the [authentication review](../research/passkey-authentication.md).

The alpha now includes opt-in password enrollment and sign-in (AUTH-12). Fresh verified sessions, a configured blocklist, bounded Argon2id, shared admission, transactional enrollment/session replacement and stale-hash rechecks are required; see ../guides/passwords.md. AUTH-13 adds browser/purpose-bound password recovery, credential versions, atomic session/proof invalidation and durable non-secret notifications. AUTH-14 adds both-address verified email changes, fresh-session/mailbox-confirmed deletion, authentication-time provenance, scoped cleanup and audit deidentification. AUTH-15 adds bounded owned-session inventory, fresh-authenticated individual/all-session revocation, proof cancellation and transactional audit. Deterministic database lock tests cover concurrent logins/revoke-all and freshness revalidation after waiting. AUTH-16 adds typed, fixed-schema audit attribution with composite ownership constraints, in-transaction recording, explicit historical provenance and scoped deidentification. Logout follows user-before-session lock order. Provider linking still requires fresh current-account proof plus a separately verified identity transaction; no matching-email merge or linking-success event is enabled. Stronger-factor recovery, queue monitoring/retention and authenticated password change remain incomplete. Linking, native tokens, external callbacks and issuer routes remain excluded. Full initial release remains blocked on their milestones. Baselines and external normative references are in ../research/protocol-dependencies.md. Every implementation ticket must state tests and residual risks; update this document when boundaries change.

AUTH-54 retains locked original proof/session deadline evidence through destructive
mutations, then checks database wall time after all potentially blocking writes.
Expired authority rolls back proof consumption, identity/credential/session changes,
audit and notification state. Session validation/inventory use owner-before-session
locks, current post-wait policy and the original idle/absolute deadline before touch.
Sensitive mailbox and revocation operations additionally retain original freshness;
rotation never extends it. Observed-lock regressions include unchanged-row waits,
audit/notice tails and final session touches. A table-free check precedes commit;
it cannot promise that wall time stops during commit, response transport or later
application work. The consuming application still owns authorization for its actions.

AUTH-20's in-progress optional management boundary requires a genuinely fresh
passkey-method session, exact owner/realm/RP and expected metadata version. The
owner lock serializes rename/removal; removal leaves another key with actual
assertion-use evidence, revokes owned sessions and cancels bound pending state.
A proof verified before removal cannot bypass final credential checks. Original
deadlines cap final audit/notice waits. Public target UUID audit attribution is
cleared with subject erasure, and fixed notices use only verified contacts.
This is a partial management boundary, not recovery or ordinary activation.
All-keys-lost proof/delay/cancellation/notification and physical-device/browser
acceptance remain required; email-free notification limits must be explicit.

Experimental AUTH-20 HTTP management adds no alternate policy path: handlers call
the shared management use cases, accept closed versioned inputs and no owner/RP/
realm selectors, retain the exact-Origin/host-cookie/no-store boundary, and clear
all auth/action cookies only after committed removal. The full OpenAPI preserves
prior schemas/routes. Native tests use independent virtual authenticators with
original exclusion/residence/UV options and actual signatures, including a removed
key rejection and valid surviving-key retry. Fixed verified-contact notifications
now have real SMTP worker evidence. Recovery, activation and physical-device/
other-browser acceptance remain open; these tests do not prove them.

Additional enrollment requires actual fresh passkey-method proof once any key
exists for the realm/owner, including another RP. All four repository stages
re-read this under owner/session locks; preflight or preverified mailbox ceremonies
cannot bypass a newly committed key. Only known email/password methods can bootstrap
a first key; legacy timestamps do not prove a method. Owner serialization permits
one initial-bootstrap winner. Original session/proof caps follow preparation,
admission and final consumption writes. This closes enrollment authority only;
reviewed recovery, stronger-policy activation and physical-device evidence remain
AUTH-20 acceptance work.


Experimental saved-code preparation/confirmation requires actual fresh passkey
method and proven configured-RP key evidence under shared owner/session locks.
Pending setup binds the exact session/realm/owner/RP; only a verifier is stored.
Preparation cannot invalidate a confirmed code, and confirmation replacement,
consumption, audit and fixed verified-contact notice roll back on any failure or
original-deadline expiry after final writes. The saved code is a bearer secret and
is not phishing resistant; offline storage is the user's responsibility. Configuration
issues no recovery session or stronger-policy activation. Email-free accounts have
no independent email notification. The separate experimental recovery services and
remaining security review are documented in [ADR 0012](../architecture/adr/0012-saved-passkey-recovery.md).


Experimental HTTP saved-code configuration uses a separate startup-aligned router,
closed JSON/no query selectors, the shared exact-Origin/host-session boundary and
8 KiB bodies. Only successful persisted preparation serializes a code, with
no-store protections and no new session/action cookie. Confirmation binds the
original session and returns no credential. Native platform/USB cases use actual
signup assertion, email-free confirmation and verified-contact rotation with real
SMTP notices; test code is never persisted in browser storage or reports. Existing
negative protocol/management assertions remain intact in separate owned accounts.
This transport addition does not implement delayed/cancellable recovery or activate
ordinary routes; independent review and physical-device/browser gates remain.


Experimental recovery claims reserve a saved code once for a realm/owner/RP/
generation/browser, without issuing any session or key. Source admission precedes
lookup; account code-verification and owner/RP/browser continuation budgets differ
so a public ID cannot suppress an already-bound browser. Same-browser resume handles
lost begin responses without changing time/audit/notice. The original seven-day
claim cap and 24-hour wait use database time. Verified-contact delay starts only
from a current unexpired leased SMTP acknowledgement. Receipt locking follows
owner -> claim -> notice; final claim/lease caps follow all writes. Failed, stale,
expired, cancelled or superseded work cannot create/restart eligibility.

Existing keys remain usable. Cancellation requires the bound browser, a genuine
fresh key, or the retained reserved code for denial only. The latter lets an alerted
all-keys-lost owner stop a stolen-code claim; it cannot resume another browser or
create any grant. It has source admission without a pre-exhaustible account/code
cancellation counter. There is no mailbox-only cancellation/login authority. Code
rotation invalidates claims atomically, deletion erases owned state/audit targets,
and source/unlinked abuse metadata remains separately retained. Email-free users
lack independent alerts; lost browser capability, expired/cancelled proof and
long SMTP outages have explicit recovery limits. Claim/replacement HTTP uses the
separate explicit experimental constructor described below. Independent
review, consent/usability, native replacement races and physical-device
evidence remain gates.


The experimental core/PostgreSQL replacement service rechecks ready claims under
owner locks rather than trusting status metadata. Private candidates remain outside
ordinary sign-in/inventory; actual candidate assertion and exact challenge/credential
snapshots precede atomic key replacement and one-use session issuance. Optional
email-before-owner locking matches mailbox proof consumers; owner/claim/candidate
locks serialize cancellation, rotation and completion. Original claim and two-minute
ceremony caps follow all final writes, including uniqueness, audit, notice and
consumption waits. Other-RP saved proof and old keys/sessions/bound proofs are
invalidated without crossing realm/owner. Completion replay grants nothing; a lost
successful response requires normal sign-in with the installed key. The saved code
stays consumed and must be replaced after sign-in. No policy upgrade or contact
change occurs. Independent review, wider usability/browser evidence, physical devices and safe
activation remain release gates; transaction tests do not establish them.


Experimental recovery HTTP requires a pre-established separate host-bound HttpOnly
browser cookie before saved-code consumption, allowing same-capability lost-response
resume without returning a raw capability. Exact Origin, closed inputs, no query
selectors, 8 KiB ordinary/32 KiB WebAuthn response bodies and redacted/no-store errors
remain shared. Anonymous operations reject any session cookie to prevent silent
account replacement; only deliberate fresh-key cancellation uses session authority.
It can deny the current owned RP claim without a claimant-only ID, making fixed
non-secret alerts actionable to an owner with a surviving key. No anonymous claim
lookup or owner selector is added. Only actual committed replacement assertion sets
a session; registration/readiness/cancellation/errors never do. Cookie retention
cannot extend database deadlines, and losing the capability retains the documented
fail-closed recovery limits. Reference pages and native Chromium recovery now exist; independent review, wider
usability, physical-device/other-browser evidence and ordinary activation remain open.


The opt-in reference pages use explicit offline/code-consumption/replacement and
cancellation consent; confirmation cannot prove offline retention. Static GETs
create no authority. Proofs are not imported from URLs, stored in browser storage,
logged or interpolated as HTML. Page-scoped network/native operations abort on
navigation and transient code fields clear, including invalid account input paths.
The client never derives readiness from its local clock or silently signs out/
switches an account. Native Chromium evidence uses original resident/UV options,
actual old/replacement signatures and real SMTP. The owned development fixture
backdates only linked claim timing after a required real receipt; it never seeds
keys/sessions/receipts, extends original expiry or exposes a production clock API.
Physical hardware, other browsers and independent recovery-policy review remain
unverified; native emulation and self-review cannot satisfy those gates.


Recovery's SQL transaction does not control credential-provider storage. Creation
on an existing resident authenticator can replace its local key before server
commit; preserving old server rows is not a promise that the provider retains the
old private key. A new same-authenticator native case covers successful replacement
and stale-signature rejection. Supervised Safari/Dashlane instead stalls during
native creation, leaving only a registration-stage pending row and no verified
candidate/completion. Provider-side identity/display handling remains unproven as
a cause. Record the failure separately from Chromium success, retain stable account
handles and original deadlines, and keep ordinary activation gated. Operational
fixture summaries now distinguish pending registration from pending assertion;
the legacy total counts both and is never proof that registration succeeded.

Client error attribution must not turn navigation cancellation into alleged
provider rejection. The shared reference transport tracks page generations through
both resolved and rejected operations, and maps native failures to finite operation/
category text without retaining raw messages or causes. Synthetic browser failures
validate those diagnostics separately from real native signature tests; neither
category nor UI feedback can authorize registration, sign-in or recovery.

AUTH-28's optional metadata boundary rejects non-HTTPS or unlisted origins/ports,
all mixed/private/link-local/special-use DNS answers, redirects and ambient proxies.
Checked addresses are pinned while hostname/SNI/certificate checks remain standard;
peer matching adds a second check. Exact issuer, bounded body/header/type/encoding,
whole-operation deadlines, shared capacity and two revision-bound cache slots limit
untrusted input and amplification. Failed/non-cacheable attempts spend a short
fetch interval; stale documents never substitute for a failed refresh. Registry
failure remains Unavailable, distinct from disabled/stale configuration rejection.

Real TLS fixtures test certificate-specific failures separately from socket errors,
Host/SNI/pinning and zero proxy/fallback resolution. Database tests prove realm and
revision rejection even on cache hits, and disable commits while network I/O waits.
No DB lock spans the network. Native DNS cannot be killed by timeout: its owned
permit remains held until completion, bounding detached work while allowing capacity
exhaustion or shutdown delay. Conservative public-address policy and public roots
do not support private-network/private-CA IdPs. No token-controlled URL is fetched.

Discovery and JWKS are untrusted verifier input, not authentication. Known private/
symmetric key fields are rejected structurally. The optional signature/claim layer
is described below; provider exchange/acceptance remain unfinished. Future final
identity/session commit must recheck enabled revision,
original transaction expiry and linking authority under locks. No account linking,
provider credential handling or permission grant is added. See
[ADR 0014](../architecture/adr/0014-oidc-egress.md) for explicit limits and remaining
provider, operational, independent review and release gates.


AUTH-29 adds an explicit opaque-snapshot key refresh with a fixed 30-second forced
attempt budget, including failed responses, alongside the existing ordinary miss
interval. A newer fresh snapshot can satisfy old observers without another request;
HTTP expiry/non-cacheability still prevents reuse. No attacker key-ID map is kept.
Refresh repeats realm/configuration checks and uses the same pinned transport with
no database lock spanning network work. Token signature/claim validation, one retry
per consumed transaction and local provider rotation evidence remain required;
fetching or refreshing a key envelope does not authenticate anyone.

AUTH-29's optional verifier consumes original OAuth exchange authority, validates
bounded compact JWT/header input, selects only configured asymmetric algorithms and
exact non-ambiguous public keys, and uses established josekit/OpenSSL verification.
Embedded keys and token-controlled key URLs are rejected. Critical extensions,
encryption, compression, none/HMAC and duplicate known security members are rejected. Known-key signature or
claim failure never refreshes keys; unknown kid gets one bounded refresh/retry.

Required typed issuer/client/nonce/subject/time and audience/azp policy prevent
issuer, client and transaction substitution. Additional audiences require explicit
trust. Final database configuration, original expiry and linking-session checks
follow network/crypto without holding their locks over I/O. Verified results retain
the minimum original transaction, token expiry and token-age cap; current/future
freshness cannot extend them. Provider iat is not auth_time, and provider email
attributes are not local mailbox or linking authority. The result is not a session.

Native crypto work has two shared leases and a whole-operation deadline; canceled
blocking jobs retain their lease until completion. Raw foreign causes and token/
claim/key/proof data stay out of diagnostics; temporary dependency buffers prevent
a whole-process erasure claim. OpenSSL deployment/upgrade and strict clock sync
remain operational responsibilities. Local Keycloak/independent interoperability and final identity/session transactions
remain required, as do
independent review and ordinary activation. See
[ADR 0015](../architecture/adr/0015-oidc-token-verification.md).


AUTH-29's optional code exchange sends the original verifier and exact redirect to
only the configured, checked/pinned token endpoint. Registered public/Basic/Post
authentication is explicit and advertised; no method downgrade or retry exists.
Endpoint parameter collisions reject. Authority is rechecked after DNS before
sending credentials, and after signature verification. Discovery snapshots survive
only within one bounded logical operation; no-cache never becomes cross-operation
reuse. One-use code failures cannot resurrect consumed state. HTTP400 invalid_grant
is distinct from provider configuration, malformed response or network failures.
Unused access/refresh tokens confer no authority and are discarded. Protected
values redact Debug and zeroize owned storage, without promising whole-process
memory erasure. Private TLS component mappings add no production network/root
bypass. Independent review and final local session issuance remain gates. The owned
Keycloak/browser/PostgreSQL suite proves only its named code/signature/rotation/
replay cases with private fixture TLS/address mapping and shared production request
code. It preserves actual cache headers and distinguishes signed invalid claims
from deliberate proxy faults. No user/device settings, production root/IP policy or
ordinary routes change; private IPC and generated credentials never become logs.


Code-flow first-fetch admission may wait once under its existing shared lease,
keeping the one-second discovery/key budget without making a valid fast callback
consume state and self-throttle. No cache-slot/database lock spans that timer;
normal registry/fetch guards and original post-DNS/final deadlines remain in force.
No-store data is refetched and failed requests/state/codes are never retried.
Standalone/forced-refresh backpressure is unchanged. A successful unknown-kid
native retry retains its operation permit through final authority validation;
otherwise a blocked final read could exceed the declared concurrency bound.
Controlled expiry/cancellation and actual-rotated-signature capacity tests exercise
these invariants, while the real provider runner applies no admission pacing.


AUTH-56 stable startup loading does not reinterpret caller/historical revisions as
current authority. It locks registry before policy, matches the full definition and
enable state, performs no DML on unchanged rows and initializes only a genuinely
absent key with a fresh revision. A conflicting generic OAuth row or stale policy
is not adopted or repaired. Recreating removed configuration cannot revive already
claimed verified contexts. Metadata restoration cannot rewrite proof provenance;
corrupt stored revisions and schema/write failures fail closed as unavailable.
New startup operations create no user/session/identity. Ordinary browser/server
OIDC activation remains unimplemented at this checkpoint.

AUTH-56's opt-in `oidc-web` boundary fixes one trusted exact source and HTTPS common
callback. Callback GET compares canonical state with independent purpose cookies
only to select fixed UI; it makes no storage/provider call or grant. Duplicate,
unknown, malformed, ambiguous and oversized inputs receive fixed scrubbed failure
content. Deliberate exact-Origin POSTs retain core one-use state/browser/nonce/PKCE/
issuer/purpose/current-source/deadline checks through real committed sign-in. A
present session cookie rejects sign-in at start and finish; cancellation never
revokes or replaces an ambient session. Request snapshot checks are not a global
browser epoch: concurrent starts and already in-flight operations remain possible.
Explicit confirmation, exact binding and one-use completion remain required. Provider
and persistence failures stay distinct from authorization rejection and never issue
a session. Final audit failure rolls back local identity/session while consumed
OAuth state remains consumed. Original deletion proof/freshness requirements are
unchanged. Supported-mode public-login acceptance now uses real owned Keycloak
with explicit private-TLS/source-copy limits; broader release and independent-review
gates stay open.

The shared AUTH-56 application factory validates a closed typed `AUTH_OIDC_*`
contract before database loading/listening. Unknown/partial/unsupported settings,
HTTP origins even in development, invalid egress/algorithm/claim choices and
inconsistent registered client authentication fail closed. Confidential credentials
come only from bounded protected files, never inferred public fallback. Core's
existing egress metadata validation is reused before provisioning; it is no I/O or
current-authority proof. Stable loading preserves revisions and operator disable.
No root/address/insecure override, additional audience, dynamic issuer, secret
logging or policy-row credential storage is added. Auth-only legacy composition
refuses enabled browser settings rather than silently dropping requested routes.

AUTH-23's explicit desktop return metadata cannot relax ordinary web origin or
provider egress policy. Only typed literal `127.0.0.1`/`::1` return addresses with
an exact nonzero/nondefault port and canonical non-root path are admitted; the
existing HTTPS-only constructor and server settings are unchanged. Exact callback,
browser/purpose, original cap, source revision and scoped ownership checks still
apply. Trusted embedding must actually own the listener; validating a socket address
does not establish ownership or app authenticity. No native callback endpoint,
Google verifier/profile, weaker client authentication or mobile fallback is added.
Tests use explicit metadata and real signed generic OIDC controls, not real Google
or OS-return evidence. Native transport and provider-required fresh deletion remain
activation gates.

The optional Google code component constrains canonical issuer, response issuer
defense, three endpoint origins, RS256, exact client/nonce/presenter and fixed
identity scopes through the existing verifier/egress/opaque proof boundary. It
rejects public authentication and non-sign-in purposes without selecting fallback
methods or constructing local authority. Email verification remains a typed signed
attribute, not mailbox ownership or linking permission. Offline actual signatures
and Google-shaped documents prove component behavior only; the in-memory repository
cannot substitute for required PostgreSQL/native/provider lifecycle evidence. No
freshness is inferred from issuance or prompts, and no provider-required account
activation/deletion path is enabled. See [ADR 0019](../architecture/adr/0019-google-code-flow.md).

Thirty PostgreSQL-crate Google-profile scenarios traverse the real state,
signature/mapping and local identity/session boundaries with controlled offline
RS256 responses. Exact provider wire assertions and independent signed-response
counters distinguish invalid claims/JIT/source policy from infrastructure failures.
Observed audit/clock waits retain the original cap, and races/rollback/realm-client
tests preserve one-use and ownership. The fixture's signed authentication-time
controls do not establish claim availability from an actual Google registration;
token issuance never creates freshness and later proof does not rewrite old
sessions. No Google callback/native/deletion activation follows from these tests.

The Google raw-query decoder requires canonical state and exact actual issuer for
successes and failures; it rejects duplicate decoded names, malformed encoding,
oversized values and contradictory/unsupported inputs. Its deliberately closed
member set is not general OAuth conformance. Scope/domain/prompt/account-selection
metadata grants no policy, and foreign error details/URIs are discarded without
output or fetch. Query parsing neither consumes nor cancels anything: subsequent
operation/private-proof/browser/source/purpose/route binding is mandatory, including
before error cancellation. Error outcomes cannot become token requests. Real
PostgreSQL tests preserve pending state after wrong private proof/browser and show
one-use successful exchange or denial-only cancellation. No arbitrary callback-URL
import, new route or issuer fallback is introduced.

Shared Google authorization orchestration compares exact service snapshots and
retained state/actual issuer/route, rejects non-sign-in purposes before I/O, and
keeps denied/provider-failure cancellation behind the same original private proof
as success consumption. Failed preparation cleanup/storage is never a successful
provider denial; token/signature failures never restore consumed state. Explicit
cancel affects no ambient session. Successful verification still confers no local
authority until the existing mapped identity transaction commits. Network source
remains an independently budgeted abuse key, not an account credential; changing it
cannot bypass provider/browser/state/nonce/PKCE/purpose bindings. Actual SQL faults,
signed-negative controls, concurrent callbacks and separate roaming admission
observations distinguish these invariants from infrastructure/test assumptions.

The opt-in desktop transport binds only literal127.0.0.1/::1 before authorization,
retains its actual port/path and accepts exact Host/origin-form HTTP/1.1 GET only.
Eight sequential connections,32headers,16KiB parser buffer, two-second header/
three-second connection bounds and an original-expiry-derived five-minute maximum
bound local abuse. Invalid state/issuer/query/body/host/path cannot create a captured
return; cancellation/drop closes listener and active stream without detached tasks.
Network/parser/request-limit failures are finite transport outcomes, never evidence
of failed credentials. The socket can still be locally denied service or a callback
intercepted outside the app; S256/private proof and current database authority remain
mandatory. The opaque captured callback supplies its actual URI to core completion,
without importing a pasted URL, granting a local session or revoking ambient state.
Handled browser responses reflect no proof, issue no cookie and scrub query/fragment
with a fixed CSP-allowed script under no-store/no-referrer headers. Browser history
outside the current page and process-wide secret erasure are not claimed. Owned
Chromium and socket checks establish transport behavior only, not registered Google,
OS default-browser launch or mobile delivery. Nine separate server real-database
scenarios now carry actual owned listener delivery through signed offline responses,
state consumption and final local commit. Exact captured URI and current revision
reject cross-listener and old-snapshot substitution; verification alone grants
nothing. One-use races, explicit versus transport-only cancellation, unchanged
unrelated sessions, actual signed rejection versus infrastructure faults and final
audit rollback/observed-expiry controls preserve these boundaries. These fixtures
establish component behavior, not real Google TLS/client/freshness or usable deletion.

The explicit eligible-client Google session-age profile adds only fixed essential
signed authentication-time request/validation to the already constrained code
exchange. Decoded/case-folded metadata claim collisions reject; no callback-selected
profile, arbitrary claims, unsupported reauthentication prompt or fallback exists.
Actual signed capability absence is provider-profile Unavailable, malformed/invalid
claims Unauthorized. The same shared flow retains every original binding. Separate
exchange methods enforce sign-in versus original account-deletion purpose before
token I/O. Verified deletion proof alone erases nothing: exact initiating owner/
subject/current source/session, genuine recent signed authentication and final caps
still gate the existing PostgreSQL transaction. Old signed time is never rewritten
by a new token/session/request. Actual-signature/database controls preserve missing/
stale/wrong-subject/cross-purpose denial, complete rollback, one deletion under a
race and deleted-subject cooldown. Those controls do not establish provider app
eligibility, forced reauthentication or usable real-provider lifecycle/activation.

The separate bound Google deletion authorization service requires the explicit
session-age profile and rejects sign-in/linking intents before I/O. Both public
sign-in constructors still reject deletion. Shared completion checks original
state, actual callback route/issuer and private browser/nonce/PKCE/purpose bindings
before either consuming a code or cancelling a provider error. Wrong owner/session
cannot cancel another operation. Cancellation leaves the initiating account/session
intact; verified proof alone also leaves them intact. Actual-signature PostgreSQL
cases cover binding negatives, one-use callback races, preparation/cancellation
storage faults, capability absence versus invalid claims, old authentication and
final deletion audit rollback. Transport/storage failures are Unavailable rather
than successful cancellation or authentication rejection. No real Google freshness,
web delivery, provider eligibility or ordinary activation is established here.


The experimental Google HTTPS boundary selects the eligible session-age profile
only through trusted construction and requires exact realm/source/HTTPS callback
composition. Separate Google sign-in/deletion proof cookies reuse the shared host/
Secure/HttpOnly/SameSite and anonymous-session/revocation guards. Stale/malformed
returned state cannot clear newer proof cookies. A GET parses only to select fixed
UI by one unique state-cookie match; codes and provider errors still need explicit
POST and full core/database binding before any consume/cancel/grant. Ambient-session
sign-in is refused; deletion uses the actual authenticated owner/session and exact
confirmation twice. Provider fields cannot select ownership/profile or return URLs.

Scripts scrub query/fragment immediately, retain callback only in memory, reject
unsupported/duplicate/badly encoded input and drop/abort proof on navigation and
restoration. Error details/URIs are neither reflected nor fetched. Fixed Google
navigation, CSP/no-store/no-referrer, closed JSON/query input,64KiB request bound and
unchanged core8192/2048-byte callback limits apply. Real signed HTTP/PG tests preserve
one-use/concurrency, realm/private-proof separation, wrong owner/session/subject,
actual old/missing/invalid claims, rollback and infrastructure error classification.
Owned private-TLS browser cases prove explicit confirmation and actual commit/deny,
not registered Google eligibility, actual provider TLS, genuine user freshness or
ordinary activation. The fixture blocks external traffic, uses public S256/nonce
inputs, verifies aggregate outcomes and removes its owned DB/TLS material. No
credential-manager/system security setting or manual device prompt is involved.


The optional native Google launcher keeps nonce/PKCE/browser proof inside its owned
operation. Only the public authorization URL reaches the first configured OS opener,
with null streams and no raw command/error logging or fallback iteration. Target
values remain argv/environment data; no caller command or token-upload API exists.
Five-second/original-expiry launcher bounds and one-second explicit child reaping
limit resources; callback capture runs concurrently, but both handoff and owned
callback are required before verification. Killing targets only the opener child,
never a browser/process group. Drop requests termination without claiming confirmed
cleanup or SQL cancellation. Explicit cancellation retains original binding and
never resurrects consumed state. Signature completion alone grants no local session.
The OS handler/configuration is trusted, not authenticated by exit status. Actual
platform/browser and Google registration remain unverified. Rebinding an ephemeral
redirect invalidates old source-revision sessions; this fail-closed guard stays intact.


The explicit native registration profile admits only canonical literal127.0.0.1
or::1 with fixed path and a concrete port, under RequireIssuer and sign-in purpose.
It never relaxes HTTPS web defaults or establishes socket ownership. Each operation
retains/persists its exact actual return; alternate admitted ports cannot consume
or cancel another operation. Code exchange sends that retained URI. Stable source
metadata includes the profile under the full registry lock; real disable/revision
changes still invalidate contexts and sessions. Existing pending hashes, private
browser/nonce/PKCE, realm/subject/owner separation, one-use and final database caps
remain mandatory. Legacy backends reject alternate returns instead of substituting
the anchor. Migration defaults old definitions to exact and preserves original
proofs/caps. Owned fixtures, process actors and offline signatures do not establish
Google registration, OS-browser interoperability or native remote-token authority.


The separate registered-native acceptance tool requires an explicit developer
sign-in mode and disposable-account consent before OS handoff. That flag prevents
operator accidents; authentication authority still needs the existing owned
callback/private proof, genuine signature and final current-source transaction.
Input/owned-setup success grants nothing and submits no wire credential. Real-mode
credentials come only from the existing bounded protected reader, never arguments,
callback input or logs. The tool accepts no arbitrary issuer/egress/algorithm and
keeps base/session-age selection in trusted setup. Only finite outcome/counts are
emitted; session validation/revocation and database destruction affect exclusively
its fresh local realm. Provider grant cleanup remains separate owner action.
Offline proof fixtures and public setup do not establish real Google/OS acceptance,
genuine freshness, ordinary activation or an installed-client DB credential model.


## Gated SAML local authority

The opt-in final transaction consumes concrete verified/mapped input under exact
current registration and default-deny policy. It reserves both authenticated IDs
in a durable realm/connection namespace that survives client/revision replacement
and erased owners. Full exact subject fields select ownership alongside their
bounded database digest; presentation and email cannot select or merge users.
Replay, owner/JIT, session and typed audit writes commit or roll back together,
with the original deadline checked after every final write wait. No database lock
spans XML verification. See [ADR 0023](../architecture/adr/0023-saml-identity-session-commit.md).

Source-bound sessions retain actual signed authentication time and the distinct
signed session cap. Disabled/stale source policy or an absent compiled backend
rejects authority, while own logout remains possible. Account erasure cascades
local authority and preserves a bounded hash-only cooldown against resurrection
from still-valid preverified input. Separate purpose-bound deletion and bounded
owned Keycloak browser acceptance are implemented below. Mandatory source/XML/
backend/independent review and broader actual IdP interoperability remain open;
normal SAML stays disabled.


The gated Axum SAML ACS is explicitly non-authoritative. Existing Lax cookies may
be absent on the cross-site POST; its fixed protected page forwards bounded form
fields to same-origin completion, where existing-session rejection and private
request/browser/RelayState binding precede core consumption and verification. This
keeps the ordinary session cookie and origin policy intact. Only the delivery page
uses a cross-site exception, with shared timeout/security headers and no SQL or
grant. See [ADR 0024](../architecture/adr/0024-saml-web-delivery.md). Normal startup
remains unchanged; broader IdP/profile acceptance and independent approval stay open.


The gated SAML deletion backend now consumes distinct opaque deletion-purpose
preparation through the unchanged verifier and requires exact current source,
initiating owner/session/identity, signed subject, actual signed five-minute
freshness, durable replay and every original/signed cap at final atomic erasure.
It shares the existing audit/verified-contact notice/cooldown tail; no callback,
ForceAuthn intent, token issuance, email attribute or weaker method can erase an
account. Compiled SAML logout/revocation cancels only bound deletion state in that
same transaction, with no later source-lock acquisition and retained final expiry
checks. Explicit same-origin HTTP confirmation is implemented with separate private
proof cookies and a non-authoritative common ACS/operation selector. Bounded
Keycloak retained-SSO password challenge and signed reauthentication-to-deletion
acceptance pass; broader actual IdP/profile acceptance remains open.

Maintained typed extraction now provides complete ordered scalar attributes from
the same verifier-selected Assertion under existing XML limits. Core requires
completeness, zeroizes/redacts these facts and never falls back to the legacy
name-keyed aggregate or raw XML. NameFormat, duplicates and value groups cannot
select or merge an owner, install contact/roles or override deny policy. New
ordinary library-signed/real-PG time cases preserve old authentication across new
issuance, retain the original24-hour session cap and reject stale authentication
at final deletion. No verifier, DB clock or security policy is replaced. See
[ADR 0028](../architecture/adr/0028-saml-attribute-and-authentication-facts.md).
See [ADR0025](../architecture/adr/0025-saml-account-deletion.md); dependency/XML/
backend and independent approval still gate normal activation.

## Gated outbound issuer metadata

The explicit native extension keeps web constructors HTTPS-only and admits HTTP
only for public native clients on canonical literal127.0.0.1/::1 callbacks. Only
ports vary; exact interface/path remain registered and later code redemption must
bind the actual complete URI. Admission cannot prove listener ownership, genuine
app identity or PKCE. Native sectors isolate each realm/client instead of sharing
loopback IP sectors. Public identification grants nothing. Typed Basic input hashes
a canonical Secret and PostgreSQL validates the registered method and credential
under the full exact enabled definition lock; stale/disabled/wrong/cross-realm
credentials reject without authority or fallback. A successful standalone check
must never replace checks inside an eventual code transaction. Migration0028
preserves legacy web trust, disable, credentials, subjects and sessions; actual
code/consent/token, other native profiles and M07 release evidence remain required.
See [ADR0034](../architecture/adr/0034-issuer-native-registration-and-authentication.md).

AUTH-37's separate optional registration component accepts trusted canonical HTTPS
web definitions and the explicit public native profile above. Full current realm/client/revision/redirect/sector/
authentication/credential policy is locked before an owner key; disable and stale
snapshots reject even after waits. Only existing realm owners receive stable random
sector subjects. Same-host web clients intentionally share the OIDC sector;
cross-host/realm mappings are distinct. No local UUID/email/provider subject is
exposed as the outbound subject. Account erasure cascades mappings. Random stored
UUIDs use existing randomness, with no new cryptographic scheme. A mapping or
registered client is not consent, authenticated-client or token authority. No issuer
route/startup path is enabled. AUTH-32 and M07 production prerequisites, real client
authentication/consent/PKCE/issuance/key/conformance work remain open.

## Optional outbound consent/code component

`issuer-codes` requires explicit fresh-owner consent under exact private browser,
handle and preview UUID binding. Preparation grants no authority. Mandatory S256,
current registered client authentication, exact actual redirect (including native
port), issuer/realm/revision and source-aware initiating session bind one-use code
consumption. Public identification cannot replace PKCE; an old or disabled upstream
source cannot authorize a downstream code. Actual authentication time is retained,
not inferred from fresh issuance. Original300second consent/60second code and
session/freshness caps survive waits; the final database-clock check rolls back all
state/subject/audit writes on expiry. Separate committed bounded source admission
precedes even unknown-client lookup. Invalid credentials/grants do not mask storage
failure. Account erasure removes local codes/mappings and deidentifies their audit
attribution in the owning transaction, preserving other realms.

This optional component returns no signed token, HTTP endpoint or normal startup
activation. The future browser boundary must bind Origin/private cookies and exact
preview confirmation, and token transport must authenticate actual client input
without ambient-cookie fallback. Signing/key/audience, refresh, native storage and
interoperability remain release work. See
[ADR0035](../architecture/adr/0035-issuer-consent-and-authorization-codes.md).

The optional HTTPS consent transport requires the same trusted root issuer/browser
origin and realm. GET renders only fixed content; explicit Origin-bound POSTs create
a preview and later approve/deny. Private HttpOnly browser/handle cookies, the actual
fresh session, an operation cookie and the exact displayed preview UUID bind the
choice. An old tab cannot approve a newer cookie-selected request. Read-only resume
revalidates all original/current source/owner/caps without granting or extending
anything. Storage failure preserves retry proofs; unusable recovery and local session
replacement clear transport state. The fixed script scrubs query/fragment, uses text
rendering, stores no protocol data in web storage and drops/aborts on navigation or
restoration. A browser abort cannot undo an already committed SQL decision. This
consent-only experimental embedding mounts no token endpoint and establishes no
signed issuance, full OAuth/OIDC interoperability or outbound production approval.
See [ADR0036](../architecture/adr/0036-issuer-https-consent-delivery.md).

## Explicit native offline policy

The optional `issuer-native-refresh` component currently persists configuration,
not refresh authority. New policies default disabled and bind exact realm/HTTPS
issuer/full public native client revision, independent policy revision and bounded
absolute/idle seconds. Changed client/policy snapshots fail closed; reconfiguration
preserves operator disable and stale enable cannot restore an old definition.
Client-before-policy locking linearizes configuration/check/disable; read-only
loading is not authorization. A distinct persisted offline client profile makes
older or feature-disabled loaders refuse rather than silently downgrade it.
Configuration-aware builds also refuse that offline profile in existing online
request, preparation/decision/redemption and core grant-validation paths; recognizing
configuration cannot authorize interpreting a future offline grant as online consent.
Migration0033 creates no consent, subject, session or token. The eventual separate
offline consent must preserve original source/session absolute caps and must not
reinterpret the old online approval, code, cookie freshness or idle deadline as
long-lived authority. Family rotation/reuse/lifecycle and native delivery remain
unimplemented acceptance requirements; configuration alone does not close them.

## Optional signed issuer component

Explicit native consent library operations require exact offline scope and consent
prompt, current enabled native policy/client, actual fresh initiating session and
private browser/handle/authorization bindings. Migration0034 marks only new native
rows and binds immutable proposed lifetime/source caps to their full realm/issuer/
client/revision/owner/session tuple. Approval uses current source/owner/session and
original caps, existing typed actual-owner-session authorization audit and a final
clock after every write/wait. Default online code paths still refuse the profile
and marker. Policy disable prevents approval but permits bound pending cancellation;
revision changes never widen a proposal. Account erasure cascades native consent.
No refresh credential or extended access is issued yet. A trusted UI must still
present preview and obtain explicit owner confirmation; a prompt input alone proves
no human action. Native HTTP delivery and refresh lifecycle acceptance remain open.

The explicit `issuer-signing`/`issuer-web` extensions use pinned josekit/OpenSSL
RS256 with bounded validated operator input and allowlisted public JWK output.
Optional Unix loading checks the opened regular owner-only file and refuses final
symlinks; trusted parent directories, ownership and secret distribution remain
operator responsibilities. Native library copies are not claimed erased. No default
key, request-selected algorithm, private SQL/JSON output or old-key fallback exists.
Current active key/revision, immutable key IDs, bounded prepublication/overlap and
explicit disable prevent metadata reconfiguration from granting signing authority.
Emergency removal cannot revoke keys already cached by consumers.

Native signing holds no SQL locks. Its opaque staged result grants nothing until
the final exact client/key/source/owner/session/code snapshot and all original caps
are checked again, access hash/code scrub/audit are written and the final clock
check commits. Replay and storage/expiry/policy failures return no staged credential.
The issued audience is the registered client; subject is the random pairwise sector
mapping, never an email/local owner/provider ID. Original auth_time is retained;
issuance cannot manufacture authentication freshness or MFA. Current conservative
expiry is bounded by the original60second code and session/freshness/key windows.

Only the dedicated token POST omits browser Origin enforcement. It accepts explicit
public identity or registered Basic authentication plus code/exact actual redirect/
S256, with strict closed bounded form/percent/duplicate/header parsing. Ambient
cookies never authenticate it. Actual transport ConnectInfo selects admission;
missing peer data fails closed and forwarding headers cannot reset limits. Local
cookie/consent routes retain their existing Origin/private-proof boundary. Opaque
access credentials cannot authenticate a local session or grant application roles.
Owner erasure cascades local ledger/code/subject rows but cannot erase a previously
issued self-contained ID token or downstream application session. The conservative
expiry bounds that snapshot; immediate offline revocation/sign-out propagation is
not provided.

Real-PG, HTTP, sequential ordinary rollover and in-process existing-RP cases provide
bounded implementation evidence. They do not establish independent review, external
RP conformance, native secure storage or production approval. The owned healthy TLS
browser/client runner is separate evidence. No adversarial cryptographic/XML
producer or custom signature-concurrency experiment is part of this increment.
See [ADR0037](../architecture/adr/0037-issuer-signing-and-final-issuance.md).

Optional access management authenticates the current exact confidential Basic client
before returning introspection metadata and binds all storage to realm/issuer/client.
Public identity/cookies never authenticate introspection. Unknown/foreign/inactive
input discloses no claims; wrong credentials/storage faults are not inactive success.
Retained key/namespace/source/owner/session/code/original-cap checks and a final clock
after waits prevent stale or extended active results. Inspection does not touch idle
time. Explicit possession revocation can only reduce matching token authority and
cannot clear an earlier revocation timestamp. It can run after logout/source expiry
without inventing owner authority, altering local sessions or revoking another audience.

The HTTP extension retains the bounded strict client form/Basic/no-store boundary,
requires actual socket peer admission, ignores forwarding headers and accepts no
ambient-cookie authority. Local cookie endpoints keep Origin enforcement. A presented
token retains only the existing standard credential hash, with no new cryptographic
scheme. This access-only increment creates no refresh/offline authority, remotely
erases no ID token/app session and does not complete native/M07/production gates.
See [ADR0038](../architecture/adr/0038-native-token-lifecycle.md).

## Native refresh delegation boundary

Explicit approved offline consent creates separate bounded authority, never an
extension of online code/cookie freshness or an upgrade of old openid consent.
Current source/account method, original authentication/session, revocation,
client/policy/key and source absolute bounds remain mandatory on rotation. Refresh
cannot update cookie time or mint new ID tokens. One-use spend/rotation/audit is
atomic; old hash reuse permanently revokes the family/all descendant access before
invalid_grant. Concurrent use has no grace fallback. Final clock checks the old idle
deadline after writes/waits. Unknown or foreign possession cannot select another
realm/issuer/client; public client IDs remain insufficient for introspection.
Audit/storage failures return errors and roll back, never a false successful
grant/revocation. HTTP human confirmation and owned native/browser/storage
integration remain unverified.

## Native confirmation HTTP boundary

The optional native consent transport retains actual Origin, session and private
browser/handle/selector checks; query/prompt/DOM markers cannot grant authority. GET
creates no state and fixed pages scrub queries; shared JS retains correlation only in
memory, uses textContent and navigates only to the server-validated return. The
displayed fixed offline expiry/idle is never recomputed from request data.
Native/online share a private cookie slot, cannot overwrite an active operation, and
cannot approve each other’s row kinds. Current source/owner/freshness/policy and
final DB clock remain mandatory. No token/refresh HTTP authority or native
interoperability is inferred from consent tests.

## Native wire and consumer boundary

An explicit mixed native endpoint uses one core admission before registered-profile
selection; it cannot fall through after a failed native/online grant. Actual current
credentials/PKCE, client/native policy/key/source/owner/session/code/consent and
original caps still bind commit. Refresh carries only opaque one-use credentials, no
new ID token or cookie time. Strict shared decoding/actual peer remain mandatory;
hints, browser cookies and public native IDs confer no consumer authentication.
Bounded owned browser/real TCP callback tests check state/issuer, PKCE, production
signature, rotation/replay/cleanup and privacy using unchanged producers. Actual
OIDC/SAML cases preserve authentication provenance and current source denial. Native
authenticated audience-authorized resource consumption uses the explicit policy
below and cannot be replaced with local-session acceptance. Production platform storage and broader
interoperability remain explicit requirements.

## Native consumer authentication and disclosure

The separate optional native inspection path requires current confidential Basic
credentials plus an exact enabled persisted consumer-to-native-audience policy.
Public identification, token possession and browser cookies confer no consumer
authentication. Schema installation and HTTP composition enable no policy. Full
current consumer/audience definitions and policy revisions prevent stale permission
reuse; disable remains reduction-only after client changes.

All client pair locks precede policy/key/source/owner/session/family/access locks in
deterministic immutable-ID order. Snapshots choose paths, not authority. Actual
credential comparison precedes even unknown/inactive results. Final database time
after all waits bounds native access/family idle/absolute lifetime. Existing provider
source guards and original authentication remain mandatory without imposing cookie
freshness or extending cookie time. Family replay/revocation and key/policy/session
disable prevent active disclosure. Infrastructure errors never become inactive
success. Active claims expose only pairwise metadata to the explicitly authorized
consumer; inactive responses disclose no reason. Native audience metadata never
becomes a local identity/session or application business permission. ADR0039 records
the explicit endpoint, scope and limits.

## Independent relying-party SDK boundary

The optional `oidc-client` operation requires exact trusted issuer/client/return,
S256, private state/nonce and response issuer before a one-attempt code exchange.
Strict callback encoding/duplicates/fixed query, originating service identity and
wall-clock plus monotonic deadlines prevent ambiguous or stale callbacks from
selecting a token request. Shared bounded discovery/JWKS and RS256 claim validation
produce only RP metadata, with no public local-session/provider-proof conversion.
Native refresh consumes the presented generation, makes one POST and returns no new
identity or authentication time. Applications must atomically replace generations
in protected per-user storage and restart authorization after ambiguous outcomes;
Rust ownership cannot stop deliberately copying an exposed secret. The trusted HTTP
ports must use the existing reviewed HTTPS/DNS restrictions and shared budget;
there is no production private-address or local-CA fallback. Local client/standalone
parity and independent assurance remain separate acceptance gates. See ADR0040.

## Configured issuer and provider composition

Default-off issuer startup validates complete trusted HTTPS/protected-file settings
and exact current enabled persisted key/public material in the chosen realm/issuer.
It cannot provision, repair or re-enable issuer policy. Later key/client/source/
owner/policy changes are still checked by the existing final issuance/rotation
transactions. Combined inbound-provider attachment checks each source's realm and
HTTPS callback and applies cleanup around all selected routes. It supplies no new
provider or signing authority. Native consumer inspection remains separately
selected and requires exact persisted authenticated-reader permission. Owned
executable/embedded/SMTP/browser/client parity is implementation evidence, not
public-root TLS, certification, independent review or live-production approval.
