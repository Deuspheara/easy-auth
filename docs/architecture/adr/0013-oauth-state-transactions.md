# ADR 0013: Browser-bound OAuth state transactions

Date: 2026-10-19. Status: accepted for the optional core/PostgreSQL boundary in
AUTH-22. Provider login, identity linking, native transport and ordinary activation
are separate acceptance boundaries. This is not an OAuth/OIDC interoperability claim.

## Context

Social and external OIDC flows need one-use state without confusing a successful
callback lookup with a verified external identity. Binding only a provider label
or a state string does not prevent browser swapping, purpose substitution or
authorization-server mix-up. Network exchange cannot safely run inside an open
owner/session database transaction. Linking must not acquire weaker authority from
an anonymous sign-in transaction or an unrelated fresh session.

The protocol requirements come from [RFC 9700 sections 4.4–4.8](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html),
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) and
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) additionally governs future
native system-browser adapters; this boundary does not implement them.

## Decision

Keep the existing four crates. The explicit `oauth-transactions` feature exposes
concrete core configuration, intent, proof generation and transaction use cases,
with one repository port. PostgreSQL owns configuration serialization, admission,
capacity, owner/session locks, original deadlines and one-use deletion. There is no
generic protocol framework, HTTP callback, provider network client, token verifier,
identity resolver or session issuer in this feature.

Trusted server configuration selects realm, connection UUID, local client UUID,
provider client identifier, exact issuer, HTTPS callback and an explicit mix-up
defense. Trusted composition persists configuration and uses the returned snapshot
before constructing the flow. Each application allocates a fresh random revision,
even when the input object is old, and cancels old-revision transactions atomically.
The realm/connection/local-client tuple is an immutable registry key; provider-client
metadata can change under that key. Disabling rotates its revision and cancels
pending transactions. Reconfiguration preserves a disable; re-enable is an explicit
administrative call requiring the latest persisted revision. A pre-disable exchange
therefore cannot become current again after reconfiguration/re-enable. Administrative
methods must never be exposed to browser input. Reconfiguring on restart intentionally
invalidates pending work; reusing an already persisted snapshot without another
configuration write does not. No stale input can restore a historical revision.

Callback URIs have a global uniqueness constraint across configured connections,
clients and realms, including disabled rows. They use canonical HTTPS URL spelling,
non-root paths, no encoded path aliases, credentials, query or fragment. Callback
selection comes from the actual trusted route/origin, not state contents, request
body fields or an untrusted Host/forwarded header. Exact issuer strings are retained
without URL normalization. The two explicit defenses are:

- `RequireIssuer`: the decoded actual authorization-response `iss` must be present
  and exactly match the configured issuer, including on error responses.
- `DedicatedRedirect`: the actual dedicated callback must match the configured
  globally unique URI. A present `iss` must still match. Missing `iss` is allowed
  only by this explicit configuration; adapters must not silently switch modes.

The dedicated-redirect alternative has the limitations described in RFC 9700
section 4.4.2.2. Provider adapters must establish support and registration policy;
this transaction layer does not infer compatibility or make network requests.

## Proof handling

Each start generates independent canonical 256-bit state, nonce and PKCE verifier
using the existing `Secret` type. S256 is SHA-256 of the ASCII verifier followed by
unpadded base64url; the RFC 7636 published vector is a regression test. There is no
`plain` method or custom cryptographic primitive. Browser correlation additionally
uses the existing independently supplied host browser secret.

Only SHA-256 verifiers of state, nonce, PKCE and browser binding enter the database.
The public authorization request carries state, nonce and the S256 challenge.
The raw PKCE verifier stays in a protected transient browser transport and then the
trusted backend token request. `OAuthBrowserProof` is neither serializable nor
cloneable, redacts Debug and owns zeroizing secrets. A trusted transport may restore
its two canonical components; copying it into JSON, a URL, browser script storage,
logs or telemetry is not an integration contract. The optional library currently
provides no cookie/HTTP adapter. Future adapters must provide bounded per-transaction
HttpOnly host transport, expiry/cleanup and reviewed SameSite behavior. Apple
cross-site form-post behavior must not weaken the ordinary session cookie.

Nonce is also an authorization-request value, not an authentication bearer. Its
retained expected value must be checked by the selected reviewed token verifier
after signature/issuer/audience validation. State consumption alone verifies none
of those claims and never selects a token endpoint from callback input.

## SQL lifecycle and locking

Migration 0016 adds configuration, pending transaction and admission tables. Every
key/query includes realm. Configuration binds the local client and provider client;
pending work additionally binds its exact configuration revision, purpose, all four
verifiers and, for linking, the original owned session. Composite session ownership
foreign keys prevent cross-owner/realm linkage and cascade physical session deletion.

Start commits realm/browser/source admission first, then serializes the realm's
pending namespace. It locks the exact enabled configuration, and for linking locks
owner before the original session using shared freshness/method policy. It removes
expired pending rows, checks capacity and inserts a fixed five-minute transaction.
A link transaction is capped by the original session's idle, absolute and fresh
authentication deadlines. The final clock check follows insertion, including trigger
or uniqueness waits; expired preparation rolls back and returns no public state. A deadline crossed
before the insert evaluates its clock filters out the insert and returns Unauthorized,
preventing a valid expiry rejection from becoming a schema-constraint Unavailable.

Consume/cancel commits its own admission, locks configuration before owner/session,
then locks the exact pending row. It compares all bindings, deletes once and checks
the original proof/session deadline after the final write before committing. The
clock check is separate from the row-selection statement so an unchanged-row lock
wait cannot admit an expired proof. Delete failures or expired final writes roll
back consumption. Error mapping distinguishes Unauthorized, RateLimited and
Unavailable; infrastructure failure is never evidence of a rejected attack.

Connection update/disable takes the configuration write lock before pending deletion.
Both race orderings are tested using observed database locks. A callback claim that
wins first can return exchange context before a subsequent disable completes; this
is not an authentication grant. A disable that wins first prevents the claim.
No lock is held during future network traffic.

Sign-in and link intents are distinct. Link start and consumption require the same
fresh owned session; passkey-required accounts reuse the existing actual-method
policy. No email lookup or implicit account merge occurs. Revoked/stale/deleted
sessions cannot consume a link intent. Revocation makes pending work unusable even
if its row remains until expiry cleanup; physical deletion cascades it. Anonymous
sign-in transactions have no user association to erase.

## Exchange versus authentication commit

Successful consume returns `OAuthExchange`: original configuration, purpose,
deadline and private proof material for one attempted provider exchange. It is
explicitly **not** a verified identity type or a session credential. Successful
state handling creates no user, external identity, session, authentication audit
or permission. Cancellation returns no exchange context.

The raw state is consumed before external exchange. Failed or lost exchange results
require a new flow; replay does not retry a code. Database state cannot be committed
atomically with a remote token endpoint. The future provider adapter must verify
the response with a reviewed implementation and carry exact transaction context
into its final identity/session transaction. That final transaction must recheck
enabled configuration/revision, original expiry, linking owner/session freshness,
account policy and identity uniqueness under locks. A disable after state claim
must prevent identity commit. Failure of session/audit insertion must roll back
that final local transaction; it does not resurrect the already-used OAuth state.
AUTH-23/25 must establish these invariants before provider login/linking activation.

## Bounds, evidence and remaining gates

Pending limits are three per browser across connections and 256 per realm. Fixed
ten-minute admission windows allow start 10/browser and 40/source, consume/cancel
20/browser and 80/source. Failed lookup admission is committed separately; a rolled
back business transaction does not reset it. Hash-only abuse metadata is separate
from user data. Expired proof rows are removed on start, configuration mutation
cancels old work, and deletion cascades linked state. Scheduled admission retention
and operational resource/load policy remain release work; no retention worker is
introduced here.

Real-PostgreSQL tests cover valid controls, replay, every proof/context mismatch,
actual callback issuer/route checks, missing-issuer policy, cancellation, revision
change/disable, unique callbacks, original-session/stronger-policy binding, capacity,
committed admission, single-winner callbacks, cancel races, both disable orderings,
rollback and expiry during unchanged-row/final-delete/start-insert waits. The
upgrade case preserves existing identity/session/audit records. Gate observation
uses independent one-connection pools and explicit infrastructure timeout failures.

Provider-specific code exchange, signature/nonce/claims validation, bounded egress,
protected provider credentials, HTTP/cookie transport, real Google/Apple web/native
checks and linking/last-credential policy remain subsequent gates. AUTH-20's device
and independent recovery review remain open. This feature activates none of them.

## AUTH-23 explicit desktop metadata extension

The additive typed `OAuthRedirect::desktop_loopback` contract admits only literal
IPv4/IPv6 localhost, a concrete nonzero/nondefault port and a canonical non-root
path. `OAuthConnection::new` remains HTTPS-only; a caller must explicitly select
the typed redirect constructor in trusted composition. No native listener, mobile
scheme, provider profile or public HTTP route is activated. Exact URI comparison,
issuer defense, global callback uniqueness and every original state/deadline check
remain unchanged. Administrative revision rotation preserves the validated definition
rather than reconstructing it through the web-only constructor. See
[ADR 0019](0019-google-code-flow.md) for the unfinished Google/native acceptance scope.
