# ADR 0036: Explicit HTTPS issuer consent delivery

Date: 2026-10-23. Status: accepted optional consent transport. Signed token issuance,
normal server activation and interoperability remain open.

## Boundary and composition

Add `issuer-consent-web` to Axum and an explicit
`experimental_issuer_consent_router`. It composes the existing local Auth/browser
router with the concrete issuer authorization service. Require identical realm and
HTTPS root issuer/browser origin; path-based issuer namespaces and development HTTP
are unsupported by this initial transport. Default routes/contracts and standalone
startup do not automatically mount it. No token/discovery endpoint is advertised.

`GET /oidc/authorize` serves a fixed non-authoritative page. It never creates a
pending request, code, subject or session, reflects no query values and sets no
cookies. Its script immediately scrubs query/fragment, accepts only the exact
closed authorization member set and retains request fields only in page memory.
The user explicitly requests a preview, then separately chooses Allow or Deny.
Client and destination are displayed as text, never HTML or navigation instructions.
Only the authenticated server decision selects the final registered destination.

The four `/v1/oidc/consent/{prepare,resume,approve,cancel}` POSTs reuse the exact
Origin, no-store/no-referrer, CSP/frame denial, timeout and sanitized error boundary.
Closed JSON/query types and a16KiB body bound apply. No owner, realm, source policy,
client credential or optional response mode can be supplied here. Core owns all
request/consent policy and PostgreSQL owns current source/owner/code transactions.
This adapter has no SQL or copied authentication rules.

## Private binding and recovery

Use fixed `__Host-` Secure/HttpOnly/SameSite=Lax/Path=/ cookies for the private
browser and handle, plus an HttpOnly public operation UUID selector. The existing
actual local session cookie remains required. Preparation refuses existing pending
proofs rather than replacing them. Decision JSON must contain the exact preview UUID;
it must also match the current operation cookie, and core independently verifies
that UUID with both private proofs and the initiating owner/session. A stale tab
cannot approve a newer operation selected by replacement cookies.

Recovery is an explicit POST, not a grant. Core's new read-only `preview` reuses the
same current client/source/owner/session/pending locks and final deadline check,
then returns only the original public preview metadata. It never changes the
original cap, rotates a cookie, allocates a subject or code, or emits correlation
state/nonce. Reloading can recover a pending request for a new explicit review.
Expired/revoked/stale recovery clears unusable transport proofs; storage failures
preserve them for retry. Successful decisions clear all three issuer cookies;
failed decisions leave newer/retryable proofs intact. Any local session-cookie
replacement or clearing also clears these transport proofs.

Navigation/restoration aborts the owned fetch and drops page inputs/preview; restored
pages cannot send a decision until a new explicit recovery. Aborting the browser
request does not promise SQL cancellation or undo an already committed decision.
Unusable approvals remain bounded by the original code cap. Process-wide erasure,
external application callback history and remote client storage are not claimed.

## Evidence and remaining work

Real HTTP/PostgreSQL tests cover Origin/media/body/query/closed fields, actual email
sign-in, private proofs, different actual owner/session, stale previews, one-use
code/denial, wrong actual native port, rollback/retry, logout and recovery/expiry.
An owned private-TLS Chromium suite uses the actual pages, actual email proof
completion and disposable database. Its inbox is a fixture-only EmailDelivery
transport, not a session/proof constructor or production route. External requests
are blocked; only the registered owned callback is fulfilled. Existing TLS/process/
database helpers are reused; no custom XML/signature producer is introduced.

The opaque redeemed result still is not an ID/access token. Concrete signing/key/
audience and final issuance semantics, a dedicated client-authenticated token POST
boundary, discovery, refresh and real interoperability remain work. Consent delivery
alone does not complete AUTH-37/38 or outbound production acceptance. Production
operations remain maintainer-supervised. ADR0032's SAML review waiver is not an
independent audit or an outbound issuer approval.
