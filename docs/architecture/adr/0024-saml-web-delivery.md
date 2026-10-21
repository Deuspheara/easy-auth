# ADR 0024: Gated SAML POST delivery and same-origin completion

Date: 2026-10-22. Status: opt-in engineering integration; production approval open.

## Decision

Add an explicit `saml-web` feature to auth-axum and
`experimental_saml_web_router`. Ordinary router/server startup remains unchanged.
The composition requires HTTPS, the authentication realm matching the trusted
policy, and the exact configured `{origin}/saml/acs`. One trusted policy constructs
request, verifier and identity components with identical source snapshots. No
browser field selects realm, connection, local client, certificate or JIT policy.
No SQL or independent identity policy is introduced in handlers.

Existing host-only Secure/HttpOnly `SameSite=Lax` cookie policy stays unchanged.
A cross-site IdP form POST may not send these cookies, including an existing local
session. Therefore the ACS is a non-authoritative delivery page: accept only the
bounded closed POST form `SAMLResponse`/`RelayState`, reject query selectors, and
render HTML-escaped hidden values with a fixed same-origin script. Reading this
page does not read cookies/storage, consume a request, verify a signature or create
a user/session. Input parsing establishes only transport shape/bounds.

The fixed script removes the hidden form from the document and forwards its fields
to a same-origin POST finish route. That route uses the ordinary origin boundary,
requires absence of any session cookie, and reads host-only request ID, independent
private browser proof and RelayState cookies. The returned RelayState must match.
Core consumes the exact one-use pending request, the concrete verifier authenticates
its signed response/Assertion, mapping checks exact policy, and the existing final
transaction grants local authority. An existing session cannot be silently replaced
because it is checked in the same-origin step rather than inferred absent from the
cross-site POST. No cookie is downgraded to SameSite=None or exposed to script.

Cancellation is also same-origin and browser-bound. Pending cookies cannot be
overwritten by another start. Finish/cancel clear their local proofs after a typed
completion result; logout and session revocation cookie cleanup clear SAML proofs
alongside the session. Missing proof/current configuration or verification failures
fail closed. Malformed transport/origin rejection does not imply durable cancellation.
Pending database deadlines remain authoritative after cookie expiry/cleanup.

## Transport and contracts

The opt-in contract adds start/finish/cancel, ACS delivery, metadata and a reference
sign-in page. Public metadata comes from the configured library producer. All
normal cookie/session APIs remain shared. Enforce a bounded form body allowing for
URL encoding; the core independently enforces the encoded assertion limit. Forms
are closed against duplicate/unknown fields and all completion APIs reject query
selectors. Returned assertions and private proofs are never placed in URLs, errors, tracing
or audit. Outgoing library-generated Redirect requests retain their protocol URL.

The ACS is the sole cross-site delivery exception. It shares the existing timeout,
no-store/no-referrer, CSP, nosniff, HSTS and redacted request-status logging code.
Only its fixed HTML handoff handler uses that exception; authority-changing routes
retain same-origin checks. CSP allows only fixed same-origin scripts/connect/form
and forbids embedding and base injection. No alternate return URL is accepted.

The response travels through the browser document, as it already does in POST
binding. No server-side untrusted-response cache, browser storage, new persistence,
XML parser, cryptographic implementation or protocol fallback is added. HTML
escaping is an output-encoding operation, not an assertion parser. Bridge and DTOs
have no Debug contract exposing their payload.

## Evidence and remaining requirements

Ordinary HTTP tests use the unchanged public fixture and shared established IdP
facade, actual verification and real PostgreSQL. Browser tests must separately
establish actual cross-site cookie delivery; router request construction alone is
insufficient. Test fixture endpoints can issue ordinary protocol messages but cannot
construct local proofs or seed local authority. Test-only TLS/protocol delivery is
not a production exception or deployed IdP interoperability evidence.

Normal SAML stays disabled. This composition is not normal server configuration,
production dependency approval, an independent audit, qualified-attribute support
or a complete purpose-bound deletion lifecycle. ADRs 0021–0023 retain maintained
source/patch approval, XML/backend review, actual IdP rollover/identity/lifecycle
interoperability and named independent approval before production activation.
