# HTTP contract v1

AUTH-19 adds explicit experimental passkey HTTP sign-in, separately enabled from
the ordinary router/server. Its verified session transaction, mode/selection contract
and remaining stronger-account gates are documented in the
[sign-in guide](../guides/passkey-authentication.md).

Initial same-origin browser contract. Realm is trusted router configuration. JSON bodies are bounded at 8 KiB. Auth responses use Cache-Control: no-store. Errors expose stable codes; internal database/SMTP details never reach the caller. Authentication secrets never appear in query parameters or response JSON.

| Method/path | Input | Output / behavior |
|---|---|---|
| GET /openapi.json | none | generated implemented v1 API specification |
| GET /healthz | none | 200 liveness, no dependency details |
| GET /readyz | none | 200 if database reachable; 503 otherwise |
| POST /v1/email/start | {email} and exact configured Origin | 202 generic accepted; browser-binding HttpOnly cookie; rate limit 429 independent of account existence |
| POST /v1/email/finish | {token} and binding cookie + Origin | 204 plus fresh session cookie; invalid/expired/replayed/misbound 401 |
| POST /v1/password/enroll | {password}, fresh session cookie + Origin | 204 enrolls once, revokes prior sessions, sets replacement cookie; 400 policy rejection, 401 stale/invalid/existing credential; 429 admission/capacity, 503 disabled |
| POST /v1/password/login | {email,password} + Origin | 204 fresh session cookie; generic 401 invalid/unknown/no credential; 429 admission/capacity, 503 disabled |
| POST /v1/password/reset/start | {email} + Origin | generic 202 and reset binding cookie; same mail path for every email; 429 shared admission, 503 disabled/delivery failure |
| POST /v1/password/reset/finish | {token,password}, reset cookie + Origin | 204 changes existing credential, revokes sessions/proofs, queues notification; clears cookies; normal login required; 401 invalid proof, 400 password policy |
| GET /reset | emailed fragment, handled only by browser | reference reset form; GET does not consume proof |
| POST /v1/account/email/start | {email}, fresh session + Origin | 202; separate current/new address proofs and binding cookie |
| POST /v1/account/email/confirm | {token}, same fresh session + change binding + Origin | 202 first proof; 204 second proof changes verified email, revokes sessions/proofs and clears cookies; login required |
| POST /v1/account/delete/start | {confirmation: "delete my account"}, fresh session + Origin | 202; current-mailbox deletion proof and binding; no mutation yet |
| POST /v1/account/delete/finish | {token,confirmation}, same fresh session + deletion binding + Origin | 204; auth account cleanup/deidentified audit, cleared cookies; generic 401 stale/invalid proof |
| GET /email-change and /account-delete | fragment handled only by browser | reference confirmation pages; GET does not consume proof |
| GET /v1/session | session cookie | public user ID/realm, required nullable email/display_name; 401 invalid, expired or method rejected by account policy |
| GET /v1/sessions | session cookie, optional after UUID | at most 50 owned active session metadata entries, next cursor; invalid caller 401 even on empty pages |
| POST /v1/sessions/revoke | {id}, fresh session + Origin | 204 owned target revoked; foreign/unknown/inactive targets are the same no-op; current target clears cookies |
| POST /v1/sessions/revoke-all | {}, fresh session + Origin | 204 all owned sessions and pending proofs canceled atomically, caller included; cookies cleared; new sign-in allowed |
| POST /v1/logout | session cookie + Origin | 204 idempotent server revocation and cookie clearing |
| GET / | none | minimal local reference email client, no third-party assets |

Planned versioned endpoints: passkey registration/authentication/management, connection-specific OIDC/social start/callback/link/unlink and SAML metadata/ACS. These require concrete OpenAPI schemas and negative tests in their milestones; they are not available by virtue of this document.

Only exact configured Origin is accepted on initial browser POST endpoints, including pre-authentication. Missing/null Origin fails closed, so command-line clients must explicitly send it. No wildcard credentialed CORS. SameSite=Lax, Secure in HTTPS production, HttpOnly, Path=/, no Domain; production session uses __Host- prefix. Dev HTTP is loopback-only and explicitly enabled. Duplicate cookie names/invalid token shapes must be rejected. An Origin guard is appropriate for this constrained same-origin contract; it is not a substitute for OAuth state or SAML correlation.

Outbound issuer (M07) has a distinct protocol contract: registered clients, exact redirects, code + S256, client authentication where applicable, signing keys, discovery, JWKS, audience-bound ID/access tokens, revocation and introspection. First-party alpha session introspection does not constitute OIDC support. Native refresh credentials and cross-origin apps are unavailable until that gate passes.

Password policy and configuration: [guide](../guides/passwords.md); credential enrollment decisions: [ADR 0003](adr/0003-password-enrollment.md).

Recovery proofs, version binding and notification lifecycle: [guide](../guides/password-recovery.md), [ADR 0004](adr/0004-password-recovery.md).

Lifecycle policy, proof ordering, freshness and privacy scope: [guide](../guides/account-lifecycle.md), [ADR 0005](adr/0005-account-lifecycle.md).

Session inventory fields, freshness, pagination, cookie effects and concurrent-login semantics: [guide](../guides/sessions.md), [ADR 0006](adr/0006-session-management.md).

Audit facts are transaction-internal with no public append/read route. HTTP/OpenAPI remain unchanged by AUTH-16. [Audit schema, attribution and linking policy](../guides/audit-events.md), [ADR 0007](adr/0007-safe-audit-and-linking.md).

## Optional mailbox contract

Migration 0009 changes Rust `User.email` to `Option<String>` and adds
`display_name` plus typed account policy. The HTTP user response has required,
nullable `email` and `display_name`; existing verified emails remain strings.
Default and experimental OpenAPI snapshots include this shared contract change.
Passkey-required accounts reject weak-method sessions, email/password login and
password recovery; mail-only lifecycle operations are unavailable pending
AUTH-20. Fresh passkey session controls work without email. The optional core/PostgreSQL signup use case now requires a separate verified
assertion before creating the account/session. Explicit signup HTTP/native browser
evidence now exists; verified-mailbox attachment remains AUTH-53 implementation work. See the
[model/migration guide](../guides/optional-mailbox.md).

## Explicit experimental passkey enrollment

The `easy-auth-axum/passkey-enrollment` feature exposes
`experimental_passkey_enrollment_router`. The ordinary router and standalone
server never enable it automatically. Composition rejects mismatched realms or
origins before mounting. This is registration only: it issues no passkey session
and does not implement sign-in, passkey-first accounts or stronger-account recovery.

| Method/path | Input | Output / behavior |
| --- | --- | --- |
| POST /v1/passkeys/enrollment/start | `{label, discoverable?:bool}`, fresh session cookie and exact Origin | 200 `{transaction_id, options: {publicKey: ...}}`; optional explicit resident request; sets/reuses two-minute HttpOnly browser binding |
| POST /v1/passkeys/enrollment/finish | `{transaction_id, credential}`, same session/binding cookies and exact Origin | 201 `{id}` after verified, atomic single-use registration; no new authenticated session |

Only these two experimental endpoints use a 32 KiB encoded JSON body bound;
ordinary routes retain 8 KiB. Core decoded ceremony buffers are additionally
bounded to 16 KiB. Start/finish outer objects reject unknown fields. `credential`
uses standard browser WebAuthn JSON: canonical base64url `id`, encoded `rawId`,
type `public-key`, `response.attestationObject` and `response.clientDataJSON`,
with optional transport/extensions fields. Only the high-level verifier's attested
credential data is authoritative; browser convenience public-key fields are not.

The private serialized verification state is absent from options, cookies and
response JSON. The binding cookie is `__Host-auth-passkey` under HTTPS, otherwise
`auth-passkey` in explicit localhost development; HttpOnly, SameSite=Lax, Path=/,
no Domain, Max-Age=120, Secure under HTTPS. It is retained after one completion so
other pending ceremonies in the same browser can finish. Current/all-session
revocation clears it when the feature is compiled; logout clears the authenticated
session, and this short-lived binding expires separately.

Errors use the existing redacted codes: 400 invalid input/JSON, 401 invalid,
expired, replayed or misbound authentication/proof, 403 rejected Origin, 413 body
bound, 415 unsupported media, 429 admission/credential/pending limits, 503 unavailable
persistence and 504 request timeout. Rejected and rolled-back operations create no
success audit fact. The experimental router serves the complete combined schema at
`/openapi.json`; its [generated snapshot](openapi-passkey-enrollment.json) is checked
against live output. Default [OpenAPI](../openapi.json) excludes experimental
routes while sharing the optional-mailbox user contract described above.

See the [enrollment guide](../guides/passkey-enrollment.md) and
[browser test instructions](../../tests/browser/passkeys/README.md) for verified
boundaries and remaining M03 release gates.

## Explicit experimental passkey authentication

The additional `passkey-authentication` feature exports `experimental_passkey_router`
and a [full schema](openapi-passkeys.json), combining base, enrollment and sign-in.
Ordinary server composition stays gated on the remaining M03 security policy.

| Method/path | Input | Output / behavior |
| --- | --- | --- |
| POST /v1/passkeys/authentication/start | `{mode:"account_bound",account_id}`, `{mode:"discoverable"}` or `{mode:"conditional"}`, exact Origin | 200 `{transaction_id,options}`; persists private state; sets/reuses host binding cookie |
| POST /v1/passkeys/authentication/finish | `{transaction_id,credential}`, same binding and exact Origin | 204 with fresh session cookie after atomic verified key/state/session/audit commit |

Both use 32 KiB bodies and the same redacted errors and cookie policy as enrollment.
Account selection uses an opaque remembered/private owner hint; email lookup and
extra/unknown mode fields are rejected. Modal discovery has no selected account;
conditional mode preserves the browser autofill hint. Private state and session
secrets are absent from JSON. See the sign-in guide for native JSON conversion,
counter/backup/context policy and the new-browser nonresident selection limitation.

## Explicit experimental anonymous signup

`easy-auth-axum/passkey-signup` exports `experimental_passkey_signup_router`,
combining base, enrollment, sign-in and three signup routes with a [full schema](openapi-passkey-signup.json).
Normal server composition and the earlier experimental constructors do not enable
signup implicitly. Every signup POST requires exact Origin, JSON, no session cookie
and at most 32 KiB; unknown fields are rejected. Even an expired/unknown session
cookie requires explicit logout first. Both completion stages require the original
HttpOnly passkey browser binding.

| POST path | Input | Result |
| --- | --- | --- |
| `/v1/passkeys/signup/start` | `{display_name}` | 200 `{transaction_id,options}` with required-UV resident creation options and binding cookie; no durable account/session |
| `/v1/passkeys/signup/registration` | `{transaction_id,credential}` registration JSON | 200 `{transaction_id,options}` for separate assertion; only the candidate/stage changes |
| `/v1/passkeys/signup/finish` | `{transaction_id,credential}` assertion JSON | 204 fresh session cookie after verified atomic account/key/session/audit completion |

Registration alone never authenticates. The prospective owner is server-selected;
no client owner, email, RP or residence override is accepted. The two-minute database
expiry is not extended at registration completion. New authenticated users have
`email: null` and passkey-required policy. Existing error/cookie/CSRF rules apply.
See the [signup guide](../guides/passkey-signup.md) for limits, one-use scope and
native platform/roaming evidence. Verified-mailbox attachment and AUTH-20 recovery/
management remain required before ordinary activation.
