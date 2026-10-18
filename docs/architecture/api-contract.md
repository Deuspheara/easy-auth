# HTTP contract v1

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
| GET /v1/session | session cookie | public user ID/realm/email; 401 invalid or expired |
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
