# Authentication flows

These are target designs. Only flows backed by implementation/test evidence are available. There is no generic protocol verifier abstraction.

## Transaction lifecycle
```mermaid
stateDiagram-v2
  [*] --> Pending
  Pending --> Consumed: Verified and committed atomically
  Pending --> Expired: Deadline reached
  Pending --> Cancelled: User or connection disabled
  Consumed --> [*]
  Expired --> [*]
  Cancelled --> [*]
```

## Initial email and session flow
```mermaid
sequenceDiagram
  participant browserClient as Browser
  participant authService as Shared auth core
  participant database as PostgreSQL
  participant emailService as SMTP
  browserClient->>authService: Request email sign-in with Origin
  authService->>database: Rate admission and expiring token/browser verifiers
  authService->>emailService: Link with secret in fragment
  authService-->>browserClient: Generic accepted and HttpOnly binding cookie
  browserClient->>authService: POST token plus binding cookie and Origin
  authService->>database: Atomically consume proof and create identity/session
  authService-->>browserClient: Fresh HttpOnly session cookie
  browserClient->>authService: Protected route
  authService->>database: Validate verifier, idle and absolute expiry
  browserClient->>authService: POST logout with Origin
  authService->>database: Revoke matching session
  authService-->>browserClient: Clear cookie
```

A GET never consumes a magic link. The email fragment is removed from history before POST; referrer policy is no-referrer. Same-browser requirement deliberately disallows cross-device email redemption initially. Mailbox compromise remains a takeover risk; email alone is not phishing resistant. Delivery occurs after proof persistence; failure leaves an expiring unusable-to-the-requester proof and allows a later fresh request under rate policy. Do not log link bodies.

## Passkeys (M03)
```mermaid
sequenceDiagram
  participant browserClient as Browser authenticator
  participant authService as WebAuthn adapter
  participant database as PostgreSQL
  browserClient->>authService: Fresh authenticated enrollment or login start
  authService->>database: Store expiring private challenge state
  authService-->>browserClient: Public WebAuthn options
  browserClient->>authService: Credential response
  authService->>authService: Validate RP, origin, challenge, UV and signature
  authService->>database: Consume state and update credential atomically
  authService-->>browserClient: Credential metadata or new session
```

Embedded RP is the application's domain; centralized RP belongs to the authentication domain. Unrelated domains cannot freely share credentials. Multiple credentials, rename/removal, discoverable login, counter/backup-state updates, recovery and virtual/real authenticator tests are release requirements.

## Email-free passkey signup (AUTH-53)

The optional shared core/PostgreSQL flow below is implemented, with explicit
experimental HTTP and native anonymous platform/roaming Chromium evidence. This
does not enable ordinary server composition. Contact attachment has experimental
core/HTTP and native Chromium/SMTP evidence; full stronger-account management/
recovery remains required. See the [signup guide](../guides/passkey-signup.md).

```mermaid
sequenceDiagram
  participant browserClient as Browser authenticator
  participant authService as Shared signup core
  participant database as PostgreSQL
  browserClient->>authService: Start with display label and browser binding
  authService->>database: Bound pending state with server-selected prospective UUID
  authService-->>browserClient: Resident creation options with required UV
  browserClient->>authService: Registration response
  authService->>authService: Verify registration through high-level service
  authService->>database: Advance pending state; no user or session
  authService-->>browserClient: Account-bound assertion options
  browserClient->>authService: Signed assertion
  authService->>authService: Verify actual key proof and state snapshots
  authService->>database: Insert user/key/session/audit; final expiry and one-use consume
  authService-->>browserClient: Session secret only after atomic commit
```

## Social and external OIDC (M04/M05)

Only the optional AUTH-22 core/PostgreSQL browser-bound transaction boundary is
implemented: [guide](../guides/oauth-transactions.md),
[ADR 0013](adr/0013-oauth-state-transactions.md). It consumes state once and returns
exchange context without authenticating a user. The provider exchange, claim
verification, identity resolution and session issuance below remain target design.
Their final local transaction must recheck original deadline, enabled configuration
revision and linking authority after network exchange.

```mermaid
sequenceDiagram
  participant browserClient as Browser
  participant authService as External OIDC client
  participant providerService as Provider
  participant database as PostgreSQL
  browserClient->>authService: Login with explicit connection
  authService->>database: Store browser-bound state, nonce and PKCE
  authService-->>browserClient: Authorization redirect
  browserClient->>providerService: Code flow with S256
  providerService-->>authService: Callback with code and state
  authService->>database: Claim unexpired connection-bound transaction
  authService->>providerService: Redeem code with verifier
  authService->>authService: Verify signature, issuer, audience and nonce
  authService->>database: Resolve issuer/subject under JIT policy
  authService-->>browserClient: New application session
```

Apple uses signed client secrets and distinct native/web client identifiers; profile fields may appear only on first grant. Native code exchange binds to a backend-created nonce transaction and allowlisted audience. Private relay emails are contact attributes. Google sub is identity; email_verified is explicit claim policy. No email-based merging. Disable connections before accepting callbacks. Remote discovery/JWKS has bounded egress, DNS rebinding defense and no redirects.

## SAML SP (M06)
```mermaid
sequenceDiagram
  participant browserClient as Browser
  participant authService as SAML SP
  participant providerService as Configured IdP
  participant database as PostgreSQL
  browserClient->>authService: SP initiated login
  authService->>database: Persist request ID and browser correlation
  authService-->>browserClient: AuthnRequest and RelayState
  browserClient->>providerService: Redirect binding
  providerService-->>authService: POST response to ACS
  authService->>authService: Verify configured cert and signed content
  authService->>authService: Validate issuer, audience, recipient, destination and times
  authService->>database: Match InResponseTo and atomically reject replay
  authService->>database: Resolve trusted NameID and JIT policy
  authService-->>browserClient: New session
```

Cross-site POST callback binding uses a separately reviewed short-lived transaction mechanism; do not globally weaken session SameSite. No IdP-initiated SAML initially, no SLO or SAML IdP. Do not expose ACS before the SAML dependency gate passes.
