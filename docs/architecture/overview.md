# Architecture

Project name: easy-auth (selected by the project owner). Rust stable, Tokio, Axum, SQLx/PostgreSQL. One binary and PostgreSQL; SMTP is a configurable delivery dependency. No mandatory JavaScript runtime or cache.

The first workspace has auth-core (use cases, repository/email ports and domain DTOs), auth-postgres (SQL transactions/migrations), auth-axum (HTTP/cookie boundary) and auth-server (composition/config). Protocol modules are added only as implemented; no empty protocol crates. An SDK is introduced with a real remote use case. Domain authorization remains in the consuming application.

Follow the [code organization guide](code-organization.md) for feature ownership, folder layout and maintainability review. Crate entry files expose deliberate APIs; feature implementation and tests live in focused modules within these boundaries.

```mermaid
flowchart LR
  embeddedApp["Embedded Axum application"] --> httpAdapter["auth-axum"]
  remoteApp["First-party same-origin application"] --> serverApp["auth-server"]
  serverApp --> httpAdapter
  httpAdapter --> coreService["auth-core use cases"]
  pgAdapter["auth-postgres implements repository"] --> coreService
  serverApp --> pgAdapter
  pgAdapter --> database["PostgreSQL"]
  coreService --> mailPort["Email delivery port"]
```

Arrows into core denote compile-time dependency, not a network RPC. Runtime core calls a repository port implemented by PostgreSQL. The server never reaches into tables directly. Embedding selects a server-configured realm and origin. Standalone alpha supports only same-origin first-party browser integration; unrelated apps require the M07 issuer, not cookie sharing.

Inbound OIDC clients and SAML SPs resolve verified external identities. Outbound OIDC issuer/client registration is a distinct module and release gate; no discovery endpoint is advertised until implemented and tested. Secrets are never part of public user/session DTOs.

See domain-model, auth-flows, api-contract, deployment and the threat model. Authentication release is blocked on the six method categories, issuer interoperability and security review, even if alpha email works.

The optional `oidc-egress` feature keeps URL/address/cache/metadata policy in core,
current enabled configuration checks in PostgreSQL, and the concrete `OidcHttps`
adapter in the server library. Embedded consumers share that adapter. Short registry
transactions commit before DNS/HTTPS; cached or fetched documents confer no identity
authority. No provider route is activated. [ADR 0014](adr/0014-oidc-egress.md) records
pinning, resource bounds and the native resolver limitation.

The optional `oidc-verification` feature builds on those documents and consumed
OAuth state. Core uses fixed per-key josekit/OpenSSL verification with mandatory
typed claim policy and bounded workers. PostgreSQL reuses configuration/owner/session
locks and final database time before and after I/O. Its opaque verified identity
retains original transaction/token caps and grants no local session or linking
authority. Its optional code exchange uses original S256 proof and explicit
registered client authentication through the same pinned HTTPS adapter. An owned
local Keycloak/browser/PostgreSQL suite verifies that boundary using a private
fixture certificate/address mapping and shared production request code. Final
ordinary provider activation and complete lifecycle acceptance remain open.
[ADR 0015](adr/0015-oidc-token-verification.md) records the boundary.

The explicit core/PostgreSQL `oidc-identities` features add exact-connection mapping
policy, an issuer allowlist and default-deny JIT configuration. Trusted policy
application rotates connection revision and cancels pending state atomically while
retaining disable. Mapping alone grants nothing; `OidcSignIn` consumes the mapped
proof in an atomic current-policy/JIT/subject/session/audit transaction. Provider-only
users have explicit policy and current source-bound sessions. Ordinary routes,
linking and complete provider lifecycle remain gated. Owned Keycloak acceptance now
extends through final JIT/session commit, with publication tracked separately.
[ADR 0016](adr/0016-oidc-identity-mapping.md) records that boundary.

AUTH-55's optional provider deletion use case consumes a separate purpose-bound
proof and requires the initiating source's exact subject and genuine recent signed
authentication. The shared account erasure tail supports absent verified contact;
the caller holds source/owner/session/identity locks and retains every original cap
through the final clock check. An explicit opt-in provider deletion HTTP/browser composition is implemented;
owned provider-to-HTTP acceptance is recorded and ordinary activation remains gated. [ADR 0017](adr/0017-provider-account-deletion.md)
and the [deletion guide](../guides/oidc-account-deletion.md) record that boundary.

[ADR 0018](adr/0018-oidc-web-composition.md) records AUTH-56's shared OIDC browser
composition, including a common exact callback, explicit session handling and stable
startup configuration. Stable policy loading and an opt-in Axum browser boundary
and shared standalone/embedded configuration are implemented; supported-mode
native public-login acceptance now has owned Keycloak evidence with explicit
private-transport limits. See the [verification history](../security/verification.md)
for dated checks and the [browser guide](../guides/oidc-web.md) for the opt-in
contract. Broader release gates remain open.

AUTH-23's optional core `google` component fixes Google issuer/egress/RS256/scope
and registered wire-authentication policy around the same opaque sign-in exchange.
It returns the existing verified identity proof and adds no SQL, route, native
transport or local-session grant. The [component guide](../guides/google.md) and
[ADR 0019](adr/0019-google-code-flow.md) distinguish offline signature controls from
the remaining public callback/native transport and real-provider lifecycle acceptance.
