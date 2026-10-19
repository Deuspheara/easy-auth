# ADR 0015: Transaction-bound OIDC token verification

Date: 2026-10-20. Status: accepted for AUTH-29's optional core/PostgreSQL
verification boundary. AUTH-29 remains in progress. Token endpoint exchange,
local Keycloak acceptance and final local identity/session issuance remain gates;
this decision activates no provider route or ordinary authentication composition.

## Context and dependency choice

AUTH-22 provides consumed browser/realm/client/connection/purpose-bound state;
AUTH-28 provides constrained documents; AUTH-29 adds bounded snapshot refresh.
None of those proves a signature or identity. Provider input must not select an
algorithm, arbitrary key URL or local account by matching email.

Use josekit **0.10.3**, defaults disabled, with its established per-verifier OpenSSL
JWS implementation. High-level compact JWS verification performs signature parsing
and cryptography; core owns required typed OIDC claim and key policy. No custom
signature verifier, insecure decoding, unsecured/JWE flow or generic crypto provider
is added. RSA PKCS#1/PSS and P-256 verification are explicit algorithm choices.

The openidconnect 4.0.1 candidate selects advisory-affected RSA even with defaults
disabled. An isolated jsonwebtoken 11.1.0 AWS-LC experiment passed its graph and
signature controls but initializes a process-global provider at high-level decode.
The selected per-verifier API avoids that integration requirement and reuses the
existing native OpenSSL family. Selection is not an independent audit. The combined
locked workspace passes compiled advisory and license/source checks without any
exception; ten packages are added and no previously locked version is removed or
upgraded. Record risks/notices in the [dependency assessment](../../research/protocol-dependencies.md).

Sources: [OIDC Core ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html),
[josekit 0.10.3 source](https://docs.rs/crate/josekit/0.10.3/source/), and
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html).

## Proof and ownership

The explicit `oidc-verification` feature adds `OidcTokenVerifier`. Trusted composition
shares one service per persisted connection/revision with its `OidcDocuments`,
PostgreSQL port and explicit `OidcVerificationPolicy`. A policy change requires
reapplying configuration for a new revision and replacing the service. It is never
selected from callback/token inputs.

`verify` consumes an `OAuthExchange` and an `OidcIdToken`. It first compares the exact
connection snapshot, rechecks it through PostgreSQL, validates the header/policy,
loads bounded keys and verifies the signature. Only an unknown `kid` can trigger one
bounded refresh and one retry. Known-key bad signatures, malformed/ambiguous keys
or bad claims do not retry. The existing refresh interval may reject an immediate
cold-cache retry; the caller starts a new flow rather than looping or reviving state.

After signature verification, PostgreSQL rechecks enabled configuration, original
expiry and linking owner/session under the established configuration -> owner ->
session lock order. It uses the shared actual-method/freshness policy and the minimum
of current session and original exchange caps. A materialized database clock read
follows all potential row waits. Read transactions commit before network/crypto;
no lock spans those operations. Core validates claims against the final database
time and the original exchange cap; it does not fall back to the application clock.

The opaque `VerifiedOidcIdentity` has no constructor, Clone or Serialize. It retains
exact configuration/purpose/subject and a deadline capped by the original exchange,
ID-token expiry and original five-minute token-age window. Nonce/PKCE/raw token are
not retained. An omitted email does not invalidate identity; a standalone verification flag
cannot create a verified email attribute. Public attributes are provider assertions, never local contact,
automatic linking, account policy or factor-assurance authority. Provider auth_time
is optional and distinct from iat; missing auth_time never becomes a fresh timestamp.

This is not a session grant. Final identity/session persistence must consume this
value once and recheck configuration, cap, owner/session, account policy and external
identity uniqueness under its own locks. Disable/revoke after the final read can
race return; no read-only proof freezes wall time or grants later authority.

## Explicit input and resource policy

- Raw ID token: at most 16 KiB; three nonempty compact segments; encoded header at
  most 2 KiB; ASCII without raw whitespace/controls. Debug is redacted and raw input
  is zeroized on final owned drop. Dependency parsing creates temporary buffers;
  this is not a process-wide secret-memory erasure guarantee.
- Header: required exact algorithm and bounded nonempty kid, optional JWT media
  type. Duplicate known fields, null optionals, unknown/critical/embedded-key/URL/
  compression/encryption/unencoded-payload extensions are rejected before fetch.
- Algorithms: explicit RS256, PS256 and/or ES256. No HMAC, none, algorithm inference,
  token-selected fallback or process-global crypto provider installation.
- Keys: preserve duplicate-member rejection before any map conversion; reject
  duplicate key IDs, inconsistent alg/use/key_ops and malformed selected components.
  RSA is 2048–8192 bits with bounded canonical modulus/exponent; EC is P-256 with
  exact coordinate sizes. Only validated public components enter the library.
- Claims: mandatory correctly typed issuer, subject, audience, exp, iat and nonce;
  exact issuer/client/nonce; bounded ASCII subject; duplicate security fields and
  null/incorrect optional types reject. Multiple audiences require explicit trust
  for every additional audience and matching azp; any present azp must match client.
- Clock: unsigned whole-second NumericDates, no leeway; iat must not be future and age must be strictly less than five
  minutes; exp must be later than iat and database time; nbf cannot be future;
  auth_time cannot be later than iat. Clock synchronization is an operational need.
- Work: two operations per shared verifier; immediate overload rejection; a 15-second
  whole-operation timeout includes repositories, document loads, refresh and crypto.
  Blocking crypto jobs retain an owned lease and token buffer after async cancellation
  until native work finishes. Input/key bounds limit that work; timeout does not
  kill native code. Document transport keeps its separate shared limits.

Errors stay finite. Invalid token/signature/claims/context returns Unauthorized;
malformed provider document/registry/worker/timeout failure returns Unavailable; bounded
capacity or refresh admission returns RateLimited. A valid key paired with an
incompatible token algorithm/use is Unauthorized, distinct from malformed key
components or duplicate provider IDs. Raw library errors, headers,
URLs, token/nonce/key/claim contents never enter diagnostics. Positive signature
controls are separate from infrastructure and malformed-provider negatives.

## Evidence and remaining acceptance

Tests use actual library-generated RS256/PS256/ES256 signatures, wrong-key controls,
original signed duplicate/extension header and claim bytes, exact errors, bounded
rotation and real PostgreSQL context/deadline ownership alongside the existing
OAuth state-replay regressions. These are component
regressions; generating and verifying with one library is not independent protocol
interoperability evidence. The required local Keycloak flow must still exercise real
code+S256 exchange, key rotation, invalid signatures/claims and replay with the
configured production boundary or a clearly identified private component fixture.
No production-provider credentials belong in CI.

No migration or HTTP/OpenAPI route is added. Native browser/passkey/SMTP checks and
hosted publication remain separate gates. Real provider web/native acceptance,
final identity resolution/linking/issuance, independent review, SAML and outbound
issuer remain open. AUTH-29 must not be marked Done on this partial boundary.
