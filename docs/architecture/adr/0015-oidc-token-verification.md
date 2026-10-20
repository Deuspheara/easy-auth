# ADR 0015: Transaction-bound OIDC token verification

Date: 2026-10-20. Status: accepted for AUTH-29's optional core/PostgreSQL
verification and code-exchange boundary.
Owned local Keycloak acceptance is implemented below; hosted publication is
tracked separately. Final local identity/session issuance belongs to the separate
[AUTH-30 boundary](0016-oidc-identity-mapping.md), with its own acceptance gate;
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
interoperability evidence. The owned local Keycloak fixture below exercises real
code+S256 exchange, key rotation, invalid signatures/claims and replay with a
clearly identified private component transport.
No production-provider credentials belong in CI.

No migration or HTTP/OpenAPI route is added. Native browser/passkey/SMTP checks and
hosted publication remain separate gates. Real provider web/native acceptance,
final identity resolution/linking/issuance, independent review, SAML and outbound
issuer remain open. Local/provider proof does not complete those separate gates.

## Code and S256 exchange

The same optional feature exposes `OidcCodeExchange`, an explicit trusted client
registration authentication choice, protected authorization-code/request/response
values, and `OidcTokenHttp`. Core owns form construction, response classification
and protocol policy. `OidcHttps` implements the port using its existing shared
capacity, public TLS roots, pinned addresses, original hostname and bounded reader.
There is no production private-network, private-root or automatic method fallback.

Use one service for one persisted configuration revision. Public, client-secret
Basic and client-secret Post are explicit choices; discovery must advertise the
chosen method and S256. An omitted authentication-method member defaults to Basic
according to Discovery, never public authentication. Basic form-encodes client ID
and secret independently before base64, rather than concatenating raw values.
Credentials/policy changes require a fresh persisted revision and service replacement.

`authorization_url` takes the matching `OAuthStart`, keeps state/nonce transient,
adds openid plus bounded unique requested scopes, and uses the original S256
challenge. Reserved endpoint query parameters reject rather than overriding trusted
bindings. Browser transport still owns protected state/proof retention and actual
callback extraction; no HTTP route or cookie transport is added here.

After callback consumption, `exchange` consumes the owned context and code. It
checks exact configuration and current database authority, loads validated metadata,
resolves the checked token target, and rechecks authority after DNS before sending
any code/client secret. One form POST contains the original verifier and exact
redirect. There are no retries, redirects, ambient proxies or cookies. Discard failed
consumed contexts and start a new flow; never resurrect state or retry its code.

A successful JSON response must contain an ID token, access token and Bearer type;
unused access/refresh tokens are bounded and discarded, never session credentials.
Only its ID-token field enters established signature/claim verification. Valid
HTTP400 invalid_grant is Unauthorized; client/configuration, malformed provider,
network and timeout failures are Unavailable. Admission remains RateLimited. Raw
error descriptions, token bodies and foreign causes are never diagnostics.

The two shared service leases cover discovery, POST and signature verification.
Code exchange has a 30-second whole-operation cap including the existing 15-second
verification bound; each document/transport operation retains its shorter limits.
Native crypto keeps its lease after cancellation. Discovery is reused only within
one logical bounded verification/exchange, including unknown-key refresh. This
avoids refetching no-cache metadata and self-throttling after a consumed code;
HTTP freshness and ordinary/forced fetch budgets remain unchanged across operations.
Private snapshot reuse repeats registry checks and keeps JWKS URI/freshness binding.

Component evidence includes actual signed successes through every configured
client-authentication method, exact proof/form binding, replay and post-DNS expiry,
provider/infrastructure error separation and actual TLS POST negatives. Private TLS
fixtures substitute only their owned address/root at the internal adapter boundary;
production IP/TLS rules and opaque request constructors remain intact. These
component checks are distinct from local Keycloak acceptance and final session issuance.


## Owned Keycloak acceptance boundary

The explicit [native suite](../../../tests/browser/oidc/README.md) uses the pinned
Keycloak26.8.1 image and real PostgreSQL begin/consume/context checks. It imports the
same private production TLS builder, GET, POST and bounded response reader sources
into an owned development example. No production visibility/root/IP override is
added. Only that private example maps the checked fixture hostname to its owned
TLS listener and certificate. Hostname/SNI, certificate, peer, timeout, type/body
and redirect/proxy checks remain enabled. Existing actual TLS negatives stay intact.

The Node runner owns the TLS proxy, intercepted callback, fresh browser contexts,
random admin/client/user credentials, container and random PostgreSQL database.
Browser-only resolver/proxy arguments and fixture-certificate tolerance change no
user device/system setting. IPC transports proof privately between owned processes;
it must never be attached to a terminal, log, trace or persisted artifact. Native
stdout is a private pipe; ordinary runner output is finite case/count/cleanup data.
No ordinary callback, local session or provider login route is implemented.

Eleven named cases cover real provider code+S256/RS256 and rotation, provider code/
verifier replay, PostgreSQL consumed-state replay, actual signed wrong nonce and
untrusted audience, wrong PKCE, controlled signature corruption and old-token
substitution, a fresh valid control after negatives and disable before any code POST.
Claim/signature negatives require an actual successful provider token envelope and
exact Unauthorized; broken transport is not acceptable denial evidence. The client
requests only openid/profile, preserving a valid omitted-email case. Public/Post
client methods and broader claim/key matrices retain separate component evidence.

Keycloak's actual no-store discovery/JWKS headers remain unchanged. Distinct
operations observe existing miss admission; real rotation therefore does not prove
the forced-refresh cached-key branch, whose bounded real-signature tests remain
separate. Controlled corruption/replay occurs at the owned proxy, not in Keycloak.
These limits preclude a general provider/compliance/production interoperability claim.

Cleanup requires normal native exit and zero local users/sessions/audits/pending,
then removal of the exact generated database, owner-labeled container and private
files. Pool closure is followed by terminating residual connections only in that
exact owned database. Emergency cleanup never converts a failed suite into a pass.
The explicit CI command runs after browser dependency setup; ordinary Cargo tests
do not silently skip or require provider tooling. No external production credentials,
new dependency/version, migration or authentication-policy change is introduced.


## First-fetch admission and final lease ownership

Further acceptance tests reproduced two application failures that the original
provider runner's explicit pauses concealed. An immediate callback after no-store
authorization metadata returned RateLimited before its code POST. With independently
fresh discovery and no-store keys, a consecutive valid exchange returned RateLimited
after the provider code was already exchanged. Requiring every caller to insert
arbitrary delays is not the intended code-flow behavior.

Code-flow authorization/exchange now holds the existing two-operation lease while
waiting at most the remaining ordinary one-second interval before its first
discovery or key load. It then calls the unchanged normal loader exactly once.
The timer retains no database or cache-slot lock; registry/URL/freshness/admission
checks run normally afterward. No failed-request, key-refresh, state or code retry
loop is added. No-store documents are refetched for each operation; cache URI and
HTTP expiry binding, ordinary fetch rate and forced-refresh bounds are unchanged.
Standalone document/token APIs and unknown-kid refresh keep prompt backpressure.
Authorization preparation has at most one second of admission plus its existing
five-second document bound; exchange/verification keep their 30/15-second caps.
Original post-DNS and final authority/deadline checks still apply after all waits.

A separate reproduced resource defect moved the last lease reference into a
successful native refresh retry, releasing it before final repository validation.
The retry now receives a clone while the operation retains its original reference
through final authority/claims checks. Native cancellation ownership is preserved.
The regression gates an actual rotated signature at its final authority read and a
second operation at its initial read: a third must promptly return RateLimited,
then both actual signed controls succeed after release. Broken crypto/network is
not accepted as capacity evidence.

Tests retain generic prompt miss rejection and require fresh no-store fetches when
flow admission becomes available. They cover expiry/disable/registry failure during
admission, canceled waiters and recovered capacity, and original expiry after a
key wait reaching actual signature/final-clock checks. The same eleven Keycloak
cases now run without runner-side pacing, preserving actual headers and fault
categories. The earlier paced record stays immutable. These changes introduce no
public root/IP override, protocol downgrade, persistence policy or session grant.
