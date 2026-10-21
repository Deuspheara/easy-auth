# Gated SAML integration

SAML is not enabled in normal embedded or standalone composition. There is no
ordinary ACS route or SAML local-session grant. [ADR 0021](../architecture/adr/0021-saml-verification-and-approval.md)
records the verifier recommendation and distinct approval requirements. An
internal assessment and green tests do not constitute independent approval.

## Outgoing requests and metadata

The opt-in core/PostgreSQL `saml-requests` feature implements outgoing registration,
metadata, request persistence, cancellation and response preparation. It selects
the [packaged qualification source](../../third-party/README.md) of saml-rs
**0.6.1** at `3b289001a7a84d5a7ff7af2671991ab7098090bd`, with the three existing
qualification patches, defaults disabled and **no cryptographic provider enabled**.
Source/patch hashes and existing upstream vectors are retained. This is a gated
engineering dependency, not an upstream release or production verifier approval.
The earlier registry producer at `6b414db010235f6c2d1121944b42919a82325b06`
(checksum `4997d94a9df26e1e2768acc8fedc70afeb456d503f7af4cd85d8d8bd363ab984`)
was a different source despite the same version; its tests do not qualify this
snapshot. Source integrity and ordinary component regressions are checked again.

Trusted embedding constructs `SamlRegistration::unsigned_redirect` with realm,
connection/client UUIDs, exact SP/IdP entity IDs, HTTPS SSO URL and HTTPS ACS URL.
Entity IDs are absolute identifiers, including URNs, and remain exact. Endpoint
URLs must be canonical HTTPS with no credentials, query or fragment. Values are
bounded; nil namespace IDs and malformed configuration reject. Entity IDs reject
userinfo and are limited to 1024 UTF-8 bytes, a conservative implementation of
the [metadata schema's 1024-character bound](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd).
Endpoint URLs are limited to 2048 bytes.

This explicit profile generates unsigned Redirect AuthnRequests and requests POST
responses with persistent NameID and directly signed Assertions. Generated SP
metadata declares those exact flags and one POST ACS; it advertises no encryption,
signing key, logout or other protocol endpoint. It does not create/enable the ACS.
A peer requiring signed requests needs a separate signing implementation and
configuration. Do not treat this unsigned profile as satisfying that requirement.

Only internally generated SP/IdP metadata is parsed by the producer. No imported
IdP XML, network metadata fetch or response parsing is exposed. saml-rs performs
XML writing and Redirect encoding; easy-auth does not implement canonicalization
or XML signatures.

Persist registration through `Postgres::configure_saml_registration`, then pass its
returned revision to `SamlTransactions::new`. Administrative replacement always
allocates a new revision, retains disable and cancels old pending requests in one
transaction. `disable_saml_registration` rotates authority and cancels pending
state; re-enabling requires an explicit call with the latest configured revision.
This is administrative provisioning, not a stable automatic startup loader.

`start` returns a committed `SamlStart`: generated request ID, authorization URL,
opaque RelayState, independent browser proof and original database expiry. Send
the URL only to the initiating browser. The transport must protect the private
browser proof in a host-bound HttpOnly cookie; RelayState/request ID alone cannot
authorize cancellation. The requests component does not provide that HTTP cookie
boundary itself. Debug output redacts state/URLs/proofs. Never log them.

PostgreSQL stores only proof hashes, exact namespace/revision/request ID and a
five-minute original admission cap. Registry serialization precedes request writes;
the cap is captured before registry waits and checked after the write tail. Pending
storage is limited to 128 requests per realm/connection/client. Expired rows are
pruned on admission. This storage bound is not an HTTP attempt-rate limiter or
resource-exhaustion assurance; browser/ACS delivery still needs its own reviewed
admission policy before activation.

`cancel` requires exact request ID, RelayState, independent browser proof and
current enabled registration. Wrong proofs leave pending state untouched. It is
one-use, has no user/session effect and never verifies or consumes an Assertion.
Cancellation/storage errors remain distinguishable from successful cancellation.

## Preparing a response for verification

`SamlTransactions::prepare_response` takes the exact request ID, RelayState and
independent browser proof. PostgreSQL consumes that request under the current
exact enabled registration and both proof hashes. It returns `SamlPreparedResponse`
with the original request ID, registration/revision, original database expiry and
observed database time in microseconds. Debug output is redacted, and the context
has no public constructor or clone. Custom storage adapters receive a default
unavailable implementation until they implement `take_saml_request`.

This recognizes and consumes browser-bound request state only. It accepts no XML,
checks no signature or signed InResponseTo, and grants no identity/session. The
future verifier must compare the authenticated response and bearer InResponseTo
with this request ID, apply all protocol/certificate checks and return a separate
verified projection. Final persistence must recheck current source authority and
original/signed deadlines and atomically retain response/Assertion replay keys.
The timing port record is trusted storage metadata, not a verification proof.

Preparation and cancellation share the same registry-before-request lock order,
expiry check, one-use delete, final clock check and commit. Wrong proofs leave
state intact; an expired/stale/wrong-namespace operation fails closed. No storage
lock spans parsing or cryptography. Once committed, preparation spends the request
even if later verification is invalid or unavailable; retry needs a new request.
It cannot be reused for cancellation, a second preparation or account management.

## Operator-pinned IdP certificates

The separate opt-in core/PostgreSQL `saml-certificates` feature adds trusted
certificate configuration; it implies `saml-requests`. Metadata/request-only
builds still have no certificate/cryptographic provider dependency. Certificate
parsing uses established OpenSSL 0.10.81 bindings, already present in the workspace
OIDC graph. This adds an explicit optional edge, no new package versions, XML
cryptography or trust fallback. Native OpenSSL deployment/patching still applies.

`SamlPinnedCertificate::from_der` accepts a single canonical DER RSA certificate
(up to 16 KiB, at least 2048-bit public key) and an explicit half-open approval
window in Unix seconds. OpenSSL parses the X.509 structure and compares the
window with NotBefore/NotAfter. Approval must fit within certificate validity.
`SamlCertificateTrust::pinned_leaf` requires one or two distinct certificates,
allowing one explicitly approved rotation overlap. SHA-256 fingerprints cover
exact certificate DER. No private key is loaded or created.

This trust model is exact operator-approved leaf pinning, including self-signed
IdP signing certificates. It is not PKI chain, hostname, revocation, OCSP or EKU
validation. System roots, fetched metadata, certificate issuer names and callback
KeyInfo cannot add trust. `active_at` must use trusted operation/database time,
with no implicit clock skew; an empty active set fails closed. It is configuration,
not evidence that an Assertion was signed or a provider is approved.

`Postgres::configure_saml_pinned_registration` atomically replaces registration
and certificate pins, allocates a fresh revision and cancels pending requests.
It retains an existing disable. `saml_certificate_trust` reads only under exact
current enabled realm/connection/client/revision and revalidates stored DER,
windows and fingerprints. Missing configuration is unauthorized; malformed stored
material is unavailable. It releases database locks before X.509 parsing. A
returned snapshot is not continuing authority: future sign-in completion must
recheck the current revision and original deadline in its final transaction.

Every revision change, including requests-only replacement and disable, deletes
old pins in the same database transaction through migration 0022. Failed pin
replacement rolls back registration, pins and request cancellation together.
The real PostgreSQL tests cover rotation, rollback, corrupt storage, identical
connection/client IDs across realms and disable. Core tests reuse unchanged public
upstream certificates with explicit historical windows and reject their expiry at
current time; no key/signature fixture is generated.

## Gated concrete verification component

The explicit core/PostgreSQL `saml-verification` feature builds the qualified
source with **only `crypto-aws-lc`**. Defaults, server routes and provider activation
remain unchanged. `SamlResponseVerifier` consumes a `SamlPreparedResponse` and a
bounded, redacted `SamlPostResponse` (one base64 POST field, at most 256 KiB). It
loads current enabled registration pins and fresh database time, releases storage
locks, then calls the established typed `finish_sso` message API. There is no
boolean-verifier trait, alternate engine, XML reparse/serialization bridge or
public constructor for `VerifiedSamlAssertion`.

The fixed profile requires both the Response and direct consumed Assertion
signatures, exact RSA-SHA256/SHA-256 and exclusive C14N under the existing qualified
profile. Only active operator-approved pins establish trust. At most two pins are
tried sequentially; both signatures must use the same approved certificate for a
single message. Mixed-certificate messages, encryption, unsolicited SSO, artifact,
SimpleSign and logout are unsupported. Locally generated IdP metadata imports only
our trusted registration and one approved certificate; its unsigned metadata import
policy does not permit inbound unsigned responses or remote metadata trust.

The library validates signed issuer, audience, destination, recipient, conditions,
bearer data and signed `InResponseTo` against the consumed trusted request/ACS.
The adapter checks its returned authenticated coverage and typed facts and admits
one Assertion, one bearer confirmation and one authentication statement. Persistent
NameID is mandatory, exact/nonempty/control-free and at most 256 Unicode characters (and 1024 UTF-8 bytes); optional
NameQualifier/SPNameQualifier must equal the configured IdP/SP respectively, and
SPProvidedID is unsupported. Missing qualifiers use those trusted namespaces;
no email matching, normalization, attributes or account linking selects an owner.

Clock skew is explicitly zero. Response and Assertion IssueInstant must be at
most 300 seconds old and not in the future; assertion/bearer/replay deadlines must be
future and no later than Assertion IssueInstant plus 300 seconds. Actual signed
AuthnInstant is required, not future and less than 24 hours old. These are this
initial application's bounded profile policies, not a claim that SAML mandates
these durations. Original DB request cap, signed deadlines, authentication age and
selected pin's approval end all bound the returned proof. There is no fresh-login
or authentication-strength claim from IssueInstant or an unspecified authn context.

Two workers per verifier bound blocking verification. Admission fails when full;
storage and worker waits each time out after 15 seconds. A timed-out/cancelled worker
retains its permit until native work exits; timeout does not claim to abort crypto.
No database lock spans XML/crypto. Library/internal errors are not logged or exposed
and map to finite application errors.

**Verified does not mean admitted or signed in.** The library's required replay
callback collects exactly two authenticated hashed ID reservations with retention
caps and rejects duplicates within that batch. This staging is not a durable replay
cache. `VerifiedSamlAssertion` is opaque, noncloneable and redacted, and contains no
raw XML. It creates no user/session and cannot clear the release gate. Final sign-in
must consume it in the same atomic transaction as durable response/Assertion replay
uniqueness, exact current source/policy, identity ownership/JIT, session and audit
writes, with a final DB-clock check. Replay namespaces must survive revision changes.

## Remaining implementation and approval

The separate identity component supplies durable replay rejection, identity
resolution/JIT provisioning and source-bound session commit. Complete lifecycle
remains open; a separate gated Axum component supplies HTTP/browser delivery below. Pending
AuthnRequest uniqueness and staged replay hashes do not replace that ledger.
These integrations remain under AUTH-32/34/35 and must retain realm/owner isolation,
one-use original caps and all existing account-policy invariants.

Dependency adoption and XML/signature/backend review must identify the actual
source, policy patches, compiled features and notices. Actual IdP/browser/database
interoperability and a separate independent reviewer/scope/findings/approval record
are mandatory. No matching-email linking, unsigned response, inline-key trust,
legacy algorithm, parser fallback or unsupported protocol path may clear a gate.

Ordinary local checks for this component:

```sh
cargo test --locked -p easy-auth-core --features saml-requests saml::
cargo test --locked -p easy-auth-postgres --features saml-requests --test lifecycle saml::
cargo test --locked -p easy-auth-core --features saml-certificates saml::
cargo test --locked -p easy-auth-postgres --features saml-certificates --test lifecycle saml::
cargo test --locked -p easy-auth-core --features saml-verification saml::
cargo test --locked -p easy-auth-postgres --features saml-verification --test lifecycle saml::
```

The second command requires the documented real development PostgreSQL database.
These component scenarios establish request-state behavior, not SAML production
approval or interoperability with a real IdP.

The concrete adapter's ordinary PostgreSQL round trip uses saml-rs's IdP API and
an unchanged public upstream Shibboleth fixture key/certificate. The same key is
encoded as PKCS#8 by OpenSSL for the AWS-LC signer; no key is generated. This proves
local component integration, not interoperability with a running Shibboleth IdP.
Ordinary controls include invalid subject/validity, signed request correlation,
wrong trusted certificate/explicit overlap, stale configuration and storage failure.
No new adversarial XML, bypass experiment or custom signature-concurrency probe is
part of this work. Broader documented condition and actual IdP/browser scenarios
remain acceptance work alongside independent security review.


Additional ordinary checks cover library-generated nonpersistent NameID formats
and a different IdP entity using the same configured signing key; both must fail,
and persistent/correct-issuer controls must succeed. Typed Rust policy tests cover
exact qualifiers, aliases, unchanged subject values and UTF-8 byte limits. They do
not establish qualifier extraction over the wire: the pinned upstream typed IdP
producer forwards NameID value/format but does not render supplied qualifier
attributes. Qualifier interoperability therefore remains open for actual IdP or
established-vector acceptance. No custom XML/signer is introduced to fill that gap.


## Gated identity policy and mapping

The optional core/PostgreSQL `saml-identities` component depends on concrete
verification. `SamlIdentityPolicy::new(registration)` fixes the current persistent
NameID profile and defaults to `SamlJitPolicy::Deny`; explicit `with_jit(Allow)` is
trusted administrative input only. `map` consumes an actual verified assertion
with exact full registration equality and returns an opaque `SamlMappedIdentity`.
It grants no local authority and does not commit replay reservations.

The verified subject supplies optional initial presentation only, using the same
nonblank/control-free/256-byte rule as existing OIDC mapping. Oversized presentation
is absent, without changing the exact subject or proof. Final ownership keys must
include realm/connection/client, both configured IdP/SP entities and persistent
subject. No email/attribute/presentation matching may select an owner or contact.

`Postgres::configure_saml_identity_policy` requires explicit pins, rotates revision
and replaces registration/pins/policy/cancelled pending state in one transaction.
It retains operator disable. `saml_identity_policy` reads only the exact current
enabled definition. Any revision change, including disable or pin-only replacement,
invalidates the previous policy atomically. Migration 0023 preserves all original
registration, pin and pending-request values and grants no default mapping authority.

Mapping and configuration alone grant no authority. `SamlSignIn` now consumes
the mapped proof in the final PostgreSQL replay/identity/session/audit transaction;
see [ADR 0023](../architecture/adr/0023-saml-identity-session-commit.md). Attribute-selected mapping remains
unsupported because the pinned typed extraction does not preserve NameFormat.
Actual qualifier/attribute/IdP/browser acceptance and independent approval remain
open. [ADR 0022](../architecture/adr/0022-saml-identity-policy.md) records the boundary.

```sh
cargo test --locked -p easy-auth-core --features saml-identities saml::
cargo test --locked -p easy-auth-postgres --features saml-identities --test lifecycle saml::
```


Persistent NameID also obeys the 256-character protocol bound in
[OASIS Approved Errata 05 E78](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).
The earlier byte-only admission allowed 257 ASCII characters; a focused Rust
regression reproduced that ordinary validation bug before correction. The byte cap
remains, with a separate character count. Ordinary signed IdP-API cases cover 256
ASCII characters, 257 rejection and 256 four-byte Unicode characters. Optional
display metadata still has its separate 256-byte bound; a valid multibyte persistent
subject can exceed that presentation limit without losing its exact identity value.


The verified proof also carries a distinct `session_expires_at_us` upper bound
for local-session creation: the earlier of signed AuthnInstant plus the
fixed 24-hour application limit and signed SessionNotOnOrAfter when present.
This follows the session guidance in
[OASIS Approved Errata 05 E26/E79](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).
It does not reuse the short request/Assertion admission deadline as cookie lifetime
or itself create a local session. The final identity transaction enforces both
distinct caps and retains any shorter database-default session lifetime.
Typed timing tests cover the optional statement cap and real signed/mapped controls
retain the resulting bound. The pinned ordinary IdP producer does not emit the
optional statement expiry, so that wire case remains actual-IdP acceptance work.

## Gated browser engineering composition

The explicit Axum `saml-web` feature exposes `SamlWebServices`,
`experimental_saml_web_router` and `saml_web_openapi`. It does not add a normal
server flag or activate the default router. HTTPS, the configured realm and exact
`{origin}/saml/acs` are mandatory. Construct services from the trusted persisted
policy and existing request/verification/identity repositories; source snapshots
are composed consistently and rechecked by core/PostgreSQL.

POST `/v1/saml/sign-in/start` accepts closed empty JSON and sets host-only protected
pending cookies before returning the library authorization URL. The reference page
is `/saml/sign-in`; metadata is `/saml/metadata`. Cross-site POST `/saml/acs` accepts
only `SAMLResponse`/`RelayState` form fields and renders a non-authoritative handoff.
It grants nothing and does not consume the pending request. Its fixed script sends
a same-origin form POST to `/v1/saml/sign-in/finish`, where existing-session rejection,
private browser proofs, actual verification and atomic replay/identity/session
commit run. POST `/v1/saml/sign-in/cancel` is same-origin and proof-bound.

This preserves existing Secure/HttpOnly/SameSite=Lax policy. An absent session
cookie on the IdP's cross-site POST cannot establish that the browser is anonymous;
only same-origin finish makes that check. Returned assertions never enter URLs,
browser storage, tracing or audit. Completion/cancellation clear pending cookies;
logout/revocation clears them with the session. Original database caps still apply.
See [ADR 0024](../architecture/adr/0024-saml-web-delivery.md) and the
[owned browser suite](../../tests/browser/saml-web/README.md) for exact limits.

These are explicitly gated engineering routes. Normal SAML remains disabled until
mandatory source/patch/dependency, XML/backend, actual IdP/lifecycle and independent
approval requirements are met. Attribute selection and purpose-bound SAML account
deletion remain unsupported. Offline producer/browser evidence is not deployed-IdP
interoperability or an independent audit.

The [gated OpenAPI contract](../architecture/openapi-saml-web.json) is generated
with `cargo run --locked -p easy-auth-axum --features saml-web --example export_saml_web_openapi`.
Its live publication and normal-contract separation are checked by the isolated
HTTP contract suite. It does not change the ordinary API document.
