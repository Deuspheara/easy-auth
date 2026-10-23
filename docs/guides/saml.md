# SAML integration

Normal standalone/embedded SAML is available as explicit opt-in under
[ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md). The maintainer waived the independent-review prerequisite;
no independent audit or security approval is claimed. Missing trusted settings,
active certificate pins or exact persisted policy still refuse startup.
Earlier component-stage descriptions below retain their historical assurance
scope; this decision supersedes their statements that normal activation is locked.

The finalized project profile and opt-in release are described in
[ADR0031](../architecture/adr/0031-saml-reference-release-profile.md) and the
[release guide](saml-release.md). Patch0011 requires both Response and Assertion
issuers to match the configured IdP. The current source inventory, rather than
the historical patch counts below, identifies the maintained delivery.

## Outgoing requests and metadata

In explicitly enabled normal standalone and embedded applications, `GET
/saml/metadata` publishes the exact configured SP entity and one HTTPS POST ACS at
`{AUTH_PUBLIC_URL}/saml/acs`. It declares unsigned Redirect requests, required signed
Assertions and persistent NameID, with no signing/encryption key or logout endpoint.
Metadata publication creates no request, user or session. Both modes use the same
trusted registration and return identical XML for that registration.

The normal-startup acceptance suite inspects that served XML and the actual
library-generated Redirect AuthnRequest. It verifies exact destination, issuer,
ACS, response binding and NameID policy, and matches request ID/RelayState to the
three distinct host-only Secure/HttpOnly/Lax proof cookies. Real PostgreSQL reads
check pending-only start, missing-proof cancellation refusal, successful bound
cancellation and spent cancellation refusal without changing trust or authority.
This is outgoing delivery acceptance; inbound XML/signature assurance and wider
provider interoperability retain their separate evidence and limits. See the
[AUTH-33 verification record](../security/saml-request-delivery-verification.md).

The opt-in core/PostgreSQL `saml-requests` feature implements outgoing registration,
metadata, request persistence, cancellation and response preparation. It selects
the [packaged qualification source](../../third-party/README.md) of saml-rs
**0.6.1** at `3b289001a7a84d5a7ff7af2671991ab7098090bd`, with the three retained
qualification patches plus ordinary producer/projection patches 0004–0007, defaults disabled and **no cryptographic provider enabled**.
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
resolution/JIT provisioning and source-bound session commit. The separate gated
Axum components below supply sign-in and purpose-bound confirmed deletion, with
bounded actual Keycloak/Chromium acceptance. Broader profiles and independent
approval remain open. Pending AuthnRequest uniqueness and staged replay hashes do not replace that ledger.
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
exact qualifiers, aliases, unchanged subject values and UTF-8 byte limits. Maintained
patch 0004 also preserves qualifiers through the built-in typed IdP producer and
existing signer. Library signed round trips preserve all three qualifier fields;
seven ordinary real-PG verifier scenarios accept absent/exact IdP/SP qualifiers
and reject mismatches or SPProvidedID through unchanged core policy. Successful
qualified subjects cannot use legacy custom rendering, which would omit fields.
This is local component evidence; broader actual IdP qualifier interoperability
and PAOS support are not established. No custom XML/signer is introduced.


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
unsupported by the current administrative policy; it no longer depends on a
lossy projection. `VerifiedSamlAssertion::attributes()` exposes complete ordered
scalar records with exact Name/optional NameFormat/value groups. Names and formats
are not normalized or merged; debug output is redacted and stored strings zeroize.
The verifier requires the maintained library's complete-record view, never its
legacy aggregate. XML-valued/nil attributes are outside this scalar profile and
reject verification, rather than returning partial facts. Empty attributes remain
a complete empty collection. Email/role/displayName data grants no owner, contact
or permission, and cannot override default-deny JIT or exact registration.
Broader actual IdP qualified NameID acceptance, additional profiles and independent
approval remain open. The owned Keycloak browser evidence below
covers only its documented persistent-subject profile. [ADR 0022](../architecture/adr/0022-saml-identity-policy.md) records the boundary.

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
optional statement expiry. The owned actual Keycloak acceptance below now covers
that wire case for its recorded profile; other provider profiles remain separate.

## Gated deletion-purpose backend

The opt-in `saml-identities` feature exposes `SamlDeletionRequests` with a
separate `SamlDeletionRequestRepository`. Construct it with the trusted exact
registration and PostgreSQL adapter; `start` requires the actual current SAML
session bearer. It generates a ForceAuthn request through the established library
and commits a distinct deletion purpose bound to that owner, session and identity.
This requests reauthentication; it does not prove recent authentication.

`prepare_response` and `cancel` require that same active initiating session plus
the original request ID, private browser proof and RelayState. Wrong purpose,
realm, source, revision, owner or session rejects without consuming another
operation. The noncloneable redacted `SamlPreparedDeletion` retains the original
earliest request/parent-session cap and cannot be passed to the sign-in verifier.
It is not a verified deletion proof or authority to erase anything. With the SAML backend compiled, logout and individual/all-session revocation
atomically remove the appropriate bound pending state. Backend-disabled builds
reject SAML authority; bounded pending state may remain until expiry or cleanup.

Migration 0025 preserves existing sign-in rows and adds closed composite bindings.
The existing sign-in repository contract remains unchanged. `SamlDeletionVerifier` consumes the
private preparation through the unchanged concrete verifier and exact mapping
policy, returning a noncloneable `SamlVerifiedDeletion`. It cannot become a sign-in
proof. `SamlAccountDeletion` requires this proof and delegates to the PostgreSQL
transaction: exact current source/policy, active initiating session/owner/identity,
exact signed subject, actual signed five-minute freshness, durable replay, atomic
erasure/audit/optional stored-contact notice/cooldown and final earliest-cap check.
The borrowed `validate_authentication_at` policy check uses trusted DB time and
grants nothing by itself. Migration0026 indexes realm/owner/session invalidation
without changing existing rows. The explicit HTTP/reference-client extension below
supplies confirmation. Eight owned Keycloak/Chromium deletion cases pass, including
a retained-SSO password challenge and newer signed AuthnInstant. A newly issued
response carrying ten-minute-old authentication is now tested with the normal
maintained IdP producer and real PostgreSQL: it passes signature verification but
cannot authorize erasure. A recent signed two-minute authentication succeeds.
A separate sign-in case preserves ten-minute-old authentication and its original
24-hour upper bound, and rejects authentication beyond 24 hours. This is local
component evidence; independent approval remains pending. No normal server flag or default deletion route
is activated. See [ADR 0025](../architecture/adr/0025-saml-account-deletion.md).

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
approval requirements are met. Attribute selection remains unsupported. The base
`saml-web` routes provide sign-in; purpose-bound deletion requires the separate
explicit HTTP extension below. Offline producer/browser evidence is not deployed-IdP
interoperability or an independent audit.

The [gated OpenAPI contract](../architecture/openapi-saml-web.json) is generated
with `cargo run --locked -p easy-auth-axum --features saml-web --example export_saml_web_openapi`.
Its live publication and normal-contract separation are checked by the isolated
HTTP contract suite. It does not change the ordinary API document.


The [provider acceptance guide](saml-providers.md) records ten owned actual
Keycloak 26.8.1 browser/rollover/realm cases, with source and cleanup evidence.
It also distinguishes documentation-only Entra/Okta integration from tested
support; Entra's documented lifetime minimum conflicts with the existing strict
five-minute signed-validity profile. No verifier restriction was relaxed.


## Explicit gated account-deletion HTTP extension

Construct `SamlAccountDeletionWebServices` with the identical persisted policy,
request/verification/final-deletion ports and select it with
`SamlWebServices::with_account_deletion`. The original constructor exposes no
account-deletion route. The selected extension adds:

- `POST /v1/saml/account-delete/start`: JSON `confirmation` must equal
  `delete my account`; requires the current SAML session and returns the provider
  URL only after its bound forced-reauthentication request is committed.
- `POST /v1/saml/account-delete/finish`: closed form `SAMLResponse`, `RelayState`
  and that same confirmation phrase; requires current session and separate private
  deletion proof cookies, actual verification and final atomic erasure.
- `POST /v1/saml/account-delete/cancel`: closed empty JSON; cancels only the bound
  operation and clears its local proofs, preserving the account/session.
- `GET /saml/account-delete`: fixed reference page with confirmation before IdP
  navigation. The returned ACS page requires a second explicit confirmation.

The shared ACS remains non-authoritative. Its same-origin script uses only a
cookie-bound, non-consuming `POST /v1/saml/operation` to choose fixed sign-in versus
deletion UI, then the selected completion enforces every original invariant.
Deletion never auto-submits, returns a session or falls back to another method.
Secure/HttpOnly/host-only/Lax cookies stay in force; no response or private proof is
put in URLs or browser storage. Stale deletion replies cannot clear newer cookies.
Lost/expired proof, expired original session, source change or provider unavailability
can prevent completion; no fresh request/token rewrites old authority or deadlines.

The [full gated contract](../architecture/openapi-saml-account-deletion.json)
separates these selected routes from the sign-in-only document and normal API.
Component tests use ordinary library-produced signatures and real PostgreSQL;
the separate owned Keycloak/Chromium suite covers eight actual provider deletion
cases, alongside ten rollover/realm cases. Its retained-SSO case requires a password
challenge and observes newer signed AuthnInstant after the existing erasure
transaction commits.
The [provider guide](saml-providers.md) and [ADR 0025](../architecture/adr/0025-saml-account-deletion.md)
record the source, results and limits. New ordinary producer/real-PG scenarios
cover old authentication in newly issued responses and exact scalar attribute
records under [ADR 0028](../architecture/adr/0028-saml-attribute-and-authentication-facts.md).
Broader actual IdP qualified/attribute profiles, additional IdPs and independent
approval remain unverified. Normal SAML remains
disabled.


The maintained typed IdP `RespondSso::attributes` option uses the existing writer
and signer for exact scalar records, and refuses mixing with lossy custom/template
attribute rendering. `authentication_instant` carries a caller-established UTC
event separately from issuance, requires built-in Web Browser SSO generation, and
rejects invalid/future dates. It authenticates no event itself. The unchanged
application verifier and database still enforce actual signed age and every cap.
See the [activation status](../security/saml-activation-status.md) for exact remaining gates.

Patch0007 wires NameFormat and consumed NameID qualifiers through the existing
unqualified-attribute validator before local-name DOM projection. This is a static
consumed-field completeness fix; no custom namespace/crypto probe or new verifier
was introduced, and independent namespace/binding review is still pending.

## Normal server configuration

The optional server `saml-web` feature compiles the normal configuration and route
composition. The standalone binary and embedded example both use
`configured_application`; `configured_auth` cannot silently drop SAML settings.
Unset all `AUTH_SAML_*` settings, or set only `AUTH_SAML_ENABLED=false`, to retain the
normal disabled server. SAML routes and schemas are absent in these modes, even
with `--all-features`. Mixing disabled with populated settings is a startup error.

For the prepared configuration contract, the complete set is:

| Setting | Meaning |
| --- | --- |
| `AUTH_SAML_ENABLED` | Exact `true` enables the configured provider after persisted policy/trust validation. |
| `AUTH_SAML_CONNECTION_ID` | Already provisioned non-nil connection UUID in `AUTH_REALM_ID`. |
| `AUTH_SAML_LOCAL_CLIENT_ID` | Already provisioned non-nil local client UUID. |
| `AUTH_SAML_SP_ENTITY` | Exact trusted SP entity identifier. |
| `AUTH_SAML_IDP_ENTITY` | Exact trusted IdP entity identifier. |
| `AUTH_SAML_SSO_URL` | Exact HTTPS Redirect endpoint without query or fragment. |
| `AUTH_SAML_JIT` | Optional `deny` (default) or explicit `allow`; must match stored policy. |

The ACS is derived from the validated HTTPS `AUTH_PUBLIC_URL` origin as `/saml/acs`;
no browser or environment callback override is accepted. Certificates are loaded
only from the exact operator-provisioned PostgreSQL registration revision, with
existing leaf-pin validity and activation windows. There is no environment
certificate, remote metadata import, system-root fallback or approval override.
Trusted administration uses the existing `configure_saml_identity_policy` operation
for full registration/pins/JIT and explicit enable/disable operations. Startup only
loads a matching enabled policy and active pins; it cannot provision, rotate or
re-enable it. Pending requests and stored revisions survive an unchanged restart.

With complete configuration and matching enabled persisted trust, the shared router
mounts sign-in, metadata, ACS and confirmed-deletion services. Optional OIDC shares
one base router/contract. See ADR0032 for the maintainer waiver and residual limits.

Run the ordinary startup checks with a freshly built default binary copied to
`EASY_AUTH_SAML_UNSUPPORTED_TEST_BINARY`, then build the normal binary and embedded
example plus `--example saml-startup-provision` with `--features saml-web,oidc-web` and run
`python3 scripts/smoke_saml_startup.py`. The documented PostgreSQL development
container or `EASY_AUTH_SMOKE_POSTGRES_CONTAINER` must be available. The runner owns
and removes its disposable database, verifies configured/disabled routes and trust
refusals in both modes, and exchanges no assertions. Its provisioning example
accepts only a loopback database with the owned startup-test name prefix; never
use its public fixture certificate as a deployed IdP.

### Verification admission scope

A `SamlResponseVerifier` admits at most two operations and retains its permit
until blocking verification actually exits, even after timeout/cancellation.
When `SamlWebServices::with_account_deletion` attaches the identical policy,
sign-in and deletion share those two permits while retaining separate repositories
and purpose-bound proofs. `SamlDeletionVerifier::share_verification_capacity`
provides that explicit same-registration composition for embedded consumers.
Separately constructed compositions/processes still have separate budgets. The
15-second await timeout is not a hard native execution or memory limit. Deployment
resource assurance and independent approval remain required; SAML stays disabled.

### Parser binding and process admission follow-up

The concrete adapter now sets decoded XML192KiB and depth128 limits, and shares
a two-task process gate across all verifier constructors in this linked core.
Separate services can await that gate up to15s; local/composed overload still
rejects immediately. Both permits remain with native work until actual exit.
Material lookup and native await have their own15s boundaries; no timeout kills
native execution. Other processes, retained waiting inputs and HTTP parsing still
need deployment budgets. This supersedes per-instance-only descriptions above.

Maintained patch0009 compares extraction with the verifier DOM before verification,
including original ranges/selected Assertion, normalized values and expanded names.
Namespace declarations are not attributes, literal text/CDATA follow XML1.0 EOL
normalization, strict XML1.1 input rejects, and backend DTD/entity rejection is
explicit. Cryptography/C14N and trust are unchanged. See ADR0030 and the
[assessment](../security/saml-parser-native-follow-up.md). Normal SAML remains
source-disabled pending the existing independent review/approval gates.
