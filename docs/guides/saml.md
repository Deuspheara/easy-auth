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

## Remaining implementation and approval

The requests feature alone has no certificate trust. Neither optional component
implements signature verification, verified Assertion extraction, issuer/audience/recipient/
destination/time/NameID or signed InResponseTo validation, response/Assertion
replay protection, JIT/identity mapping or source-bound session/lifecycle commit.
Pending AuthnRequest uniqueness is not a substitute for the Assertion replay ledger.
Those integrations remain under AUTH-32/34/35 and must retain realm/owner isolation,
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
```

The second command requires the documented real development PostgreSQL database.
These component scenarios establish request-state behavior, not SAML production
approval or interoperability with a real IdP.
