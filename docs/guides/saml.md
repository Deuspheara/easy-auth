# Gated SAML integration

SAML is not enabled in normal embedded or standalone composition. There is no
ordinary ACS route or SAML local-session grant. [ADR 0021](../architecture/adr/0021-saml-verification-and-approval.md)
records the verifier recommendation and distinct approval requirements. An
internal assessment and green tests do not constitute independent approval.

## Outgoing requests and metadata

The opt-in core/PostgreSQL `saml-requests` feature implements outgoing registration,
metadata, request persistence and cancellation. It selects published saml-rs
**0.6.1**, defaults disabled, with **no cryptographic provider enabled**. The
published package source revision is `6b414db010235f6c2d1121944b42919a82325b06`,
checksum `4997d94a9df26e1e2768acc8fedc70afeb456d503f7af4cd85d8d8bd363ab984`.
This producer is distinct from the later source/patch pin assessed for signature
qualification. It is not an inbound verifier dependency approval.

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

## Remaining implementation and approval

The requests feature does **not** implement signing-certificate trust/rollover,
signature verification, verified Assertion extraction, issuer/audience/recipient/
destination/time/NameID validation, response correlation consumption, Assertion
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
```

The second command requires the documented real development PostgreSQL database.
These component scenarios establish request-state behavior, not SAML production
approval or interoperability with a real IdP.
