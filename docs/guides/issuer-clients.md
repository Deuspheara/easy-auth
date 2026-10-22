# Gated outbound issuer client metadata

The `issuer-clients` Cargo feature in core/PostgreSQL implements trusted outbound
client configuration and opaque sector-subject storage. It does not turn easy-auth
into an authorization server. There are no authorization, token, consent, discovery,
JWKS, dynamic registration or standalone activation routes. SAML and M07 release
prerequisites remain open. See [ADR0026](../architecture/adr/0026-outbound-client-registration.md).

## Trusted registration

An operator supplies a realm, a client UUID and one to eight canonical HTTPS
redirects on a single DNS hostname. Use `IssuerClientRegistration::public` for a
public web client, or `::confidential(..., &secret)` with an existing generated
`Secret` for a confidential web client. The latter declares client_secret_basic;
only its SHA-256 verifier is stored. Keep the raw secret private at provisioning;
it is not serializable or printed in registration Debug. The public UUID is not
an authentication credential. Token-endpoint parsing/authentication is future work.

`Postgres::configure_issuer_client(&input)` returns the actual freshly persisted
revision. Retain it instead of the original input. Redirect comparison through
`permits_redirect` is exact, including fixed query spelling, path, port and case.
Duplicate redirects, different hostnames, wildcard/userinfo/fragment/noncanonical
URLs, IP literals, native/custom schemes and HTTP are unsupported. There is no
wildcard or loopback-port exception in this initial web profile.

Replacement never implicitly re-enables a disabled client. The explicit
`disable_issuer_client(realm, client)` rotates its revision; old snapshots remain
invalid. After configuring the current definition, `enable_issuer_client(&current)`
checks the full current snapshot. `check_issuer_client` checks metadata only and
cannot authenticate a caller. These methods are trusted administrative APIs, never
browser-selected configuration. No public registration or enable endpoint exists.

## Opaque subject metadata

`Postgres::issuer_subject(&current, user_id)` allocates or reads a stable random UUID
for the existing realm owner and configured hostname sector. It returns neither
the local user UUID nor an inbound federation subject. Same-host clients share
that sector; different hosts and realms have distinct mappings. Paths, ports and
fixed query values do not change the hostname sector. Trusted operators must
establish hostname control. Multi-host sector documents are not fetched/supported.

Allocation requires the current enabled full definition and an existing owner
under client-before-owner locks; concurrent same-sector allocations converge on
one stored subject. Existing account erasure cascades only its subject mappings.
Re-creating a mailbox creates a new owner and a new subject. Disable or stale
configuration cannot select a mapping, even if it already exists.

**This is metadata, not consent or token authority.** Do not expose this method as
a user-selected account lookup. Future issuance must authenticate the real current
session, authorize the owner/client/request, enforce exact redirects and S256,
obtain actual explicit consent, and bind its final transaction to current
configuration and original deadlines. Fixed `explicit` consent and `pairwise`
subject policy columns prohibit a silent storage-level bypass; they do not record
that any user has consented. Public subjects and client_credentials are unavailable.

## Verification

```sh
cargo test --locked -p easy-auth-core --features issuer-clients issuer::
# With the normal local PostgreSQL DATABASE_URL configured privately:
cargo test --locked -p easy-auth-postgres --features issuer-clients --test lifecycle issuer::
```

Tests cover registration shape/exact matching, credential redaction and storage,
fresh revisions, preserved disable, secret rotation/stale snapshots, full-definition
comparison, closed storage policy, realm/sector/owner boundaries, concurrent stable
allocation, rollback, account erasure and an actual migration preserving account/
session rows. Observed database lock cases verify committed disable or owner removal
cannot be ignored by a waiting lookup. They perform no XML/signature experiments.
Full client-auth protocol negatives, native profiles, actual consent, token issuance,
key rotation, conformance and standalone interoperability remain future M07 work.
