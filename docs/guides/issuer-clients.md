# Gated outbound issuer client metadata

The `issuer-clients` Cargo feature in core/PostgreSQL implements trusted outbound
client configuration, current credential validation and opaque sector-subject
storage. It does not turn easy-auth
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
URLs, IP literals, native/custom schemes and HTTP are unsupported by these web
constructors. There is no wildcard or loopback-port exception in the web profile.

Replacement never implicitly re-enables a disabled client. The explicit
`disable_issuer_client(realm, client)` rotates its revision; old snapshots remain
invalid. After configuring the current definition, `enable_issuer_client(&current)`
checks the full current snapshot. `check_issuer_client` checks metadata only and
cannot authenticate a caller. These methods are trusted administrative APIs, never
browser-selected configuration. No public registration or enable endpoint exists.

After restart, `load_issuer_client(realm, client)` restores the exact enabled stored
definition and revision without a raw confidential-client secret. It neither
reconfigures nor enables a client. Invalid stored profile/redirect/sector data fails
as Unavailable without repair. Missing/disabled keys reject. This is a snapshot,
so later operations must still check the entire current definition under locks.
The core verifier/revision restoration methods are trusted configuration APIs,
never a way to authenticate by presenting a stored verifier.

## Explicit public native loopback registration

`IssuerClientRegistration::public_native_loopback(realm, client, redirects)` selects
the separate native profile. Register one to eight canonical HTTP loopback callback
paths using literal `127.0.0.1` and/or `[::1]`; each interface must be explicit.
For example, `http://127.0.0.1/callback` admits the same literal interface/path on
an actual ephemeral port. The registration discards only the anchor port. Actual
returns must keep exact scheme, address and path, with no query, fragment or userinfo.
DNS localhost, other IPs, root paths, port0, mixed web/native URLs, duplicate anchors
that differ only by port and noncanonical spellings reject. Native clients have no
shared secret; no confidential-native fallback exists.

Do not reconfigure per operation to choose a port. `permits_redirect(actual)` checks
the stable profile, while the future authorization-code transaction must store the
exact actual URI and compare that entire URI during redemption. Metadata admission
does not own a socket or authenticate the installed app. Custom URI schemes and
claimed HTTPS dispatch are separate future profiles. See
[ADR0034](../architecture/adr/0034-issuer-native-registration-and-authentication.md).

## Current client credential validation

Construct `IssuerClientAuthentication::public(client)` for public identification,
or `::basic(client, &secret)` for an explicitly registered confidential Basic client.
The typed input keeps only a verifier and redacts Debug. It cannot be constructed
from a database verifier. `Postgres::validate_issuer_client_authentication` validates
client/method and secret against the exact current enabled persisted definition
under one transaction. Wrong method/client/secret and stale/disabled definitions
reject; storage failure is Unavailable, never public fallback.

Public identification authenticates no app or user. Successful credential validation
issues no code, session, consent or token, and cannot be cached as an authorization
proof. The actual code exchange must compose credential/current-policy checks in
its own transaction through consumption and final expiry. HTTP Basic decoding,
the token endpoint and signed cross-client token audience tests remain protocol work.

## Opaque subject metadata

`Postgres::issuer_subject(&current, user_id)` allocates or reads a stable random UUID
for the existing realm owner and configured hostname sector. It returns neither
the local user UUID nor an inbound federation subject. Same-host clients share
that sector; different hosts and realms have distinct mappings. Paths, ports and
fixed query values do not change the hostname sector. Native clients instead use
distinct realm/client sectors, so a shared loopback address never shares subjects
across apps; one native client's port/interface/path changes retain its sector.
Trusted operators must
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
The additive profile migration preserves disabled legacy web registrations,
credentials, revisions, subject mappings and sessions. Native cases cover stable
concurrent allocation, real erasure, per-client/realm separation and observed
credential replacement/operator-disable waits. Method/client/secret/realm failures
cannot create grants or select weaker methods. No dependency or HTTP route is added.
Full client-auth protocol negatives, other native profiles, actual consent, token issuance,
key rotation, conformance and standalone interoperability remain future M07 work.
Current source-specific local verification is recorded in the
[issuer client verification record](../security/issuer-client-verification.md).

## Optional consent/code crate

Enable `issuer-codes` in core/PostgreSQL for the separate explicit consent and
one-time code component. Construct a trusted `IssuerAuthority` from the operator's
realm and stable HTTPS issuer, then `IssuerAuthorization` with the repository.
Prepare with the actual fresh session/browser Secrets and a code/openid request,
nonempty state/nonce and S256. Approve or cancel using the exact returned preview
UUID plus the initiating session and private browser/handle. A public preview UUID
alone authorizes nothing. Approval returns the validated actual callback with
code/state/iss; cancellation returns only access_denied/state/iss.

Redemption requires typed registered public/Basic input, the canonical code Secret,
the complete actual redirect, a43–128character RFC7636 verifier and a trusted network
source for bounded abuse admission. Native port flexibility applies to admission;
redemption still compares the exact original actual port. The opaque result is for
a later signing layer, not a wire token. Do not serialize its internal local owner
or session as an outbound subject. No issuer HTTP router, token endpoint, normal
server activation or production approval accompanies this optional crate feature.
See [ADR0035](../architecture/adr/0035-issuer-consent-and-authorization-codes.md).

Verify in isolation against real PostgreSQL:

```sh
cargo test --locked -p easy-auth-core --features issuer-codes issuer::
DATABASE_URL=postgres://… \
  cargo test --locked -p easy-auth-postgres --features issuer-codes --test lifecycle issuer_codes
```
