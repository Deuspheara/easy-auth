# ADR 0034: Native issuer registration and current client credentials

Date: 2026-10-23. Status: accepted crate implementation; outbound protocol and
production/interoperability gates remain open.

## Registration decision

Extend the existing optional `issuer-clients` modules inside core/PostgreSQL.
Keep the public/confidential HTTPS web constructors and their exact matching
unchanged. Add the deliberate public-only `public_native_loopback` constructor
and a closed `IssuerRedirectProfile`. Inbound OAuth/OIDC connection policy and
ordinary server configuration do not inherit this exception.

The native profile accepts only canonical HTTP `127.0.0.1` and `[::1]`, a non-root
fixed path, no credentials/query/fragment, bounded ASCII input and nonzero ports.
The exact explicit default-port spelling `:80` is also admitted; URL serialization
otherwise removes that port. Alternate literal hosts, leading-zero ports and path
normalization are not accepted by that exception.
Normalize only the registration's port; require the same scheme, literal interface
and exact path on each actual return. Register both interfaces explicitly when
needed. Reject DNS `localhost`, other loopback addresses, alternate IP spellings,
wildcards and mixed web/native definitions. Duplicate paths on one interface with
different registration ports are duplicate definitions. Custom schemes and claimed
HTTPS application dispatch remain separate native profiles, not implied support.

[RFC8252 section7.3](https://www.rfc-editor.org/rfc/rfc8252.html#section-7.3)
requires an authorization server's loopback profile to admit request-specific
ports. This metadata admission proves no listener ownership or application identity.
The eventual code transaction must retain the exact actual redirect, including
its actual port, through authorization and redemption. It must require S256 for
public and confidential clients and actual authenticated-owner consent. No code,
token or native grant is created in this increment.

Native subject sectors use the explicit reserved identifier
`urn:easy-auth:native-client:{client UUID}`, scoped by the existing realm key.
Sharing `127.0.0.1` must never correlate separate native clients. A client's
interface/path/port changes retain its sector, while the existing revision change
invalidates stale configuration. Web clients retain their existing hostname sectors.
The historical sectors table column is named `host`; its value is a sector key,
and native entries deliberately contain the reserved URI rather than a hostname.
Subject values remain separately stored random UUIDs, never owner identifiers.

## Authentication boundary

`IssuerClientAuthentication` represents parsed public identification or Basic
secret input. It has no constructor accepting a stored verifier. The Basic
constructor hashes an existing canonical `Secret`; Debug is fully redacted.
Core rejects a different client identifier or registered method. No implicit
method selection, public fallback, body-secret method or native shared secret is
introduced. Native applications remain public; see
[RFC8252 section8.5](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.5).

PostgreSQL validates against the full exact enabled client under its existing
configuration lock, then compares the supplied credential verifier in that same
transaction. Missing/wrong credentials are Unauthorized; storage failures remain
Unavailable. The public result is a check at that instant, not an authenticated
client proof, consent, user session or token grant. A later code redemption must
compose the private credential comparison while holding its own current-client
lock through consumption and final deadline checks; a preceding standalone call
cannot replace that transaction.

`load_issuer_client` restores an enabled persisted definition after restart using
its stored verifier, without retaining/reconstructing the raw secret. Core exposes
explicit trusted metadata restoration (`confidential_from_verifier` and validated
persisted revision); neither is a request-authentication input. The loader revalidates
the closed profile, exact canonical stored redirects and sector, and performs no
provisioning, repair or implicit enable. Missing/disabled keys reject; corrupt or
unsupported definitions are Unavailable. Loading is a point-in-time read, so
operations still acquire their own exact current-client lock before authority.

## Storage and evidence

Add migration0028 with `web_exact` as the legacy default. Existing registration,
revision, disable, credentials, subjects and session rows remain unchanged. Closed
storage policy restricts native rows to public authentication and their own native
sector. Configuration replacement/current checks include the profile; published
migrations are immutable. No dependency, crypto implementation or HTTP route is added.

Core negatives cover literal address/path/method/client/bounds and canonical forms.
Real PostgreSQL covers legacy disabled web migration preservation, distinct native
client/realm subjects, stable allocation under concurrent transactions, actual owner
erasure, rollback, stale/profile/credential replacement, cross-realm credential
rejection, storage failures and observed configuration-lock waits. These are ordinary
domain/database tests, with no new XML/signature fixtures or signature-concurrency
experiment. Code/consent/token/audience and external native interoperability must
receive their own protocol evidence. SAML's ADR0032 waiver is not outbound issuer
approval; production operations remain maintainer-supervised.
