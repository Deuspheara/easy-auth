# ADR0026: Gated outbound client registration and sector subjects

Status: engineering implementation; M07 activation and prerequisites remain open.

[ADR0034](0034-issuer-native-registration-and-authentication.md) extends this
initial web-only component with explicit public native loopback registration and
current credential validation. Existing web rules and historical evidence below
remain unchanged; neither component establishes code/token interoperability.

Outbound issuer clients belong to `issuer/`, separate from inbound OAuth/OIDC
connections. The opt-in `issuer-clients` feature provides trusted administrative
registration and PostgreSQL metadata only. No dynamic registration, authorization,
token, consent, discovery, JWKS or issuer startup route is introduced. AUTH-32
remains a recorded release prerequisite; this slice does not approve it.

Start with HTTPS web redirects, one to eight distinct canonical exact URLs on one
DNS hostname. Fixed query strings are allowed and compared byte-for-byte; fragments,
credentials, wildcards, noncanonical spellings, IP literals and HTTP are rejected.
Native loopback/custom schemes and multi-host sectors require a later explicit
profile. [RFC9700 section2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1)
requires exact matching; no substring, prefix or URL-normalized callback match.

Public clients have no credential. Confidential clients declare client_secret_basic
with only the verifier of an existing canonical256-bit Secret retained. This
records authentication configuration, not a token-endpoint authenticator.
[RFC6749 sections2.2–2.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.2)
distinguish public identifiers from client authentication. The eventual code flow
must require S256 for both types and actual explicit consent; no consent bypass,
client_credentials grant or public-subject option is enabled here.

Use stored random UUID subjects per realm, canonical redirect hostname sector and
local owner. Clients on the same hostname share a sector; distinct hostnames and
realms do not. Port/path/query changes preserve the sector subject. This follows
[OIDC Core section8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
without a new hash/encryption scheme or remote sector-document fetching. Trusted
operators must establish hostname control. A realm is the future issuer namespace;
changing its issuer identity requires a separately reviewed migration. Local user
UUIDs, email and inbound provider subjects are never returned as outbound subjects.

Fresh configuration revisions and disable checks prevent a stale snapshot from
selecting metadata. Replacement retains disable; explicit enable requires the
latest full definition. Subject allocation locks current client configuration before
the owning user key, requires both realm-scoped rows, and inserts/selects the stable
subject transactionally. It grants no authentication, consent or tokens. Future
issuance must separately authorize the current session/owner, validate the complete
request, and retain source/revision/deadline checks through its commit.

An additive migration creates separate sectors, clients and subject mappings, with
closed credential/policy fields and composite realm foreign keys. Account erasure
cascades subject mappings through the existing user FK. Public APIs and published
migrations remain unchanged. Real PostgreSQL coverage must establish replacement,
disable/stale definitions, realm/sector ownership, concurrent stable allocation,
rollback and existing-account erasure. Ordinary registration negatives are not SAML
adversarial research. Full AUTH-37/client-auth and M07 interoperability stay open.
