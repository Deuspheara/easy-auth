# Owned actual Keycloak SAML acceptance

This ordinary integration suite exercises real Keycloak 26.8.1, the gated Axum
SAML browser boundary, the unchanged concrete verifier and actual PostgreSQL
replay/identity/session commit. It does not edit XML, generate custom cryptographic
fixtures, use a signature bypass or provide a proof/identity/session setup endpoint.
Normal server SAML stays disabled.

```sh
cargo build --locked -p easy-auth-axum --features saml-web --example saml-keycloak-browser
DATABASE_URL=postgres://… EASY_AUTH_SAML_KEYCLOAK_REPORT=/absolute/new-report.json node tests/browser/saml-keycloak/run.cjs
```

Use the existing Docker, Node24, OpenSSL and pinned Playwright/Chromium setup under
`tests/browser/passkeys/`. Keycloak uses the existing image digest in
`../oidc/keycloak.cjs`; no new package/image version is selected. Its existing
bootstrap creates a disposable realm/user/OIDC fixture client; this suite adds its
separate SAML client through the same strictly realm-scoped admin connection. The
unused OIDC client is not an alternate authentication path. No OIDC negative or
proxy signature-mutation scenario is invoked.

The provider's normal SAML client settings require persistent NameID, both message
and Assertion signatures, RSA-SHA256, exclusive canonicalization, POST return and
180-second assertions. The application keeps unsigned Redirect AuthnRequest as
its explicit supported outgoing profile. Signing-key rollover uses Keycloak's
existing RSA key-provider administration; no signing key is exported and no XML
or signature byte is changed. Public certificates are approved explicitly inside
actual validity windows through the production pin and policy configuration APIs.

Ten ordered cases cover default-deny/no grant, genuine signed browser sign-in,
unapproved new signer rejection, approved overlap/new signer, still-enabled old
signer in overlap, new-pin-only ownership, existing subject under JIT deny, equal
provider subject and local IDs in two isolated realms, and disabling one realm
while the other stays usable. Every sign-in is sequential, in a fresh browser
context, through real Keycloak credentials and HTTP POST. No custom signature
concurrency experiment or resource probe runs.

Only private process pipes configure pins, JIT and the selected one of two fixed
realm routers. HTTP input cannot choose those values. The fixture uses production
configuration and routes; its SQL reads only aggregate facts. It never inserts a
user, identity, session or verified proof. Two users/two identities/six sessions/
six audit facts/twelve replay reservations and no pending request are observed.
The two identities have one exact provider subject and two owning realms.

The existing private HTTPS proxy forwards both application and actual IdP traffic.
Only the isolated Chromium context tolerates its temporary certificate, and its
network routes/DNS are constrained to the owned hosts. No system trust, production
TLS or cryptographic policy changes. Admin provisioning uses the owned loopback
backend; IdP browser messages travel over the actual private HTTPS path. Protocol
bodies, cookies, credentials and keys never enter logs/reports/screenshots/traces.

Cleanup verifies the exact owner-labelled container, fixture process, disposable
PostgreSQL database and private files. The shared database helper retains its
historical `easy_auth_oidc_` cleanup namespace only. Reports contain versions,
source/binary hashes, finite cases and aggregate facts. Actual interoperability is
limited to this configuration, image, browser and platform. Attribute projection,
explicit qualified-NameID profile cases, Entra/Okta, full purpose-bound lifecycle,
maintained distribution/XML/backend review and independent approval stay separate.

The tenth case observes the already verified opaque timing proof at the identity
repository port, delegates the original mapped proof and bearer verifier unchanged
to PostgreSQL, and records only scalar/hash facts after successful commit. Aggregate
reads prove actual signed authentication time is copied exactly, every stored
expiry honors the verified session upper bound, and that upper bound remains
distinct from short admission expiry. All six grants carry a signed statement cap
stricter than the fixed24-hour default, establishing the ordinary Keycloak
SessionNotOnOrAfter wire path without parsing or recording XML. This is observation,
not a replacement verifier or a grant bypass.


## Confirmed account deletion

Run the separate ordinary deletion cases with the same built fixture:

```sh
DATABASE_URL=postgres://… EASY_AUTH_SAML_KEYCLOAK_REPORT=/absolute/new-deletion-report.json node tests/browser/saml-keycloak/run.cjs --account-deletion
```

Eight cases cover genuine sign-in, an actual signed reauthentication return with
no authority before second confirmation, wrong confirmation without state change,
returned-operation cancellation, a real different provider subject rejected at
completion, exact-subject confirmed local erasure with replay retention, and remote
IdP account preservation, plus retained provider SSO/password challenge with newer
actual signed authentication time at successful deletion. The fixed reference client and same-origin operation
selector are exercised in Chromium. Only owned provider SSO cookies are cleared
for ordinary account selection; the retained-SSO scenario explicitly preserves
them. Application/session/proof cookies stay private.

The fixture explicitly selects the existing deletion services. It creates no local
authority outside normal sign-in and changes no production composition. The
observer reports erased sessions separately with null historical timing checks;
pre-erasure timing facts are retained in the report. Original ten-case assertions
are unchanged. Both suites run in CI and clean only their own resources.
Older authentication-time wire cases, qualified identities/attributes, other IdPs
and independent approval remain separate. No custom XML/cryptographic fixture or
adversarial probe is introduced.

The deletion timing observer consumes no XML and creates no authority. It forwards
the original verified deletion proof unchanged, and records only a scalar comparison
after successful real erasure. The initial grant must be unique for that realm/owner;
multiple grants produce an unavailable measurement rather than selecting a session
heuristically. The new case requires one actual initial grant and a strictly newer
signed deletion authentication time. Earlier seven-case reports retain their scope.
