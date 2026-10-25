# Owned Apple web acceptance

Build `apple-web-browser` with Axum's explicit `apple-web` feature, install the
existing `../passkeys` npm dependencies/Chromium and set `DATABASE_URL` to an owned
disposable loopback PostgreSQL. Run `node tests/browser/apple-web/run.cjs` from the
repository root. Do not point it at retained preview/account storage.

The fixture creates a random database and private temporary TLS key/certificate,
then removes them through bounded owned cleanup. It generates maintained JOSE keys
in memory, validates actual public Apple authorization inputs and the actual ES256
client credential, and returns normal RS256 code results. No fixture can create a
local verified proof, owner or session. A facts endpoint observes aggregate counts
only. The binary is a test example, never a deployment or production credential loader.

Chromium intercepts only Apple's authorization navigation; the fulfilled provider
page actually submits a cross-site HTML form to the application's HTTPS callback.
Every delivery checks method, Lax-cookie omission and lack of local authority.
Cases cover denial/unavailability, malformed delivery, unsigned profile/XSS,
restoration, interrupted-finish discard, signed nonce rejection, wrong-browser
proof, deliberate committed sign-in/replay and ambient-session protection. DOM,
browser storage, fixed diagnostics, script errors and CSP are observed. Private
payloads stay in transient fixture memory, never reports or categorical diagnostics.

The runner imports unchanged database/process/TLS helpers and the producer was
extracted unchanged before reuse. Node fixture HTTP uses only the owned loopback
proxy and exact virtual Host, because it does not inherit Chromium's resolver.
TLS trust exceptions belong only to this fixture; no system trust is changed.
Optional `EASY_AUTH_APPLE_WEB_TEST_REPORT` writes a new provenance report with
source/binary hashes and aggregate results. `EASY_AUTH_APPLE_WEB_TEST_BINARY` can
select an explicitly built fixture binary. Neither is a provider configuration.

These are offline producer and transport tests. They do not establish real Apple
registration, eligibility/consent, web/native interoperability, physical-device
delivery, key-console rotation or provider-grant lifecycle. AUTH-24 stays open for
unperformed provider acceptance. Ordinary activation, independent security review,
SAML waiver limits and the outbound OIDC release gate remain separate.
