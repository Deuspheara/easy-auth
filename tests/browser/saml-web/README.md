# Owned SAML browser delivery

This ordinary engineering suite exercises the gated Axum SAML pages, cross-site
POST delivery, same-origin finish, actual concrete signature verification and the
real PostgreSQL final grant. It does not contact a deployed IdP or establish
independent security approval. Normal server composition stays disabled.

```sh
cargo build --locked -p easy-auth-axum --features saml-web --example saml-web-browser
DATABASE_URL=postgres://… EASY_AUTH_SAML_WEB_TEST_REPORT=/absolute/new-report.json node tests/browser/saml-web/run.cjs
```

Use the existing Playwright/Chromium installation under `tests/browser/passkeys/`.
The existing private HTTPS proxy and owned-database process harness are reused.
Only the browser context trusts the temporary certificate; no system trust or
production TLS settings change. The library IdP fixture uses unchanged upstream
public signing material. The IdP HTTPS navigation is fulfilled within this context
using a loopback call to that fixture's ordinary producer, then a real browser form
POST returns to the application. There is no proof/session/identity setup endpoint.

Assertions check actual complete request headers, not the reduced header list
that omits cookies. The ACS receives no pending Lax cookies; the fixed same-origin
finish receives the private proofs and commits a usable provider-only local user.
HttpOnly/session/proof cleanup, existing-session rejection and logout are checked.
Only aggregate database facts, versions, source/binary hashes and case names enter
the report. Never record headers, assertions, protocol URLs or key material.

The harness owns a disposable loopback PostgreSQL database and private temporary
TLS directory. Cleanup is verified, including database removal. The shared database
helper retains its historical `easy_auth_oidc_` namespace solely for its existing
strict cleanup validation; it does not turn this fixture into OIDC acceptance.
The first local runner attempt failed because Node did not inherit Chromium's DNS
mapping. Its diagnostic was redacted and its exact owned database identified by
its configured callback before emergency cleanup. The successful retry uses the
owned loopback fixture address, catches provider-delivery errors and cleans itself.

The recorded results are Chromium/macOS/offline-producer evidence only. Real IdP
rollover/qualifier/attribute acceptance, other supported browsers, complete
purpose-bound lifecycle and dependency/XML/backend/independent approvals remain
separate requirements. No adversarial XML or cryptographic bypass fixture is added.

The final existing-session-at-finish control restores the genuine cookie issued by
the first verified flow while a second operation is at the IdP. It checks the
resulting browser/session state without seeding database authority; it does not
claim simultaneous tab-login evidence. Rejection preserves the original bearer
and leaves the unconsumed pending database request to its original deadline. The
final aggregate therefore deliberately contains one pending request before the
entire owned database is removed.
