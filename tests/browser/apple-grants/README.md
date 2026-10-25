# Owned Apple grant lifecycle browser check

Never deploy these fixtures. Use only an owned disposable loopback PostgreSQL
instance through `DATABASE_URL`. The harness creates/removes one fresh database,
mail inbox, private TLS proxy and Chromium contexts. Keep retained accounts,
passkeys, databases and system/browser trust settings out of this run.

```sh
cargo build --offline --locked -p easy-auth-axum --no-default-features --example apple-grant-erasure-probe
cargo build --offline --locked -p easy-auth-axum --features social-linking-web,apple-grants-web --example apple-grants-browser
node tests/browser/apple-grants/run.cjs
```

Install Chromium using the existing `tests/browser/passkeys` Playwright setup.
Optional `EASY_AUTH_APPLE_GRANTS_TEST_REPORT` writes a new JSON evidence file with
`wx`; never point it at an existing artifact. Binary overrides are
`EASY_AUTH_APPLE_GRANTS_TEST_BINARY` and `EASY_AUTH_APPLE_GRANT_ERASURE_PROBE`.
Rebuild the erasure probe without features immediately before the selected fixture:
it refuses to operate when capture/linking is selected. The probe additionally
requires the exact random `easy_auth_oidc_` database prefix and loopback host.

Nine cases exercise actual native browser navigation, private/cross-site cookie
boundaries, normal mailbox owner proof, signed Apple nonce rejection, explicit
link/sign-in capture, retained-factor unlink, immediate local source-session
invalidation, configuration failure, actual database backoff, confirmed ciphertext
erasure and feature-disabled account-erasure preservation. The latter invokes
ordinary repository preparation/completion with the owned real mailbox session
and generated bound verifiers in a separately compiled binary; it is a persistence
probe, not browser/mail confirmation or a public deletion-authority shortcut.
The original owner's separate browser session remains valid throughout.

The unchanged maintained producer signs controlled public authorization inputs
and verifies the real protected ES256 client secret. No session or verified proof
is seeded. Revocation uses an offline port which validates the exact fixed Apple
endpoint, client, signature, token and type hint; production HTTPS transport has
separate real private-TLS tests. Fixture-only routes expose finite aggregate counts
and invoke that preconfigured worker. They accept no key, token upload, endpoint,
source selector or authentication proof. No remote Apple endpoint is contacted.

The runner asserts exact final database/provider/grant counts and normal cleanup,
including no emergency cleanup or raw fixture diagnostic. Only finite results,
source/binary hashes and environment versions enter evidence. It reports no raw
credential, cookie, callback, grant, ciphertext or provider error body. It does not
establish real Apple registration, OS delivery, provider interoperability,
independent review or production readiness. SAML waiver limits and outbound OIDC
release gates remain unchanged.
