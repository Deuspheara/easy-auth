# Owned executable / embedded issuer parity

Run from the repository root with local PostgreSQL/Mailpit and the existing
Playwright installation. See [the setup and limits](../../../docs/guides/issuer-standalone.md).
The runner uses the actual server binary and the shared configured embedded factory,
real SMTP, browser consent, separate Node and Rust clients, and disposable storage.
Only summary booleans escape private IPC. No token, email message, private key,
trace, browser profile or callback URL is saved. Cleanup removes only this run's
random database, recipient messages and private directory. Fixture services must
never be deployed or connected to production data.


The shared browser toolchain now pins the third-party `openid-client` 6.8.8 RP:
install it with `npm ci --ignore-scripts --prefix tests/browser/passkeys`.
`node --test tests/browser/issuer-standalone/standards/fetch.test.cjs` checks the
owned Fetch boundary before the full runner. Existing Node/Rust/native controls
remain. Each mode additionally requires third-party discovery/code+S256/nonce/
state and actual JWKS/JWS verification, wrong-state refusal before any token POST,
and successful verification on both sides of the ordinary rollover. The result
requires eighteen true facts per mode. No original assertion or wait is removed.

The RP explicitly selects public-client authentication and
`enableNonRepudiationChecks`; its default TLS-only code-flow behavior is not used
as signature evidence. `standards/fetch.cjs` preserves original response bytes and
restricts requests to the exact owned HTTPS origin and metadata/JWKS/token paths.
It pins only the fixture certificate/address, retains hostname validation, bounds
bodies/time and rejects ambient cookies, redirects and insecure requests. It adds
no production transport override, signing producer or custom verifier. Tokens and
callback values remain in private memory; reports contain booleans only.
