# Signed issuer component verification

Optional component increment, 2026-10-23. See [ADR0037](../architecture/adr/0037-issuer-signing-and-final-issuance.md),
[the API contract](../architecture/api-contract.md#optional-signed-issuer-transport)
and [the guide](../guides/issuer-signing.md). Exact implementation commit and hosted
run are recorded in the tracker after push; earlier consent CI is separate evidence.

## Exercised behavior

Concrete pinned josekit/OpenSSL RS256 uses explicit bounded PKCS8 operator input,
redacted opaque keys and an allowlisted public JWK. Unix protected-file loading
checks the opened regular owner-only bounded file and atomic final-component
NOFOLLOW. Trusted parent directories/ownership remain operator responsibilities;
other platforms fail closed. Private keys have no SQL/public projection.

Migrations0030/0031 add realm/issuer public-key revisions, explicit selection/enable/
disable, overlap/retention/readiness and a separate hash-only access ledger. Fresh
reenable/reopening propagation applies even to an old active/bootstrap key. Only
the first namespace bootstrap has an immediate deadline. Uninterrupted live
reaffirmation preserves maturity. Metadata quota includes reenable/reopening.

Signing holds no SQL locks and returns nothing before the final exact client/key/
source/owner/session/code snapshot, PKCE/actual return and original time caps are
rechecked and atomic access/code/audit writes commit. Sequential replay, missing
selected private key, intervening policy change, final expiry/audit failure and
erasure cases retain negative assertions and healthy controls. Actual unaltered
tokens verify before/after explicit rollover using overlapping public keys.
Historical29->30 and30->31 upgrades preserve existing rows; the latter redeems a
previously approved code. Account erasure removes local ledger/code/subject rows
and preserves other realms/operator keys; no remote offline JWT erasure is claimed.

Seven isolated HTTP cases cover actual email/consent and public/Basic/native token
POSTs, unknown/duplicate/bounded media/query/form/header input, exact native port/
PKCE, no cookie fallback, mandatory real peer admission and ignored forwarding
headers. Metadata cannot select a foreign namespace and default routes stay absent.
OpenAPI reflects closed form/public-key shapes and exposes no private key type.

Two additional real-PG existing-RP cases use actual discovery, authorization,
callback, form token POST and JWKS through a test-only in-process wire adapter.
Public/Basic flows reach the concrete verifier. Individually wrong audience,
nonce and configured algorithm refuse unaltered ordinary production tokens.
This shares the existing josekit verifier; it is bounded internal integration,
not an independent implementation, live DNS/TLS or external RP certification.

Three owned private-TLS Chromium/separate Node client cases pass. Actual email
completion and explicit browser preview/approval return a bound code; no private
proof cookie is read/manufactured. The separate client retains PKCE/state/nonce,
sends no cookies/Origin, explicitly trusts only the fixture certificate and retains
hostname verification. Node crypto verifies the unchanged production signature
with the published public JWK and fixed claims. Wrong ordinary PKCE and sequential
code replay fail; issued access cannot authenticate a local session. Aggregate
facts are1user/1session/1subject/1consumed-code/1access-row/1redemption-audit. Existing
eight consent/recovery cases also pass. Both suites remove owned databases and TLS
files normally, without emergency cleanup or diagnostics. Only healthy application
forwarding is used; no proxy signature-mutation mode is selected.

## Final local checks

Rust1.95/macOS arm64, disposable real loopback PostgreSQL, pinned Playwright/Chromium
and Node24:

- `cargo fmt --all -- --check` passes.
- Strict locked workspace all-target Clippy passes with default and all features.
- `cargo test --locked --workspace`:115passed,0failed,0ignored.
- `cargo test --locked --workspace --all-features`:883passed,0failed,0ignored,
  including517real PostgreSQL lifecycle and149HTTP cases.
- Isolated signing PostgreSQL15cases, token HTTP7cases and protected-file2cases pass;
  the four core key/window/profile cases pass in the full and focused suites.
- Warning-free all-feature Rustdoc passes.
- Compiled advisory audit and all-feature cargo-deny advisories/licenses/sources/
  bans pass. The existing inactive SQLx/MySQL rsa0.9.10 advisory remains visible;
  no advisory ignore is introduced. Cargo.lock changes only direct feature edges
  to existing zeroize/libc packages, with no package/version change.
- Pinned browser dependency `npm audit --audit-level=low`:0vulnerabilities.
- SAML source inventory remains245files/11patches;11existing source/qualification
  script checks pass. Integrity is not independent security approval.
- Scoped redacted Gitleaks, changed Markdown relative links and diff checks pass.
  Protected original files remain unchanged, unexecuted and unpublished.

Review corrected a fresh-publication readiness gap before commit and added a real
database regression. Initial RP fixture failures came from missing migrations,
non-admitted fixed-query callbacks and globally duplicate callback configuration;
setup was corrected without loosening production checks or assertions. Rustdoc's
generic type needed code formatting. The source scanner misclassified literal PEM
headers as an embedded key; naming the exact PRIVATE KEY label preserves the same
strict boundaries without adding a scan ignore. No published migration, existing
security assertion, advisory policy or timeout was weakened.

## Scope and maintainability

Separate structural commits extracted shared locked code checks and consent/
timeout composition before behavior changes. Core `issuer/signing`, PostgreSQL
registry/final issuance, Axum form/authentication/wire handlers and server protected
key input retain their existing crate responsibilities. New source/test modules
are below300lines. Longer issuance transactions and ordered scenarios deliberately
retain locks, original caps, writes, rollback and healthy controls visibly together.
No generic signer/framework, public proof constructor, speculative crate or
unrelated cleanup is added or deferred.

Normal standalone activation, refresh/revocation/userinfo APIs, native secure storage/
owned-listener acceptance, broader external interoperability and production approval
remain separate work. ID/access expiry conservatively retains the original code/
freshness/session/key caps, currently at most60seconds. Access grants no local
session or application business role. No independent audit, conformance certification
or production readiness is claimed. ADR0032 waived independent SAML review; it was
not performed and confers no outbound approval. No PR, contact, image publication,
live deployment, adversarial XML/cryptographic producer, bypass/fuzz/stress or custom
signature-concurrency experiment is part of this delivery.
