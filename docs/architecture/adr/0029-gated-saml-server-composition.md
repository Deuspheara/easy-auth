# ADR 0029: Prepare normal SAML composition behind a closed approval gate

Date: 2026-10-22. Status: accepted engineering composition; activation remains
blocked by the mandatory security gates in ADR 0021.

## Decision

Add the optional `saml-web` server feature and bounded, closed `AUTH_SAML_*`
configuration to the shared `configured_application` factory used by standalone
and embedded consumers. Compilation is not approval. No settings means disabled;
`AUTH_SAML_ENABLED=false` alone also means disabled. Partial, unknown, duplicate,
non-Unicode and oversized settings fail closed rather than silently disappear.
There is no environment approval flag or automatic development exception.

A complete requested configuration is validated using the existing core types and
an exact `{AUTH_PUBLIC_URL origin}/saml/acs`, requiring HTTPS. Its activation check
unconditionally returns an AUTH-32 approval-gate error before database loading,
SMTP construction, provider provisioning or listener creation. A second check at
the service-construction boundary prevents accidental direct internal use. The
compatibility `configured_auth` API also refuses requested SAML configuration.
A later explicit reviewed source change, tied to exact dependency/profile and
approval evidence, is required to open this gate. No override is supplied here.

Prepare the service construction and route selection now, keeping their code
compiled and component-tested. They compose existing request, verifier, sign-in
and confirmed-deletion services; no persistence or identity policy moves into HTTP.
When both providers are selected, one base router and one merged OpenAPI contract
serve OIDC and SAML. Existing public single-provider constructors retain their
behavior. SAML's bounded non-authoritative POST ACS remains the sole SAML cross-site
exception; authority-changing completion keeps the existing same-origin boundary.
Both providers retain their separate private proof-cookie cleanup.

## Trusted provisioning and restart

Startup does not provision SAML. A trusted administrator must first use the existing
`configure_saml_identity_policy` transaction with the full registration, approved
leaf certificates/windows and JIT policy. Such provisioning alone never mounts ACS
or grants an identity. Certificate rollover, policy changes and explicit enable
remain administrative operations; environment data cannot replace certificate trust.

`Postgres::load_saml_identity_policy` reads an existing key, restores its stored
revision into the expected full registration, checks its enabled exact definition
and JIT, loads and validates its configured pins and requires an active pin at a
fresh database time. It then rechecks the full policy after parsing releases locks.
It never creates missing policy, rotates revision, cancels pending work or clears
operator disable. An absent, generic registration-only, policy-mismatched, disabled,
foreign-realm or inactive-certificate configuration fails closed. Runtime use cases
retain their independent current-source and final-transaction checks; startup is
not a lasting authority snapshot. No SQL lock spans cryptographic verification.

`SamlRegistration::with_persisted_revision` is an additive validated data-restoration
API, not a proof constructor; every repository operation still requires the whole
current trusted definition. No migration, verifier change, new dependency, provider
metadata fetch or certificate discovery is introduced.

## Evidence and limits

Tests cover closed configuration, exact trusted endpoints, default-deny JIT,
read-only repeated/concurrent PostgreSQL loads, missing/mismatched/disabled policy,
tenant isolation, combined routes/contracts and preserved Origin/ACS boundaries.
Normal binary and embedded startup tests assert SAML routes are absent in disabled
modes, complete activation fails with its explicit gate reason and startup creates
no SAML registration, pins, policy, pending request, user, session or audit authority.
CI retains the existing upstream vectors, full real-PG and provider/browser suites.

These are ordinary engineering checks. They do not approve XML/signature/backend
security, native-resource assurance or independent review. Existing experimental
constructors remain explicit engineering APIs. Normal production SAML stays disabled.

Local verification on 2026-10-22 passes `cargo fmt --all -- --check`, strict
locked default/all-feature workspace all-target Clippy, warning-free all-feature
workspace rustdoc, and locked workspace tests: 115 default and 798 all-feature
result counts, including 466 real PostgreSQL lifecycle tests. The final combined
router/deletion-contract/logout-cleanup case passes separately. Sixteen ordinary
SAML startup cases and all thirteen existing OIDC startup cases pass, and their
owned databases are removed. Isolated `saml-web` server all-target compilation,
242-file/seven-patch source integrity, eleven source/runner checks and scoped
redacted secret scanning pass. Initial HTTP test failures were sixteen
`PoolTimedOut` errors while the local development PostgreSQL container was stopped;
after restarting it the full HTTP suite passes all131cases. A local Python
bytecode-cache permission error was resolved by using a writable temporary cache;
the source/runner checks were rerun successfully. These infrastructure failures
are not hidden skips, and none of this evidence closes the security approval gate.
