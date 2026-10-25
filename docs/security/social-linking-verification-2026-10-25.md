# Explicit social identity linking: local engineering verification

Date:2026-10-25. This records owned local engineering evidence, not registered
provider interoperability, production qualification, independent review or release
approval. Real Google/Apple registration, native/OS journeys and production
verification remain deferred. Remote Apple grant custody/revocation is separate.
SAML waiver limits and the outbound OIDC release gate remain unchanged.

## Implemented boundary

Core/PostgreSQL `oidc-linking` implements explicit original-owner/session-bound
Google/Apple proof completion, subject uniqueness, retained-method unlink, removed-
source invalidation, scoped cooldown and atomic audit/verified-contact notice.
Migration0037 preserves historical rows and old-column data. Existing policy and
source checks remain authoritative; email/profile never selects another owner.
Passkey-required accounts gain no fallback. A freshly issued local cookie never
substitutes for signed provider authentication time.

Explicit Axum `social-linking-web` composes the existing exact registered provider
namespaces with separate link cookies, closed same-origin start/finish/cancel,
retained-method unlink and fixed account/return pages. Default builders expose no
link operation. Apple cross-site delivery remains cookie/storage/DB-free. Its
same-origin state-only hint selects presentation without consuming, exchanging
or mutating. Original private proof, signed result and final core/PG checks remain
mandatory. Link/unlink never issue or rotate a local session.

## Checks and results

Commands used the locked offline dependency graph and an owned PostgreSQL17.11
loopback container. Required database suites ran against actual disposable databases;
none were silently skipped. The retained local preview/accounts/passkeys were not
used. Standard cargo profile overrides disabled incremental/debug payloads while
retaining build-script debug level1 for the existing macOS SQLx alignment constraint.

| Check | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Same strict Clippy with `--all-features` | Passed, including final probe example |
| Strict isolated Axum `apple-web` and `google-web` builds | Passed |
| `cargo test --workspace` | 128 passed;0 failed/ignored |
| `cargo test --workspace --all-features` | 1103 reports passed (1102 primary plus intentional logging-child repeat);0 failed/ignored |
| Full all-feature HTTP / core / PostgreSQL | 211 /169 /628 passed |
| New real-PG linking / HTTP scenarios | 22 /13 passed |
| `cargo test --workspace --all-features --examples` | 35 passed with owned database/socket access |
| Existing genuine Apple / Google HTTPS Chromium suites | 11/11 and13/13 passed |
| Genuine combined social HTTPS Chromium suite | 13/13 passed |
| Existing SAML source / reference token checks | Passed |
| Compiled advisory and all-feature cargo-deny | Passed; no exemption added |
| Redacted changed-public-source secret scan | 64 files passed before this receipt was added; no leaks |
| Website formatting / source/link tests / Astro check / build | Passed;7 source tests,0 diagnostics,27 generated pages |
| Website Chromium interactions/search/mobile/routes/anchors | Passed;26 routes and441 anchors; ephemeral server closed |
| Dependency lock | Unchanged |

The lockfile's inactive optional RSA RUSTSEC-2023-0071 entry remains visible; it
is not globally ignored or part of the compiled graph. Existing license, source,
algorithm and trust policy remain unchanged. No new package/version is introduced.

Browser evidence used Node26.0.0, Playwright1.64.1 and Chromium156.0.8078.4. Ordinary
email delivery/confirmation established local sessions; maintained signed code/
JWKS producers established provider sessions. No fixture endpoint seeded a
verified identity/session. Tests checked deliberate confirmation for both providers,
Lax cookie absence on actual Apple cross-site POST, private return removal/location
scrubbing, no browser storage/raw rendering, wrong signed nonce, lost finish with no
retry, late hint/restoration, stale-tab cancellation, account switching, returning
linked-provider ownership, current-source unlink denial and removed-source session
invalidation. A separately built `google-web` adapter without linking accepted the
same real local session but rejected the same real linked mailbox-OIDC session;
the selected linking build still accepted that source as a positive control.

Final owned-browser aggregate:2 users,0 identities,3 historical sessions,7 audit
rows,0 pending operations;2 Google exchanges/signatures and2 Apple exchanges/
signatures. Processes stopped normally and random databases/private TLS files were
removed without emergency cleanup. Screenshot inspection caught and corrected a
missing-display-name label; rebuilt assets display the verified contact/name and
passed the journeys again. Screenshots and raw protocol/private IPC remain local.

## Investigations and limits

Initial compilation caught a non-Clone secret copy, an unnecessary return and an
unused fixture field; corrected without lint suppression. One HTTP run105pass/
1fail had an incorrect expected status: malformed Secret state uses the existing401
rejection, while unknown JSON remains400. The next107pass/1fail had a misspelled
observation table; corrected to `auth_security_notifications`, then108/108 passed.
The later logout proof-hygiene case also passed in the full211-case HTTP suite.
No production assertion, freshness cap, security policy or required check weakened.

The initial ten browser journeys passed but their aggregate observer expected an
incorrect request count. Observation now independently counts aborted requests and
asserts no retry. A label rerun initially used a stale embedded binary and failed;
rebuilding included the corrected asset, after which all journeys passed. An
additional example command omitted `DATABASE_URL` and loopback permission: seven
cases reported missing database environment and three reported socket permission
errors. The correctly configured complete rerun passed without source changes.
These failures are recorded rather than represented as successful validation.

Maintainability review covered file tree, domain ownership, visibility, duplicate
policy, names and tests. Provider route groups and unchanged producer imports were
extracted in separate commits. New production/test modules stay below300 lines.
Longer ordered constructors/browser scenarios deliberately retain setup, protocol
observations, negative/positive controls and cleanup together. No SQL/business
policy moved into HTTP, proof constructor/framework was introduced, published
migration changed or unrelated cleanup deferred.

The original checkout's73 unrelated private/research files retained identical
bytes, original tracked/untracked change set and empty index. All development and
validation used the isolated checkout and owned disposable fixtures. No real
provider was contacted, registration created, production data used, PR opened,
merge performed or deployment requested by this change. Acceptance/release gates
remain visible in the primary tracker. See the [integration guide](../guides/social-linking.md)
and [ADR0044](../architecture/adr/0044-explicit-social-identity-linking.md).
