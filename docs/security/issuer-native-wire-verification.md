# Native wire and owned client verification

Date: 2026-10-24. Scope: AUTH-40 native transport and bounded owned-client
acceptance on `feat/auth-40-native-token-families`. This increment does not complete
native resource-consumer introspection, AUTH-40, standalone interoperability or
production assurance. [ADR0038](../architecture/adr/0038-native-token-lifecycle.md)
and the [native guide](../guides/issuer-native.md) define the contract and limits.

## Implemented boundary

Explicit `issuer-native-web` composes existing online code, native code/refresh,
registered revocation, fixed native confirmation and discovery. One committed
source admission precedes registered-profile selection. Exactly one existing core
operation runs; failed branches never retry through another profile. Shared concrete
signing capacity, actual current credentials, genuine source/owner/session, exact
policy/code/consent/key and final transaction checks remain mandatory. Closed forms
and response schemas preserve five-field online output; native refresh produces no
new ID token or cookie. Only this composition advertises offline capabilities.

No new dependency, migration, crypto/XML producer or public proof constructor.
Published migrations0032–0035 and Cargo.lock are unchanged. Default standalone
outbound activation stays gated. Public native IDs/token possession cannot
authenticate introspection or become local sessions. Explicit authenticated,
audience-authorized consumption of native access remains required AUTH-40 work.

## Verification

Final source passes:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` and its
  `--all-features` variant.
- `cargo test --locked --workspace` with real PostgreSQL:115passed,0failed/ignored.
- `cargo test --locked --workspace --all-features` with real PostgreSQL:
  968top-level cases plus one isolated child-process invocation,969reported
  successful executions,0failed/ignored; includes576PostgreSQL and169HTTP cases.
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps`.
- Isolated native wire HTTP:8passed. Isolated existing/native feature lint and
  structural regression checks pass. Eight wire cases cover actual native/online
  issuance, rotation/replay, closed inputs/current credentials/no cookie fallback,
  committed unknown-client admission, post-disable cleanup, DB-only refresh/revoke
  race, audit rollback and exact live contracts/metadata/default separation.
- Genuine OIDC/SAML native delegation:2passed using unchanged normal producers.
  Original authentication and cookie-idle separation remain; incompatible account
  policy/current source disable denies grants and credential cleanup still works.
- Owned native browser/client:6passed, normal isolated database/private-TLS cleanup.
  Actual Chromium and real bound TCP loopback exercise explicit denial/approval,
  fixed preview recovery, independent state/nonce/PKCE and production ID verification,
  one-use rotation/replay/cleanup and browser/privacy separation. Existing owned
  signed issuer browser regression:3passed after native composition changes.
- `python3 scripts/audit.py`:compiled advisory PASS; existing inactive optional
  MySQL lockfile rsa0.9.10 RUSTSEC-2023-0071 remains disclosed. No ignore added.
- `cargo deny --all-features check`:advisories/bans/licenses/sources pass.
- `python3 scripts/check_saml_source.py`:245files/11patches pass; existing source/
  qualification Python suite:11passed. Source integrity is not independent approval.
- Scoped redacted Gitleaks passes on owned changes and structural commit paths;
  changed links/diff/tree/responsibility/visibility and size review pass.

The OIDC test initially requested an invalid email-free/mailbox account-policy
combination, correctly refused by the existing database constraint. The fixture now
uses valid incompatible `passkey_required` policy and retains the original denial
assertion. Earlier fixture/import/schema compilation corrections preceded final
checks. No production invariant, assertion, timeout or advisory policy was weakened.

## Maintainability and remaining scope

Separate structural commits5222731,b12e95a,73e719a,5ca1af4 share admitted operations,
genuine HTTP/session setup and owned example composition before behavior changes.
Their focused core/PG/HTTP/legacy-browser regressions passed. Named native wire
modules own services, strict input, finite responses, routing, metadata/UI selection,
revocation and contract. Core retains policy/selection and PostgreSQL retains all
transactions. New source/test modules stay below300lines. Longer ordered scenarios
retain setup, denial, valid controls and cleanup together as function-size review
exceptions. No generic framework or unrelated cleanup is deferred.

The native fixture retains credentials only in memory. Production clients require
protected per-user platform storage, serialized rotation and atomic replacement;
the guide specifies this requirement without claiming OS-vault acceptance. The
owned test establishes bounded IPv4 behavior, not external certification, Rust SDK
or standalone parity. Authenticated native consumer introspection remains open.

All73protected private review/research/comparison files remain byte-identical,
unexecuted and unpublished. No PR, contact, registry image publication, live service,
adversarial fixture, bypass/fuzz/stress or custom signature-concurrency experiment.
SAML activation follows ADR0032's maintainer waiver:independent review was waived,
not performed. Green engineering checks close no independent assurance finding.
