# Issuer consent/code verification

AUTH-38 optional core/PostgreSQL increment, 2026-10-23. See
[ADR0035](../architecture/adr/0035-issuer-consent-and-authorization-codes.md).
The later [HTTPS consent receipt](issuer-consent-verification.md) adds explicit
consent/recovery delivery; this earlier receipt retains its original component scope.
This is component evidence, not an HTTP/token endpoint, independent review,
conformance or production-approval report.

## Evidence boundaries

Core checks the closed initial code/openid/S256 profile, complete RFC7636 verifier
range and the same published S256 vector already used by inbound OAuth. Request,
authority, exact callback/query and response-issuer policies reject unsupported or
cross-client/realm metadata. Response construction retains actual callback spelling,
fixed query bytes and explicit native port80. No custom cryptographic fixture,
algorithm, signature producer or XML verifier is introduced.

Real PostgreSQL cases check no local authority before/after consent, explicit
one-use approve/cancel, private browser/handle/preview/owner/session/issuer/realm
separation, wrong code/client/method/secret/verifier/actual port, current disable/
revision, actual source-aware freshness and one concurrent grant. Approval/audit
faults roll back subject/code creation; redemption/audit faults restore the valid
unconsumed code. Independently observed client/owner waits recheck committed disable
or revocation. Independently observed final audit waits cross the original cap and
roll back every mutation, including correlation scrubbing. These are ordinary SQL
transaction tests, not signature-concurrency or stress experiments.

Ordinary existing signed OIDC and SAML producers traverse unchanged verification
and local identity/session commit before outbound consent. The result preserves
their actual authentication time; committed source disable rejects later consent/
redemption. No new signed/hostile fixture or proof constructor is added. Local
mailbox methods cannot authorize provider/passkey-required policy, and old or
unknown methods do not become fresh authority. Cross-owner audit attribution and
invalid durable code shapes are rejected by actual constraints. Confirmed erasure
deidentifies issuer attribution and cascades codes/subjects in only its own realm.

Migration0029 preserves existing account/session/client/subject/audit facts. Its
historical fixture writes original attribution columns, never today's writer
against an older schema. Existing audit kinds retain their original INSERT columns;
only new typed issuer kinds use issuer metadata. There is no schema detection,
retry or permissive runtime fallback. All published migrations remain unchanged.

## Verification receipt

Rust1.95/macOS arm64, with the repository's real loopback PostgreSQL service:

- `cargo fmt --all -- --check`; strict locked workspace all-target Clippy in
  default and all-feature modes: pass.
- `cargo test --locked --workspace`:115passed,0failed,0ignored.
- `cargo test --locked --workspace --all-features`:844passed,0failed,0ignored,
  including502real PostgreSQL lifecycle cases.
- Isolated `issuer-codes`:13core issuer tests and21real PostgreSQL code cases pass;
  two additional real OIDC/SAML source cases pass in the all-feature run.
- Warning-free all-feature/no-dependency Rustdoc; compiled advisory audit and
  all-feature cargo-deny advisories/licenses/sources/bans: pass. The inactive
  SQLx/MySQL rsa0.9.10 RUSTSEC-2023-0071 entry stays visible; no ignore added.
- Unchanged245file/11patch SAML source inventory and11existing source/qualification
  script checks: pass. Relative documentation links, diff whitespace and scoped
  redacted Gitleaks: pass. All73protected files remain byte-identical, unexecuted
  and unpublished.

The first broader DB run exposed older-schema fixtures calling the shared audit
writer before0029. Isolating the new typed issuer INSERT preserves the existing
columns/semantics and every original assertion, without schema probing or fallback.
A development test also tried to re-enable a stale pre-disable client revision;
its setup now uses the latest explicit trusted definition and retains the negative
control. Strict Clippy found one discarded must-use registration, now asserted.
No existing assertion, timeout, security policy or advisory gate was weakened.

The separate structural subject-allocation extraction is5f3870e; relevant issuer
Clippy/tests passed before behavior changes. Final feature commit and exact hosted
run are recorded in the tracker with delivery. Local checks do not establish
hosted success, HTTP acceptance, signing, independent review or conformance.

## Remaining acceptance

AUTH-38 still needs actual HTTP consent/token delivery and its closed transport/
Origin/private-cookie/preview/error contracts. AUTH-39 must implement real signed
issuance, exact audience/issuer/key policy and final lifetime semantics; a consumed
opaque component result is not a signed token. Refresh/native families, other native
profiles and actual interoperability remain open. Production operations retain
maintainer supervision. ADR0032 waived independent SAML review; no independent
review was performed or outbound issuer approval inherited from that waiver.
