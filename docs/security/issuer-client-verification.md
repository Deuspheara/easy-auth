# Issuer client registration and credential verification

AUTH-37 crate increment, 2026-10-23. See
[ADR0034](../architecture/adr/0034-issuer-native-registration-and-authentication.md)
and the [component guide](../guides/issuer-clients.md).

## Implemented boundary

Explicit public native loopback registration extends the existing optional issuer
metadata component. Literal interface/path matching remains exact; only ports vary,
including the explicit default-port80 spelling. Web constructors keep their
original exact HTTPS rules. Each native realm/client has its own stored random
subject mapping. Metadata restoration after restart validates the persisted
profile, sector, canonical callbacks and revision without retaining raw secrets,
repairing data or clearing disable.

Typed public/Basic credential input is distinct from trusted registration data.
PostgreSQL locks and checks the full current enabled definition before comparing
credential verifiers. Wrong client, method, secret, realm, stale snapshot or disable
cannot create authority or select a public fallback. Presenting a canonical encoding
of the actual stored verifier also rejects; the valid original secret still passes.
Credential checks and metadata allocation issue no consent, code, token or session.

Migration0028 defaults all previous registrations to exact web policy. Its actual
0027-schema fixture preserves disabled trust/credentials/revision, subjects and
sessions through upgrade. Current locked checks include the profile. Native cases
exercise rollback, concurrent stable allocation, real account erasure with another
realm retained, and observed configuration-lock replacement/disable orderings.
No dependency, XML/signature implementation, signed fixture or HTTP route is added.

## Local verification

Rust1.95/macOS arm64 with the repository's real loopback PostgreSQL fixture:

- `cargo fmt --check` and strict locked default/all-feature workspace all-target
  Clippy (`-D warnings`) pass.
- `cargo test --locked --workspace`:115 passed,0 failed,0 ignored.
- `cargo test --locked --workspace --all-features`:816 passed,0 failed,0 ignored,
  including479 real PostgreSQL lifecycle cases. The final full run includes the
  explicit native port80 admission correction.
- Isolated `issuer-clients`:8 core and25 PostgreSQL cases pass, including legacy
  account/session migration preservation and all previous issuer assertions.
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features
  --no-deps` passes.
- Compiled advisory audit and all-feature cargo-deny advisories/licenses/sources/
  bans pass without a new ignore. The inactive SQLx/MySQL rsa0.9.10
  RUSTSEC-2023-0071 finding remains visible.
- Maintained SAML source inventory remains245files/11patches; all11 existing source/
  qualification-script checks pass. Private review/comparison/bounds files remain
  excluded from the change set and unexecuted.

Final secret/diff/document-link and hosted exact-commit evidence are recorded with
the delivery. Earlier runs before the final port80 correction retain their own
scope; the final full run and isolated checks qualify the final implementation.

## Maintainability and remaining acceptance

Core native admission, typed credentials and registration remain separate cohesive
modules. PostgreSQL configuration, read-only restoration, credential validation and
subject allocation own their respective database responsibilities. The reusable
credential validator always acquires its current-client lock itself, then retains
it in its caller's transaction. Tests separate native policy, credentials/loading,
observed orderings, erasure and migration preservation. All added source/test files
remain below300lines; longer ordered migration/lifecycle cases deliberately retain
the original snapshot, operation, negative outcome and positive control together.
No unrelated cleanup is deferred.

The actual authorization-code/consent flow, HTTP client-auth handling, signed token
audience, key rotation, other native profiles and independent interoperability
remain requirements of the continuing issuer work. Do not mark those requirements
passed based on registration or credential checks. SAML's maintainer waiver is
not an independent audit or outbound issuer approval. Production operations remain
maintainer-supervised; this increment enables no normal issuer endpoint.
