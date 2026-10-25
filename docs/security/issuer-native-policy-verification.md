# Native offline policy verification

AUTH-40 configuration increment, 2026-10-23. This supplies explicit trusted policy,
not offline consent, refresh credentials or completed native acceptance. See
[ADR0038](../architecture/adr/0038-native-token-lifecycle.md) and
[the guide](../guides/issuer-token-management.md).

## Implemented boundary

Core `issuer-native-refresh` adds the distinct public native refresh registration
and bounded `IssuerNativeRefreshPolicy`. Absolute lifetime is1second–7days; idle is
1second–24hours and no greater than absolute lifetime. The original source/session
absolute cap cannot be exceeded. Invalid/overflowing time calculations reject.
These are configuration facts, never a proof or a cookie/code lifetime extension.

Migration0033 preserves existing online rows and adds only configuration/profile
support. New policies are disabled. Replacement rotates revision and preserves
operator disable. Exact current full client and policy definitions are locked in
client-before-policy order. Client replacement invalidates earlier policy; stale
enable cannot restore it. Read-only loading neither repairs nor enables storage.
No consent, subject, session, credential or owner audit event is created.

Feature-disabled/older PostgreSQL loaders reject the distinct persisted profile.
Cargo feature unification is handled explicitly: core refresh support without
PostgreSQL refresh support still compiles, and unsupported PostgreSQL registration/
checking/loading cannot silently interpret the marker as ordinary online native.
The enum marker remains recognizable; construction and refresh policy require the
explicit core feature. No HTTP route, scope, grant type, discovery or startup change.

## Evidence

Rust1.95/macOS arm64, existing locked dependencies and disposable real PostgreSQL:

- Two isolated core cases pass: exact profile/realm/redirect and bounded limits;
  original absolute cap and checked timestamp arithmetic.
- Eight isolated PostgreSQL cases pass: default deny/permanent revision invalidation;
  exact full client/policy; disable preservation; failed-write rollback; realm/issuer/
  client isolation; storage/constraint refusal; observed client/policy lock waits;
  migration preservation of actual online consent, subjects, sessions and audit.
  An enabled offline policy cannot enter the existing online consent flow; a
  separate ordinary online native client retains its genuine fresh-session control.
- A feature-disabled profile case passes both without core refresh support and with
  only core refresh enabled. Mixed features compile and refuse unsupported storage.
- Final `cargo test --locked --workspace`:115passed,0failed,0ignored.
- Final `cargo test --locked --workspace --all-features`:912passed,0failed,0ignored,
  including538real PostgreSQL lifecycle and153HTTP cases, after the downgrade guard.
- Formatting, locked strict default/all-feature all-target Clippy, warning-free
  all-feature Rustdoc, compiled advisory audit and all-feature cargo-deny pass.
  The existing245file/11patch SAML inventory and11source/qualification tests pass.
  Scoped redacted Gitleaks, changed relative links, size and diff checks pass.
- Hosted results must be tied to the exact pushed commit and are recorded separately
  in the tracker. Earlier access receipts do not qualify this new source. No new
  native system-browser acceptance is claimed from existing HTTP/workspace tests.

Initial migration-test build used an incorrect relative include path; the next
run exposed nullable JSON aggregation for an empty historical table. Corrected
both test defects without changing production/security checks or weakening assertions.
Review also corrected additive Cargo feature handling before final verification.
The unpublished commit was amended after review added explicit online-flow
refusal for offline-capable registrations, including default SQL preparation/
decision/redemption and core grant validation. Configuration-aware older binaries
must not reinterpret a future offline consent through online-only code paths.

## Maintainability and remaining work

Core policy stays in `issuer/tokens/native/`; PostgreSQL configuration/current
policy locking stays in `issuer/native_refresh/`. Feature tests separate policy,
configuration, isolation/storage, ordering and upgrade. Every new source/test file
is below300lines. Ordered negative/positive and migration scenarios retain their
invariants as function-size exceptions. No new dependency, crypto, generic plugin
framework, public proof constructor, advisory ignore or unrelated cleanup.

AUTH-40 remains In Progress for actual owner-reviewed offline consent, bounded
original grant/family, atomic one-use refresh rotation, reuse-detected descendant
revocation, current source/owner/revoke-all lifecycle/audit, and actual owned native
system-browser/PKCE acceptance. Storage guidance records future client requirements,
not tested refresh integration. Broader interoperability and production gates remain.
ADR0032 waived SAML independent review; no audit was performed. Protected private
review/research/comparison work is unchanged and neither executed nor published.
