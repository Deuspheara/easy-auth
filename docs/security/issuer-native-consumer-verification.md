# Native consumer verification

Date: 2026-10-24. Scope: AUTH-40 authenticated, explicitly audience-authorized
native access introspection. See [ADR0039](../architecture/adr/0039-native-introspection-consumers.md)
and the [native guide](../guides/issuer-native.md). This receipt is engineering
evidence, not independent audit, external certification or production approval.

## Delivered boundary

An exact persisted confidential-consumer/native-audience policy starts disabled.
Revision-aware provisioning/enable/disable/load preserve current full definitions
and explicit operator authority. New migration0036 enables no policy and preserves
all prior online/native credentials; published0032–0035 remain unchanged.

Core retains policy, admitted use case and sealed metadata; PostgreSQL owns sorted
client-pair locks, actual credential comparison, current permission/native policy,
retained key, original source/owner/session, family/generation/access/consumed grant
and final database clock. Inspection creates no local session or extended cookie/
authentication time. Earlier unexpired access generations may remain active until
their own expiry; family replay/revocation invalidates all generations. Infrastructure
faults remain errors even when another snapshot is unauthorized or disappears.

An explicit builder adds `/oidc/native/introspect` and its exact live contract;
without it the route/schema are absent. Current Basic authentication is mandatory
even for unknown tokens. Public native IDs/cookies/known tokens confer no consumer
authentication. Closed bounded status input, actual peer/source admission, sanitized
finite errors and no-store responses are shared. Native aud/client_id/scope metadata
creates no business permission. Existing online introspection remains separate.

## Local verification

Final frozen-source local gates pass:

- `cargo fmt --all -- --check`.
- Strict locked workspace/all-target Clippy, default and all features.
- `cargo test --locked --workspace` with real PostgreSQL:115passed,0failed/ignored.
- `cargo test --locked --workspace --all-features` with real PostgreSQL:
  988top-level cases plus one isolated child-process invocation,989reported
  successful executions,0failed/ignored; includes591PG and172HTTP cases.
- Warning-free all-feature Rustdoc (`RUSTDOCFLAGS='-D warnings' cargo doc --locked
  --workspace --all-features --no-deps`).
- Compiled advisory audit and all-feature dependency/license deny pass. Existing
  inactive optional MySQL lockfile rsa0.9.10 RUSTSEC-2023-0071 stays disclosed;
  no advisory ignore is added.
- SAML integrity245files/11patches and11existing source/qualification Python cases
  pass. Source integrity is not independent approval.
- Scoped redacted Gitleaks, relative links/diff/tree/visibility/size review pass;
  all73protected files remain byte-identical and excluded from publication.

Hosted exact-commit CI will be recorded separately after push; no hosted consumer
pass is claimed by these local results.

Focused evidence before final gates:2core policy/projection cases,12initial consumer
real-PG cases and3HTTP cases passed. Expanded native tests cover15consumer cases,
genuine OIDC/SAML provenance, current source/method disable, cookie/freshness
separation, exact audience/two-real-realm isolation, migration/restart preservation,
storage errors, actual database-only revoke/disable ordering and final expiry after
an observed family wait. Initial signatures complete before database races.

The first expanded run passed59native PG cases/failed1:new replacement-key activation
was correctly refused before its existing300second publication interval. The next
run passed59/failed1 because that real interval outlived the initiating session's
five-minute freshness. An intermediate all-feature run also reported590PG passed/1failed
with that pre-correction initiating-session failure; its172HTTP/136core cases passed.
The fixture now waits301real seconds, performs a genuine new
email sign-in and only then issues native access and selects the replacement. No
stored readiness/authentication timestamp, production gate, timeout or assertion is
weakened. The final rollover case checks retained old access followed by explicit
old-key disable. Source review also added an independent-storage-error negative and
an exact generation-history guard before final frozen-source verification.

Owned native browser6cases and existing signed issuer browser3cases passed after
consumer composition changes, with normal isolated DB/private-TLS cleanup. The
browser fixture keeps credentials in memory; protected production platform storage
and serialized atomic replacement remain documented client requirements. No OS-vault
acceptance is inferred.

## Maintainability and limits

Separate structural9d9c663 names family policy restoration inputs;20existing real-PG
family regressions and strict PG lint passed before consumer behavior. New core
consumer, PostgreSQL consumer/inspection and thin HTTP modules have cohesive
responsibilities and narrow visibility. Shared access validation/finite DTO/status
input avoid copied policy. All new modules stay below300lines; longer ordered
transactions/scenarios retain locks, actual credentials, original caps, waits, final
clock, error classes and valid controls as reviewed function-size exceptions.
The rollover case deliberately observes the real publication interval. No generic
framework, new dependency/crypto producer, public proof constructor or unrelated
cleanup is deferred.

SDK/standalone standards-client parity remains AUTH-41; operational production work
requires maintainer supervision. SAML ADR0032 waived independent review, not
performed it. Engineering checks close no independent assurance finding. All73
protected private review/research/comparison files remain unchanged, unexecuted and
unpublished. No PR, contact, registry image publication, live service, adversarial
fixture, bypass/fuzz/stress or custom signature-concurrency experiment.
