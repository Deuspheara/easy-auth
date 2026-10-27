# Incident recovery qualification — 2026-10-27

AUTH-49 test/documentation revision
`2b912b70f9d994a0a65f86d328377aa1892d071b` qualifies selected incident reductions
against genuine populated PostgreSQL authority and its earlier physical snapshot.
No production behavior, dependency, public API, published migration or cryptographic
implementation changed. The runtime remains the implementation qualified in the
[retention/recovery evidence](retention-verification-2026-10-27.md); those exact99f4dd8
operational results retain their original scope. No hosted result is claimed.

## Observed scenario and independent controls

The maintained normal mailbox account, RS256 key/issuance, native consent/family
and authenticated-consumer fixtures create actual local sessions, signed ID tokens,
opaque access/refresh credentials and an unredeemed code. A second realm has its
own usable original authority. No raw bearer/private key is printed or persisted.

After closing the fixture's source connections, PostgreSQL physically copies only
its SQLx-owned database into a new uniquely named owned database. Public CONNECT
is revoked; only fixture administration pools connect. No HTTP listener, SMTP or
provider worker runs against the copy. This is a database-snapshot regression,
not an encrypted-archive test or production cloning/promotion tool. The separate
actual encrypted-backup drill already covers archive integrity, full restoration,
never-served clones and runtime CONNECT refusal.

The scenario first verifies original source authority. Matching-client/credential
family revocation makes that family's access inactive and refresh invalid while
a separately issued family and the owner session remain valid. Trusted key disable
then makes that separate family's access inactive, the sole current key metadata
unavailable and stale private-key-backed code issuance unavailable. There is no
empty-JWKS or old-signer fallback. Genuine owner revoke-all then rejects the old
local session. Repeated reduction preserves the family's first revocation time;
a revoked session cannot authenticate another owner operation.

After these live reductions, the earlier snapshot still accepts the original local
session, original native access and pre-incident enabled key configuration. This
positive control demonstrates the danger of unreconciled restoration. Reapplying
the recorded reductions independently against the copy makes those same paths
reject again. The other realm's session, authenticated native access and published
key remain usable on both databases. Snapshot operations cannot select the live
store accidentally: that would fail the restored-authority positive controls.

An existing cached public JWK still verifies the old ID-token signature after local
key disable. The test deliberately preserves this limitation. Local reduction
cannot erase a self-contained token, cached key or downstream application session;
consumer expiry/incident policy remains necessary.

A second real PostgreSQL test deliberately panics inside its scenario, observes
the panic and verifies that its exact owned snapshot database was removed. Fixture
pools close every released connection; after shutdown, bounded observation requires
zero actual snapshot backends before an ordinary DROP. No forced termination or
unrelated database deletion is used. Earlier failed-debug fixtures were contained
in the exclusively owned disposable cluster and removed with that cluster.

## Exact committed validation

On clean2b912b7, completed at2026-10-26 23:40:01 UTC (2026-10-27 Europe/Paris):

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
```

All passed. Default suite:167 passes. All-feature suite:1193 reported passes,
including one isolated logging child (1192 primary). Both have zero failed/ignored
tests. Real PostgreSQL was supplied throughout. The all-feature PostgreSQL lifecycle
target passed676 cases, including both new incident cases. Existing actual key
rotation observed its full production propagation interval; no clock/deadline was
rewritten to accelerate it. Audit and all-feature cargo-deny advisories/bans/
licenses/sources passed. Inactive `rsa0.9.10`/`RUSTSEC-2023-0071` remains reported.

The new incident guide passed website format, seven unit tests, type/build checks
(zero diagnostics) and genuine Chromium navigation/search/theme/mobile/keyboard/
route checks on2b912b7:33 routes/548 anchors. Earlier fixed screenshot bytes were
restored after preserving the new owned captures. Redacted Gitleaks found no leaks
in the incident commit. Changed Markdown file targets resolved. Final evidence-only
updates retain these runtime/test results under their original exact source.

## Investigated failures

The previous goal-owned PostgreSQL container no longer existed. The initial test
failed `PoolTimedOut`, not skipped; a new random-loopback/no-bind/AutoRemove owned
PostgreSQL fixture was provisioned, leaving the preview and unrelated services alone.
Two initial new-test expectations assumed empty JWKS and invalid_grant for disabled
sole-key issuance. Reading the existing contract established exact Unavailable
results instead. Production contracts and preceding assertions were unchanged.

Initial snapshot cleanup failed SQLSTATE55006, then its bounded backend observation
timed out. Sanitized observation identified an idle final-query backend after
client pooled shutdown. Closing fixture connections after every release fixed the
lifetime; the zero-backend observation and exact DROP assertions remained. An
explicit failing-scenario control now proves cleanup before panic propagation.
The final focused run passed both cases, then both passed again in the complete
all-feature suite. No timing/security/assertion waiver was introduced.

## Acceptance limits and maintainability

The scenario lives in the existing native feature suite; its private snapshot
helper owns only physical-copy fixture lifetime and cleanup. Files stay below300
lines. The longer ordered scenario deliberately keeps source positives, reductions,
snapshot revival, independent family/key controls and unaffected-realm checks
visible in one place; this is a documented test-function size exception. No public
internals, generic production recovery framework or unrelated refactor was added.

The [incident guide](../guides/incident-recovery.md) distinguishes genuine owner
proof, matching client/credential possession and trusted configuration authority.
A separately protected complete incident inventory is still required. This selected
drill cannot infer deleted identities, consumed proofs, provider trust or queued
side effects missing from an old snapshot. Their reconciliation and promotion
remain explicit operator decisions; no automatic completeness claim follows.

AUTH-49 remains In Progress with its actual AUTH-48 dependency. AUTH-47/AUTH-48
prerequisites, deferred real provider/OS/production verification, SAML waiver limits
and the outbound OIDC release gate remain open. There is no independent security
approval, protocol compliance, release, PR, merge or deployment. All73 protected
original files, their exact change set/index and retained preview/accounts/passkeys
remain preserved.
