# Apple backend component verification — 2026-10-25

Implementation source: [9fdba16](https://github.com/Deuspheara/easy-auth/commit/9fdba16a7f60277e6509e7d91bbde608ecead0d6),
preceded by separate protected-signing and design commits. Subsequent receipt-only
changes do not modify executable source. This is automated local component
verification, not an Apple-provider, physical-device, independent audit or release
qualification. [ADR0043](../architecture/adr/0043-apple-code-flow.md) defines scope.

## Implemented boundary

Optional core/PostgreSQL `apple` generates fixed short-lived ES256 client secrets
from one protected P-256 key and verifies initiated web/native code results with
the existing RS256 worker. State, private browser proof, source, exact issuer/client/
return, nonce convention, purpose and original caps remain bound. Only the Apple
profile accepts exact text/boolean email verification flags; generic/Google retain
original signed-type rejection and S256 requirements. Initial names are bounded
unsigned presentation, separate from opaque verified identity. Email never links
accounts or establishes local contact/freshness.

No runtime PostgreSQL implementation, migration, lockfile version, ordinary HTTP
route, startup setting, OS callback adapter, grant vault or revocation integration
is added. Existing mapping/JIT/session commit remains authoritative. No ordinary
Apple activation is established.

## Validation

All commands ran in an isolated checkout with owned disposable PostgreSQL17.11;
no retained preview/account/passkey storage was used. Cargo used locked offline
resolution. macOS build overrides enabled build-dependency debug information while
leaving dev/test debug information and incremental builds disabled, matching the
previously verified native toolchain configuration.

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`: pass.
- Same strict Clippy command with `--all-features`: pass, including final review.
- `cargo test --offline --locked --workspace`:128 passed,0 failed/ignored.
- Same workspace command with `--all-features`:1051 reports, comprising1050 primary
  cases plus one intentional logging subprocess repeat;0 failed/ignored. Includes
  core169, HTTP181 and real PostgreSQL606. Final reviewed source was rerun after an
  internal unreachable credential branch became explicit `InvalidInput`.
- Isolated `cargo test --offline --locked -p easy-auth-core --features apple`:81
  passed; core Apple contributes19 scenarios. No Google/identity feature required.
- `cargo test --offline --locked -p easy-auth-postgres --features apple --test
  lifecycle oidc::apple`:10 passed. No Google/passkey feature required.
- Compiled dependency advisory gate and all-feature cargo-deny advisories/bans/
  licenses/sources: pass. Inactive optional SQLx/MySQL RSA RUSTSEC-2023-0071 remains
  visible, with no ignore or weakened reachability gate.
- SAML source integrity245 files/11 patches and maintained UI-token check: pass.
  No SAML source, waiver condition or outbound release gate changed.
- Redacted scoped gitleaks54 public changed files: pass;285 changed-document local
  link targets exist. Receipt additions receive a final separate scoped scan.
- Website unit7, formatter, Astro check0 errors/warnings/hints and static26-page
  build: pass. Existing genuine browser assertions cover25 routes/420 anchors,
  search, theme/copy/navigation and mobile layout. Only screenshot destinations
  were redirected to new owned temporary files; assertions were unchanged.

## New negative and transaction evidence

Maintained JOSE producers generate owned keys held fixed within each scenario.
Independent ES256 verification checks exact client-secret claims/window/replacement;
wrong format/curve/IDs/windows reject and signing admission is bounded. Real RS256
code results cover web and explicit native plain/SHA256-hex nonce conventions.
Foreign signature/algorithm, wrong issuer/audience/azp/nonce/subject/time/flag type,
duplicate signed flags, unexpected metadata/endpoints and non-sign-in purpose
reject. No success comes from a mocked verified-proof constructor.

Real PostgreSQL tests traverse admission, actual one-use consume, credential/code
request assertions, signed result, mapping and final transaction. They cover wrong
browser/private proof/state/route, replay, bound cancellation, JIT denial, returning
subjects, no matching-email merge, equal-subject realm isolation, single-winner
callbacks, serialized subject creation, final audit rollback and disable during
token POST. An independent observer sees the actual final audit lock wait while
the original cap is live, observes its expiry, then confirms rollback after release.
Its owned pending setup preserves the original five-minute interval; no server
policy or deadline is extended. Signed-response counters and valid controls keep
fixture/infrastructure failures distinct from authorization rejection.

## Failures, review and limits

Compilation caught an Option iterator, an unused fixture import and a test call to
the existing three-ID disable API; corrected before final checks. An optional
UI-token command initially used a nonexistent script name; the maintained Python
check passed. No assertion, admission limit, timeout, security policy or signature
verification was weakened to fix those failures. Current Apple metadata and claim
references were read from official primary sources; no provider data was invented.

Maintained modules are cohesive and under200 lines. The longer constructors and
ordered consume/cancel, signing and test sequences retain their security invariants
visibly; no public proof constructor, generic provider framework, duplicated SQL
policy or unrelated cleanup was introduced. The protected original checkout's73
unrelated paths/bytes and empty index were rechecked unchanged. Owned resources
are cleaned separately; retained services/accounts/passkeys remain intact.

The owner explicitly deferred real Apple registration. App/Services IDs, actual
HTTPS form-post/native OS delivery, initial/subsequent provider consent, provider
key rotation/revocation and manual signed negative controls are unverified.
Grant lifecycle remains separate work. Keep the ticket In Progress and ordinary
activation gated; do not report this as Apple interoperability or production
readiness. Push does not authorize a PR, merge or deployment; hosted outcomes are
recorded separately and are not inferred from local results.
