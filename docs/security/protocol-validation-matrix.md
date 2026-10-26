# Protocol validation matrix — AUTH-47

Status: In Progress. This matrix separates implemented controls, current execution
and remaining acceptance. It is not protocol certification, independent security
approval or a production release decision. Real Google/Apple registration and
manual OS/provider verification remain deferred by the owner. The SAML activation
waiver retains its limits; outbound OIDC remains a hard release gate.

## Evidence rules

A test file or discovered name is not proof of execution. Use the compiler's test
list for the exact package/features/target, then require a successful actual run,
nonzero passing cases and zero failed/ignored cases. Preserve signatures, negative
assertions, original deadlines, concurrency and realm isolation. Do not reinterpret
unperformed manual checks as passed or silently count them as ignored tests.

Receipts must distinguish selected feature combinations, runtime source, fixture
source/binary hashes, controlled offline providers and actual interoperability.
An older successful receipt establishes only its recorded source/profile scope.
Sanitized output contains finite outcomes/counts; no token, cookie, authorization
header, code, assertion, key, provider credential or raw error body is evidence.
Tests use owned disposable databases/mail/TLS only, never retained preview data.

## Current isolated-feature execution

These commands were selected directly from the parsed CI workflow and executed
locally against the verified owned PostgreSQL container. Runtime source is the
validated AUTH-26 baseline `b4638a6706c81c1be2245108c190b48c31637895`; AUTH-47's
current change is CI/evidence wiring, not authentication behavior. Every row has
exit0, zero failed/ignored cases and a nonzero actual test summary. Counts overlap
between feature profiles and are not a count of distinct security requirements.

| Package / target | Features | Selector | Passed |
| --- | --- | --- | ---: |
| core / lib | google,apple,oidc-linking | `oidc::` | 98 |
| PostgreSQL / lifecycle | google,apple,oidc-linking | `oidc::linking::` | 22 |
| Axum / browser | social-linking-web | `social::` | 13 |
| core / lib | apple-grants | `oidc::` | 88 |
| PostgreSQL / lifecycle | apple-grants | `oidc::apple::` | 33 |
| Axum / browser | apple-grants-web | `apple_web::` | 22 |
| Axum / browser | apple-grants-web,social-linking-web | `social::` | 18 |
| server / lib | apple-grants | `oidc_http::` | 13 |

The two new browser CI steps were replayed verbatim with a fresh owned runner
folder. Thirteen social and nine captured-Apple-grant Chromium cases passed,
including separately built feature-disabled controls and normal database/TLS
cleanup. Reports record source/binary hashes; copies of disabled probes are made
before subsequent feature builds can overwrite the ordinary target path.
The workflow checks both reports against the checkout revision, expected case
counts, normal cleanup and the actual fixture/disabled-probe binary hashes before
retaining sanitized artifacts. The guard accepted the valid receipts and rejected
six missing, mismatched or emergency-cleanup variants in disposable copies. Strict default Clippy is added alongside the existing all-feature
check. Existing protocol/crypto assertions and checks are unchanged.

Cargo discovery and actual execution confirm the Apple storage cancellation test
is wired through the explicit `vault::worker_tests` path. The isolated apple-grants
run includes it; filesystem layout alone is not a coverage check.

## Refreshed owned-provider execution

The following unchanged CI profiles were built and executed from the same runtime
baseline with fresh, randomly owned Keycloak containers, private TLS and disposable
PostgreSQL databases. All returned exit0 and their exact expected case counts.
Each runner verified normal database/process/provider/private-file cleanup; no
emergency cleanup was counted as success. Sanitized private receipts retain source
and binary hashes. These are actual Keycloak interoperability observations for the
pinned image/profile, not registered Google/Apple or arbitrary-provider acceptance.

| Profile | Passed | Boundary |
| --- | ---: | --- |
| OIDC backend identity/JIT and lifecycle | 23 | Actual code exchange, rollover, subject/source policy and final atomic deletion |
| OIDC HTTP deletion | 6 | Actual provider reauthentication and public HTTP lifecycle boundary |
| OIDC public web | 18 | Standalone/embedded modes, original proof caps, restart persistence and normal client authentication |
| SAML sign-in/rollover | 10 | Actual signed Keycloak output, explicit pins/overlap, realm isolation and signed session cap |
| SAML confirmed deletion | 8 | Exact subject, second confirmation, cancellation/replay and retained-provider-SSO freshness |

Current issuer consent (8 cases), signed browser/separate Node HTTPS client
(3 cases), and native loopback/refresh (6 cases) also passed with normal owned
cleanup. Standalone/embedded Rust/Node parity also passed, with matching real SMTP,
independent client verification, native refresh, logout and before/after key
rollover behavior. Both modes preserved the full 300-second publication interval,
required real reauthentication afterward and completed normal database, recipient
mail and private-file teardown. No clock/readiness deadline was shortened.

## Refreshed passkey, SMTP and reference UI execution

The native signup/authentication browser suite passed all 31 cases. SMTP enrollment
passed four cases and saved-code recovery passed nine. Each used its own disposable
PostgreSQL database; the SMTP suites used a newly owned loopback-only Mailpit and
removed only their generated recipients/messages. The genuine reference UI and its
separate presentation-only inventory pagination test also passed. The UI used real
mailbox/password/passkey operations, required its normal fixture database teardown,
and kept CSP/browser-error/external-network checks. No retained preview, account,
passkey or mailbox was touched.

These remain Chromium virtual-authenticator observations, not Safari,
physical-device or native OS storage acceptance.

## Remaining browser and startup profiles refreshed

At source base `4975e06ab165e3c09f42b32d5ac0164699da1cc2`, the existing isolated
Google desktop loopback profile (1), Google HTTPS browser (13), Apple form-post
browser (11) and SAML cross-site delivery/finish (8 named checks) all passed. The
web profiles required normal owned database/TLS teardown; the desktop socket-only
profile creates no database identity/session and does not claim Google/OS launch.
Google/Apple browser fixtures use controlled provider ports and do not substitute
for registered-provider acceptance. All reports retain exact source/binary hashes.

The two existing startup CI steps were selected from parsed YAML and replayed
verbatim with the explicit owned PostgreSQL container and newly generated database
names. OIDC reported 13 passing cases; SAML reported 31 passing case records and
configured-startup success. Both removed their databases normally. The freshly
built no-provider binary was copied before enabled builds, retaining actual feature
refusal controls. Standalone/embedded configuration, disabled/no-feature/partial
refusal and trusted opt-in checks used no provider exchange, mail delivery or local
account/session creation. These are startup checks, not real public TLS deployment.

The separate sign-in and deletion reference-client browser checks also pass:
each rejects seven malformed callbacks, requires explicit completion, scrubs URLs,
refuses replay and browser storage, and distinguishes 503 from success. These use
fixed intercepted HTTP responses and establish no provider acceptance. Initial
sandboxed invocations failed; sign-in diagnosis located Chromium launch before
scenario execution. The unchanged commands passed with browser process permissions;
no assertion, fixture or application code was changed.

## Current workspace gates

On 2026-10-26 the exact unchanged runtime baseline passed `cargo fmt --all --
--check`, strict workspace/all-target Clippy with both default and all features,
and `cargo test --locked --workspace` plus its `--all-features` counterpart against
the owned PostgreSQL fixture. The default run passed 128 tests; all-feature output
contains 1151 passing results including one separately spawned logging-child result,
so 1150 primary tests. Both runs report zero failed and zero ignored cases. Source
integrity passes for 245 maintained files/11 patches; six source-check and five
qualification-helper tests pass. UI token integrity, Markdown target links, YAML
parsing, scoped secret scanning and patch whitespace also pass. Maintained
SAML/C14N qualification passed 1149 cases across 48 test groups with
zero failures/ignored cases and matching shipped dependency versions/features.
The existing advisory and all-feature license/dependency-policy checks also pass.
No advisory suppression or license-policy exception was added.

## Control and acceptance inventory

The workspace baseline has 128 default and 1150 primary all-feature passing tests
at runtime integration `d58b596eb8e3a1c157cfb934c106e07ca2db8d95`, followed only
by receipt/README changes in `b4638a6`. That baseline includes real PostgreSQL,
negative protocol cases, observed lock waits and tenant isolation. It does not
by itself refresh all browser/provider/source-qualification receipts below.

| Area / documented invariant | Existing feature-owned corpus and bounded evidence | AUTH-47 follow-up / remaining acceptance |
| --- | --- | --- |
| Mailbox/password/session proof: one use, browser binding, no enumeration or weaker-method upgrade, original idle/absolute/freshness caps | [HTTP cases](../../crates/auth-axum/tests/browser/), [PG identity](../../crates/auth-postgres/tests/lifecycle/identity/), [session concurrency/revocation](../../crates/auth-postgres/tests/lifecycle/sessions/), [audit ownership/rollback](../../crates/auth-postgres/tests/lifecycle/audit/), [reference browser](../../tests/browser/reference-ui/README.md) | Owned SMTP/reference replay above passes; the bounded control-to-assertion review is linked below; operator/load/incident work stays separately tracked. |
| Passkeys: exact RP/origin, signed context, UP/UV/signature, one-use/realm binding, lifecycle and recovery assurance | [core passkeys](../../crates/auth-core/src/passkeys/), [PG feature scenarios](../../crates/auth-postgres/tests/lifecycle/passkeys/), [browser](../../tests/browser/passkeys/README.md), [attachment](../../tests/browser/passkeys/attachment/README.md), [recovery](../../tests/browser/passkeys/recovery/README.md) | Owned Chromium/SMTP paths above pass; virtual-authenticator evidence does not establish all physical devices, Safari or OS recovery behavior. |
| OAuth/OIDC: transaction purpose/source/owner, PKCE, nonce, issuer/audience/algorithm/key/time, JIT and no email merge | [core verifier](../../crates/auth-core/src/oidc/verification/tests/), [PG OIDC](../../crates/auth-postgres/tests/lifecycle/oidc/), [actual owned Keycloak backend](../../tests/browser/oidc/README.md), [public web/native](../../tests/browser/oidc/web/README.md) | Isolated current runs above supplement the baseline; the three owned Keycloak profiles above now pass; keep profile/source limits explicit. |
| Google: fixed provider policy and signed claims, native/web return, purpose separation and genuine signed age where selected | [Google core](../../crates/auth-core/src/oidc/verification/tests/google/), [web](../../tests/browser/google-web/README.md), [desktop](../../tests/browser/google-desktop/README.md) | Owned fixtures are separate from registered Google/manual native eligibility and actual provider lifecycle; those checks remain unperformed here. |
| Apple: fixed registered-client profile, protected client secret, signed nonce/native convention and unsigned-profile separation | [Apple core](../../crates/auth-core/src/oidc/verification/tests/apple/), [native/signing](../../crates/auth-core/src/oidc/apple/tests/), [web](../../tests/browser/apple-web/README.md) | Current isolated core/PG/HTTP checks pass; real Services/App IDs, HTTPS registration, OS delivery, provider/key lifecycle remain deferred. |
| Explicit linking: original owner/session and proof, retained factor, last-source/concurrent unlink, no email-based ownership transfer | [PG linking](../../crates/auth-postgres/tests/lifecycle/oidc/linking/), [HTTP](../../crates/auth-axum/tests/browser/social/), [owned browser](../../tests/browser/social/README.md) | Current isolated profiles and13-case browser replay pass; actual registered-provider/OS acceptance remains separate. |
| Apple custody/revocation: authenticated storage binding, explicit keys/rotation, atomic detach, lease/version/final cap, finite retry and erasure | [core envelope/cancellation](../../crates/auth-core/src/oidc/apple/grants/), [PG jobs/upgrade/rotation](../../crates/auth-postgres/tests/lifecycle/oidc/apple/grants/), [owned nine-case browser](../../tests/browser/apple-grants/README.md), [receipt](apple-grant-revocation-verification-2026-10-25.md) | Current isolated profiles and browser replay pass. Explicit maintenance, retained keys and remote redemption/local commit crash gap remain obligations; no live Apple revoke is claimed. |
| SAML: pinned/verified signed content, strict parser/conditions/correlation/replay, rollover, realm/purpose/time and final transaction | [core](../../crates/auth-core/src/saml/), [PG](../../crates/auth-postgres/tests/lifecycle/saml/), [maintained source qualification](../../scripts/qualify_saml_c14n.py), [owned Keycloak](../../tests/browser/saml-keycloak/README.md), [review history](saml-evidence-review.md) | Actual owned rollover/deletion profiles and maintained source qualification above pass. Preserve [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md); broader IdP/profiles and independent approval are not established. |
| Outbound issuer/client: exact registration/redirect/PKCE, authenticated client, original consent/source bounds, replay/rotation, native audience and no cookie authority | [core issuer](../../crates/auth-core/src/issuer/), [PG](../../crates/auth-postgres/tests/lifecycle/issuer/), [native families](../../crates/auth-postgres/tests/lifecycle/issuer_native_refresh/), [standalone/client parity](../../tests/browser/issuer-standalone/README.md), [native browser](../../tests/browser/issuer-native/README.md) | Consent, signed Node client, native loopback and configured Rust/Node standalone/embedded parity above pass; internal/owned fixtures do not clear outbound release acceptance. |
| HTTP/egress/log boundary: exact Origin, closed media/body/query, private cookies, TLS/address pinning, no redirect/proxy/stale fallback, finite errors | [HTTP suite](../../crates/auth-axum/tests/browser/), [real private-TLS transport](../../apps/auth-server/src/oidc_http/tests/), [source/logging controls](../../crates/auth-core/src/) | Current Apple transport profile passes alongside workspace negatives. All fifteen table rows now have a bounded source/assertion map; external/operational acceptance remains separate. |

## Bounded source review: native refresh transaction

The [rotation transaction](../../crates/auth-postgres/src/issuer/native_refresh/family/rotation.rs)
validates the presented client before lookup, revalidates current authentication
inside the transaction, and locks current source policy, signing key, delegated
owner/session, family and refresh credential before creating a replacement.
Spent-token detection reduces family authority and commits that reduction; it
cannot return an active descendant. The
[write module](../../crates/auth-postgres/src/issuer/native_refresh/family/writing.rs)
scopes the spend by realm/issuer/client/family/hash and requires exactly one affected
row. Replacement hashes, generation, idle deadline, access credential and audit
share one transaction. After audit insertion, the final check compares the actual
database time against the **original** idle and absolute caps before commit.

The review traced those claims to concrete assertions rather than test names alone:
[rotation cases](../../crates/auth-postgres/tests/lifecycle/issuer_native_refresh/families/rotation.rs)
check hash-only storage, unchanged cookie/source times, permanent descendant
revocation, audit-fault rollback, and exactly one successful database-only concurrent
rotation followed by reuse revocation. The
[deadline case](../../crates/auth-postgres/tests/lifecycle/issuer_native_refresh/families/deadlines.rs)
observes a real audit lock wait before the original idle cap, releases it after the
cap, then requires InvalidGrant with the original generation/deadline and an
unspent original credential. The
[isolation cases](../../crates/auth-postgres/tests/lifecycle/issuer_native_refresh/families/isolation.rs)
use the same actual client ID in two realms and require each owner to retain its
own usable family after cross-realm refusal. These cases passed in the recorded
all-feature baseline; the fresh native browser replay separately checks the public
loopback/rotation/reuse path. This is a bounded internal review, not independent
security approval or a claim that the rest of the threat model is fully reviewed.

## Bounded source review: provider verification and explicit linking

The [token verifier](../../crates/auth-core/src/oidc/verification/flow.rs) checks the
exchange configuration/current repository authority before signature work and
checks it again afterward. Its maintained signature worker returns typed claims;
unknown-key retry remains inside the original bounded operation lease.
[Claim validation](../../crates/auth-core/src/oidc/verification/claims.rs) enforces
original proof expiry, finite token age/time order, expected audiences, issuer and
provider-specific nonce policy before constructing an opaque verified identity.

The [link commit](../../crates/auth-postgres/src/oauth/identities/linking/completion.rs)
requires Link purpose and the original expected session, locks current identity
policy and the scoped subject, then verifies the fresh session's actual owner.
An existing scoped subject is rejected; no email lookup or transfer selects an
owner. Identity insertion, optional protected Apple capture, audit and verified
local notice share a transaction, followed by the original deadline check.
[Atomicity cases](../../crates/auth-postgres/tests/lifecycle/oidc/linking/atomicity.rs)
require exactly one winner for two owners linking one scoped subject, prove notice
failure rolls back link/unlink authority while consumed provider state stays spent,
and distinguish late target-disable refusal after actual provider I/O. The current
22-case isolated PG linking profile and 13-case browser profile passed. This review
adds no new proof constructor, fallback or independent approval.

## Review and gates

Review against the [threat model](threat-model.md) and [architecture](../architecture/overview.md)
must inspect actual assertions and trust/transaction boundaries, not infer safety
from green totals. Source/policy disable, nonce/subject/realm mismatch, concurrency,
final post-wait time, audit/notice rollback, secret redaction and valid controls
must remain observable. Application authorization stays outside authentication.

The [control-to-assertion review](threat-control-review.md) maps all fifteen
threat-model rows, records corrected documentation drift and preserves residual
limits. The named remaining browser and startup profiles above are refreshed.
This bounded local evidence does not replace the remaining manual acceptance.
Registered Google/Apple/manual OS/device checks and independent review remain open.
Backup/restore/rolling recovery, performance/abuse capacity and publication are
separate tracked obligations; this matrix neither executes nor waives them.
No unavailable external check becomes a local pass. AUTH-47 remains In Progress.
