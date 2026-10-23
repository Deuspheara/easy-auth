# Native confirmation HTTP verification — AUTH-40

This increment implements explicit owner confirmation transport, not completed
AUTH-40, native token/refresh HTTP, owned native client/browser interoperability,
independent review or production approval. The preceding family library is
[a11e017840835be4d1084631ca01546783648d4c](https://github.com/Deuspheara/easy-auth/commit/a11e017840835be4d1084631ca01546783648d4c).
Its exact CI40030407310 is tracked separately; it does not qualify later source.
ADR0032 waived independent SAML review, which was not performed by that waiver.

## Authority and delivery

Optional `issuer-native-consent-web` composes actual native and online services for
one exact trusted realm/HTTPS root issuer. It adds a fixed native page and closed
prepare/resume/approve/cancel JSON POSTs; default startup and routers stay unchanged.
Native confirmation displays the immutable proposed grant expiry and idle bound.
Only an explicit owner decision with the genuine initiating session, private browser,
handle and operation selector can reach the existing core approval transaction.
Prompt/query/DOM markers are not consent proofs. Shared finite browser mechanics
select display/transport from fixed server HTML, never source/account/persistence
policy. GET allocates nothing; query is scrubbed, values render through textContent,
correlation stays in memory and only the authenticated server return navigates.

Native/online requests share one private operation cookie slot. Preparation cannot
overwrite it; wrong kind/realm/session/selector cannot approve. Actual local-session
replacement clears transport, successful decisions clear it and failed approvals
retain retry proofs. Unusable resume clears only selected transport. Existing core/
PostgreSQL exact client/policy/source/owner/freshness/consent/code and final database
clock remain mandatory. Cancellation after policy disable remains possible.
No SQL, migration, dependency/version change, custom producer or security relaxation.
This consent-only router mounts no token, refresh, revocation or discovery endpoint.
Native code can currently reach only the separate concrete library exchange.

## Focused evidence

Eight isolated real-PostgreSQL HTTP cases pass: actual preparation/fixed preview/
unchanged resume/approval and subsequent concrete native library issuance; default
online refusal; actual other session and post-disable cancellation; Origin/query/
scope/prompt/PKCE/return boundaries; closed/duplicate/media/body/cookie limits;
actual session-change clearing; two real realms sharing one client ID; typed audit
fault rollback/retry; exact live closed contract, distinct native operation IDs,
HTTPS/realm composition and default route absence. Tests reuse the unchanged
ordinary key/account producer, not a new cryptographic fixture.

The existing owned HTTPS consent browser regression passes8cases with normal
owned-database/private-TLS cleanup after sharing browser mechanics. It verifies
default behavior and is not new native browser/loopback acceptance. Shared JS syntax
checks pass. Actual native UI/client end-to-end execution remains required.

Separate structural86b5635 extracts existing cookie/page/root composition and moves
ordinary HTTP issuer setup to support, before native behavior.25selected issuer/RP
cases, strict all-feature and isolated issuer-web linting passed. Feature-local
fixture imports were corrected in this unpublished structural commit. Initial
native tests omitted the PostgreSQL migration path; setup was corrected. An absent
route assertion first lacked required Origin and therefore observed the browser
boundary; the corrected request proves404. No production rule/assertion was weakened.

## Maintainability and remaining scope

Native wire types, thin handlers, fixed page, contract and router have named modules.
Private cookie mechanics and the finite browser controller are shared; no generic
framework or duplicate source/account/SQL policy is added. New tests separate
lifecycle, transport, contract/composition, realm isolation and audit rollback.
Modules stay below300lines; complete ordered scenarios retain their invariant
sequence as documented function-size exceptions. Protected private review/bounds/
comparison files remain unexecuted and unpublished. Published migrations are unchanged.

Final local gates are recorded below; exact pushed source/CI is recorded in AUTH-40.
Native token/refresh/revocation wire delivery, actual owned native browser/loopback/
PKCE acceptance, explicit new OIDC/SAML delegation lifecycle cases and secure-client
storage requirements remain AUTH-40 work. Public native IDs/cookies/known tokens
remain insufficient authenticated introspection-consumer authority. Production stays
supervised. AUTH-40 and the full feature goal remain active.

## Observed full-suite failure and test-only correction

The first all-feature run passed161HTTP and134core cases, then reported573PG
passes/1failure in the unchanged email admission scenario. Its source-limit assertion
followed admissions split across two valid ten-minute windows. Read-only aggregates
from the preserved failed test database showed source counts7and14 and21total
challenges; neither source bucket reached20. The PG executable was the same as the
previously passing family run. This was a test precondition failure, not evidence
that the limiter admitted above its per-window limit.

The test now waits for a fresh window only when fewer than5seconds remain, without
changing clocks/counters/production limits. All original5admission,20source-limit,
new-source and realm-isolation assertions remain. Added final checks prove the
controls and persisted buckets used one actual window. The focused original case
passes. The scheduling fix is recorded separately; the full suite is rerun rather
than reporting the first failure as a successful gate. No timeout, ignore or
production policy is weakened.

## Final local verification

Formatting and locked strict default/all-feature workspace/all-target Clippy pass.
Default workspace115cases and all-feature workspace958top-level cases plus one
isolated child-process invocation pass,0failed/0ignored, including574real PG and
161HTTP cases. Warning-free all-feature Rustdoc passes. Eight isolated native HTTP
cases and isolated native-consent-only strict linting pass. The unchanged owned
HTTPS consent browser regression8cases passed with normal database/private-TLS
cleanup; actual native browser execution remains open. Compiled advisory audit,
all-feature cargo-deny, unchanged245file/11patch SAML integrity,11source/qualification
tests, scoped redacted Gitleaks, changed relative links/diff/size review pass.

The first full run's email-window failure is retained above. Separate test-only
33dd591 preserves all original assertions and adds real-window checks; focused
original-case/strict PG lint and the complete final default/all-feature rerun pass.
Structural86b5635 remains separate from native behavior. No published migration,
production limiter, protocol/security check, timeout or advisory policy changed.
