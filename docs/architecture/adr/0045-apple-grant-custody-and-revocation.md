# ADR 0045: Protected Apple grant custody and retry-safe disconnect

Date:2026-10-25. Status: design and implementation in progress for AUTH-26.
No ordinary activation, registered-provider acceptance, production qualification,
independent approval, PR, merge or deployment is authorized by this decision.

## Scope and primary contract

The owner directed locally verifiable engineering while deferring real provider/
production verification. AUTH-25 engineering is pushed, but its AUTH-24 acceptance
gate and AUTH-25 -> AUTH-26 relation remain. They are release blockers, not evidence
of prerequisite qualification. The SAML waiver and outbound OIDC release gate stay
unchanged. This work extends existing core Apple/OIDC features, PostgreSQL
transactions and explicit Axum composition; no provider framework or new crate.

Apple's [Sign in with Apple revocation contract](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens)
uses the fixed HTTPS endpoint `https://appleid.apple.com/auth/revoke`, the registered
client ID, a freshly issued protected client-secret JWT and an opaque refresh/access
token with its matching hint. Its200 response may be empty and also represents an
already-invalid token. Do not confuse this API with Account and Organizational
Data Sharing's different `/auth/oauth2/v2/revoke` endpoint. Neither an uploaded ID
token, an arbitrary endpoint nor a local session is a provider-revocation token.

The [token response](https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse),
[response errors](https://developer.apple.com/documentation/technotes/tn3107-resolving-sign-in-with-apple-response-errors)
and [account deletion note](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple)
require separating provider credentials, identity verification and local account
lifecycle. The provider error body is untrusted: retain only finite categories,
never raw descriptions, tokens, headers or foreign errors. Offline fixtures must
exercise actual client-secret verification, encoded token type, empty200, retry,
malformed replies and isolation. Documentation reads are not a real-provider run.

## Explicit capture and protection

Add optional `apple-grants` to the existing core/PostgreSQL Apple modules. Default
sign-in/link operations continue discarding unused credentials and expose no grant
capture/revocation capability merely because the feature compiles. A separate
explicit composition must retain tokens only from the same initiated one-use
Apple code exchange whose signed identity/nonce/source/purpose proof passed the
existing verifier. There is no uploaded-token or public proof constructor.

Keep the existing response parser's validation/error semantics shared; extract
its successful wire projection separately before extending it. Ignore unsigned
profile for ownership. Prefer a returned refresh token for revocation; retain an
access token only with explicit bounded lifetime facts. Protect captured material
before it reaches SQL, and atomically attach it to the actual realm/source/identity
resolved by the final existing sign-in or link transaction. No email merge,
policy transition, new freshness inference or weaker fallback is introduced.

Reuse pinned josekit0.10.3/OpenSSL's compact JWE implementation strictly as an
internal at-rest envelope: fixed `dir` + `A256GCM`, exact versioned type and
associated realm/source/client/identity/grant UUID binding. This is not inbound
JWE authentication or a new protocol grant. Exact header selection rejects every
extra member, compression, alternate algorithm/type or mismatching context before
decrypting. The library owns nonce/tag/AEAD construction; do not implement crypto.
Payloads/ciphertexts and blocking capacity are bounded. Owned raw inputs/plaintext
buffers zeroize; native-library/internal parser copies are not claimed erased.

Trusted operator composition supplies explicit32-byte random storage keys with
non-nil unique IDs, one current writing key and bounded explicitly retained reading
keys. No generated/default key, key in request/SQL/browser, arbitrary-payload crypto
API, raw credential accessor, key-by-trial or retired-key fallback. Missing keys,
authentication/tag failure and malformed data fail closed with categorical errors.
Rotation rewraps the same opaque grant and immutable binding under the current key,
using a fresh library nonce and compare-and-set persistence. Rewrap changes no
provider token and does not manufacture a successful provider revocation. Old
reading keys must remain protected until every active/pending envelope is migrated.

## Storage, disconnect and retry

Use an additive immutable migration with realm-scoped active grant rows and
finite pending/leased/completed/error states. Keep live identity association
separate from immutable non-secret envelope binding. Never store raw tokens,
client secrets, email or raw subject in job metadata. Historical unqualified Apple
identities gain no fabricated credential or remote-success claim.

Local unlink must retain AUTH-25's original fresh retained-method, current-source,
owner/realm, subject serialization, deadline, audit and verified-contact notice
checks. Move every captured grant for the removed identity into durable pending
revocation in that same transaction. Account/identity deletion must likewise not
cascade away pending revocation material. Storage-level lifecycle constraints/
triggers must prevent a build without the optional worker from silently discarding
existing protected grants. Pending jobs retain only minimal opaque binding/source
metadata and encrypted revocation material, separate from erased local account
rows. Document finite retry eligibility and the maintenance needed to purge expired
unconfirmed ciphertext; expiry is not remote success. Realm erasure is explicit.

The worker claims one realm/source-matching job with a finite lease, commits the
claim before network I/O, decrypts through the explicitly selected vault key and
sends only to fixed Apple HTTPS with existing DNS/IP/TLS/time/body/redirect limits.
Revocation must still be possible for an administratively disabled sign-in source;
that never reenables authentication. Source/client/key changes cannot retarget a
pending credential to another client. Sign-in signing key and at-rest storage key
rotation remain separate. Do not hold owner/identity/session SQL locks over I/O.

A finite lease token/generation controls acknowledgments and rescheduling. A crash
or lost200 permits idempotent retry; stale/concurrent workers cannot acknowledge,
replace or erase another job/generation. Only the documented successful response
marks confirmed completion and erases ciphertext. Provider/config/transport errors
remain distinct finite failures with capped backoff/attempt/retention policy; no
busy retry, raw diagnostics or invalid_client-to-success conversion. Local session
revocation/isolation and account deletion do not wait on provider availability.

There is no distributed transaction with Apple's code redemption. A crash or final
local rejection after a remote token was issued cannot be represented as durable
capture or remote revocation. Do not auto-revoke a mismatched/unverified foreign
subject or invent a session to recover the gap. Record this operational limit and
manual/provider qualification work; do not claim it is solved by local atomicity.

## Required evidence and maintainability

Core tests cover token-envelope/header/key/context isolation, redaction, tampering,
size bounds, explicit rotation and missing/retired keys. Real-PG suites cover actual
verified sign-in/link capture, atomic rollback, multiple grants, unlink/deletion,
feature-disabled lifecycle preservation, lease/retry/concurrent completion, source/
realm isolation, expiry/purge, key rotation and migration/privacy constraints.
Provider fixtures must verify actual request encoding/signature and bounded error/
retry semantics; genuine HTTP/browser completion must never expose raw grants.

Required format, strict default/all-feature lint, workspace/real-PG and relevant
security gates remain. Record exact failures and source hashes/commits, not merely
passing assertions. New responsibilities live in owning Apple grant and PostgreSQL
feature modules; refactors remain separate from behavior. Preserve published APIs/
migrations unless this scoped explicit contract requires an additive extension.
Review file tree, visibility, transaction/lock order and duplication before closure.

## Capture/ledger engineering checkpoint

Optional Rust capture now shares original callback admission/redemption/signed
verification and final existing identity/link transactions. Explicit authorization,
opaque verified/mapped/capture types and sign-in/link use cases require a configured
vault. Captured material reaches SQL only after bounded encryption against the
actual resolved identity. Default flows still discard unused credentials. The
payload includes exact provider client, for worker comparison before dispatch.

Migration0038 queues all captured grants on identity deletion. Ordinary account
deletion with no vault still erases audit subjects and preserves pending ciphertext/
minimal binding metadata. Trusted row/version-based rewrap preserves pending
eligibility of604800 elapsed seconds rather than timezone-dependent calendar
arithmetic. The separately implemented worker/maintenance checkpoint below supersedes the
earlier queue-only limitation. The first deletion test's direct SQL correctly hit the audit-
user foreign key; the corrected case uses actual ordinary account deletion
preparation/completion without relaxing that constraint. Observed final-audit
expiry, source-disable, concurrent completion, missing configuration and rollback
controls accompany actual captured sign-in/link/unlink tests.


## Explicit worker and HTTPS engineering checkpoint

Core now supplies the concrete source-bound worker, protected form and opaque
post-response confirmation. PostgreSQL commits one60-second lease before I/O,
limits attempts to8, preserves original7-day eligibility and checks current lease/
generation/time after lock and write waits. Failure backoff begins at30 seconds;
exhausted attempts stay visibly failed. Confirmed empty200 erases ciphertext;
expiry instead records unconfirmed expired state. Bounded maintenance processes
64 rows per phase and purges terminal metadata after another7 days. Invocation is
required, including for disabled/inactive sources; ordinary startup adds no worker.

The signer is shared explicitly with code exchange, including its existing native
worker bound. The concrete server adapter reuses the existing protected form POST,
TLS, checked address and operation limits. A private response profile permits an
absent Content-Type only for empty200, caps revocation bodies at16KiB and leaves
normal OIDC document/token JSON assertions intact. No redirect, transport retry,
proxy, cookie, TLS bypass or provider error text reaches public output.

Owned fixtures verify actual client-secret signatures/form fields and real-PG
lease/retry/local-session behavior. Private TLS scenarios exercise actual POST,
empty replies, bounded errors, malformed envelopes, declared/chunked oversize,
timeout and certificate/hostname negatives. The initial TLS test observed the
client's certificate rejection before the server had recorded its second failure;
its corrected observer waits for the actual handshake count without changing the
certificate assertion. HTTP/browser integration and full ticket acceptance remain
in progress. These fixtures do not establish a registered Apple revocation result.
