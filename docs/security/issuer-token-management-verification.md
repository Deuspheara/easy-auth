# Access lifecycle verification

AUTH-40 access-management increment, 2026-10-23. Full native refresh-family scope
remains unfinished. See [ADR0038](../architecture/adr/0038-native-token-lifecycle.md),
[the guide](../guides/issuer-token-management.md) and the preceding
[signed issuer receipt](issuer-signing-verification.md). Exact pushed source/hosted
results are recorded separately in the tracker; earlier CI does not qualify this source.

## Implemented and exercised

The optional core/PostgreSQL service inspects/revokes actual existing hash-only
access credentials. Introspection requires current confidential Basic authentication
and its own audience. Public client IDs, local cookies and a known token do not
authenticate a consumer. Unknown valid opaque formats still authenticate the client
before inactive success; bounded presented input immediately becomes the existing
SHA-256 verifier and has no raw projection. Foreign/unknown/revoked/inactive results
expose no claims. Authentication/storage failures remain finite errors.

Ordered current client/key/namespace/source/owner/session/access/original grant locks,
exact original method/authentication time/revision and all original consent/code/
session caps precede a last database-clock check. Inspection changes no idle time.
Ordinary active-key rotation retains live old-key access; explicit key disable or
unpropagated reenable does not. Original code authority cannot be widened by the
access ledger. Active metadata exposes only pairwise subject/issuer/audience/time/
type/scope, with no owner/session/nonce/hash/raw token or business role.

Migration0032 adds a nullable permanent revocation timestamp; published migrations
are unchanged. Exact matching credential possession/current registered method can
reduce only its realm/issuer/client's access authority. Confidential clients require
their actual Basic secret. Unknown/foreign/repeated revocation is indistinguishable
success; an existing timestamp never changes/clears. Local sessions and original
codes/audit remain unchanged, and explicit revocation remains possible after source/
session expiry. No fake owner-actor event or offline ID-token erasure is claimed.

The opt-in HTTPS HTTP extension shares strict form/Basic/trusted-peer admission,
finite errors and no-store/no-cache. No Origin/cookie/forwarding-header authority
is introduced. Closed4KiB forms allow token, optional client_id and ignored hint;
presented credentials are at most1024printable ASCII bytes. Unknown/duplicate decoded
members, malformed percent/UTF-8, query/media/encoding/oversize input refuse. Inactive
JSON contains only active=false; revocation200 has an empty body. Active/inactive
OpenAPI shapes are both closed and do not overlap. Ordinary issuer/server routers
have no new management endpoints; full refresh/delegation is not advertised.

## Local evidence

Rust1.95/macOS arm64 and disposable real PostgreSQL:

- Final `cargo test --locked --workspace`:115passed,0failed,0ignored.
- Final `cargo test --locked --workspace --all-features`:902passed,0failed,0ignored,
  including530real PostgreSQL lifecycle cases and153HTTP cases.
- Isolated token-status PostgreSQL13cases pass: actual credential checks; client/
  realm/issuer isolation including inconsistent trusted-port scopes; permanent/public
  possession revocation; current owner/session/key/client/namespace policy; retained
  key rotation; original caps; observed revoke/expiry waits; DB-only concurrent
  revoke; storage failures; complete31->32 row preservation/usable prior credential.
- Isolated management-enabled issuer HTTP11cases pass, including4new real email/
  consent/code/token/status cases and7retained issuer transport cases. Closed schema,
  actual Basic/public roles, cookie refusal, unknown formats, default-route absence,
  storage classification, media/query/body/header/peer and authority checks pass.
- Two new core metadata/presented-input policy cases pass in the full suite.
- Formatting, strict locked default/all-feature all-target workspace Clippy and
  warning-free all-feature Rustdoc pass.
- Compiled advisory audit and all-feature cargo-deny advisories/licenses/sources/
  bans pass. Existing inactive SQLx/MySQL rsa0.9.10 advisory remains visible; no
  advisory ignore, dependency/package/version change or new cryptographic scheme.
- SAML source245files/11patches and11existing source/qualification-script checks pass.
  Integrity/ordinary qualification is not independent security approval.
- Existing owned signed-issuer HTTPS browser/separate-client3case regression passes
  with normal database/private TLS cleanup. This does not exercise new native
  refresh/system-browser behavior or claim that unfinished acceptance has passed.
- Scoped redacted Gitleaks, changed relative Markdown links, diff and protected-file
  checks pass before commit. Protected review/comparison/research is neither executed
  nor published.

The original structural rename was committed before its formatting-stopped process
was checked. It was corrected, verified17core issuer tests and amended while still
unpublished. The strict form/contract extraction then passed7isolated HTTP cases
before a separate structural commit. A discarded must-use test registration was
replaced with a real revision assertion; a visibility error was fixed within the
issuer's private boundary, and borrowed temporary test hashes received explicit
bindings. No existing assertion/policy/timeout or advisory gate was weakened.
Final review also added the original-cap predicate and regression, and closed both
introspection response schemas. Full checks above ran after those corrections.

## Remaining scope and maintainability

Core input/projection/port/use case stay in `issuer/tokens/`. PostgreSQL state,
revocation and introspection transactions stay in its owning folder; retained key
policy stays with signing. HTTP closed types/handlers/composition stay under
`issuer_web/management/`. Credential, lifecycle, policy, ordering and migration cases
have separate modules. New modules are under300lines. Longer ordered transaction/
scenario bodies retain lock/cap/final clock and healthy controls visibly together.
No generic plugin/token framework, public proof constructor, speculative crate or
unrelated cleanup is introduced/deferred.

AUTH-40 remains In Progress for explicit native offline consent/policy, a separate
bounded grant/family, one-use refresh rotation with reuse-detected family revocation,
typed lifecycle audit, secure client storage guidance and actual owned native system-
browser/PKCE acceptance. Existing code/freshness caps cannot silently become offline
authority. Introspection is not local authentication or application authorization.
Broader standalone/SDK interoperability, normal outbound activation and production
approval remain open. ADR0032 waived independent SAML review; it was not performed.
No PR/contact/image publication/live deployment, adversarial XML/cryptographic
producer, bypass/fuzz/stress or custom signature-concurrency experiment is part of
this access increment. Ordering tests complete ordinary issuance before database-only
revocation/inspection operations; they establish no new signing concurrency assurance.
