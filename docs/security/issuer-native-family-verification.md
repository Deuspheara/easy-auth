# Native family library verification — AUTH-40

This receipt covers optional core/PostgreSQL native family operations, not completed
AUTH-40, HTTP human confirmation, native system-browser acceptance, interoperability
certification, an audit or production approval. ADR0032 waived independent SAML
review; no independent review was performed by that waiver.

The earlier explicit-consent source0004f61e1d78b174fa8c177a915b23ca02dbdfe5 passed
[exact CI40021214196](https://github.com/Deuspheara/easy-auth/actions/runs/40021214196).
Two separate local structural commits precede family behavior:07d0fdf shares the
existing concrete signing engine and typed audit modules;82b639f moves ordinary
issuer test setup to support. Before extraction delivery, focused strict Clippy,
23core issuer,28real-PG signing and10audit cases passed. The fixture move retained
28signing cases and strict linting.

## Implemented authority

Initial native issuance requires a genuine separately approved native code, S256,
exact actual callback and full current client/policy/key/source/owner/session/code/
consent facts at preparation and completion. Only concrete RS256 produces the opaque
signed proof. Family/hash-only refresh/access, code consumption and typed audits
commit atomically. Initial ID/access retain original short code/freshness/key caps.
The distinct offline family retains the original proposed/source absolute cap.

Refresh spends one hash, increments bounded generation, writes fresh access/refresh
hashes and credential-actor audit atomically. Access is at most300seconds; family
idle rolls only inside original absolute bounds. Final clock includes pre-rotation
idle after writes/waits. Cookie idle/freshness/timestamps and original auth_time are
unchanged; refresh returns no new ID token/session. Reuse permanently revokes family
and descendant access before invalid_grant. Revocation accepts either matching
family credential and reduces authority after source/policy/session disable.
Unknown/repeated input succeeds indistinguishably; audit/storage failure rolls back
and returns error. Actual current client authentication and full namespace remain.
Maximum10active families per owner/client and10000generations bound policy/history.

Migration0035 preserves online rows and approved native consent, adds exact tuple
constraints and hash-only history. A deidentification trigger removes new audit
references for unchanged feature-independent erasure SQL. Restart evidence uses
fresh connections after schema DDL; live old-query/DDL concurrency is not claimed.

## Focused evidence

Five isolated native core tests pass, including malformed committed metadata,
absolute/idle/access caps, audience/authority and redacted credential output.
Twenty family PostgreSQL cases pass, including the finite active-family quota
boundary: maintained-library verification of genuine RS256 ID claims;
one-use code and exact PKCE/actual callback; hash-only storage; original caps;
rotation/reuse; actual revoke-all; audit failure rollback/retry; permanent cleanup
after source/policy disable; realm/client/credential isolation; database-only
rotation/revoke races; observed final-audit idle expiry; genuine cookie-idle/freshness
expiry without cookie extension; migration/restart preservation and actual two-step
account erasure. Full final gates are recorded below. All signatures finish before database concurrency cases; no custom
signature-concurrency experiment, new crypto/XML producer, bypass, fuzz or stress run.

## Maintainability and remaining work

Core signing proof/engine, native family policy/ports/use cases and PostgreSQL
issuance/family/session delegation remain separate owning modules. New modules stay
below300lines. Longer ordered transactions/scenarios retain lock order, immutable
caps, writes, final clock and rollback evidence together as function-size exceptions.
No dependency/version change, generic framework, public proof constructor, security
check relaxation, timeout increase or advisory ignore. Published0032–0034 are unchanged.
Protected review/bounds/comparison files remain unexecuted and unpublished.

Actual confirmation HTTP/UI, native wire token/revocation transport, secure platform
storage integration, owned native system-browser/PKCE acceptance and explicit new
OIDC/SAML delegation lifecycle acceptance remain work. Existing source checks are
reused, never waived. Public native client IDs are not introspection authentication.

## Final local gates

`cargo fmt --all -- --check`, locked strict workspace/all-target Clippy in default
and all-feature configurations, default workspace115cases and all-feature workspace
950top-level cases plus one isolated child-process invocation pass with zero failures
or ignored cases. All-feature coverage includes574real PostgreSQL lifecycle and153HTTP
cases. The isolated native feature (without optional provider backends) passes
all44policy/consent/family PostgreSQL cases. Warning-free all-feature Rustdoc, compiled advisory audit, all-feature
cargo-deny, unchanged245file/11patch SAML integrity,11source/qualification tests,
scoped redacted Gitleaks, relative links, diff and source sizes pass.

The existing owned HTTPS signed issuer/separate-client browser regression passes
all3cases with database and private TLS cleanup. This is regression evidence for
the shared concrete signer, not new native refresh system-browser acceptance.
The initial expanded isolation test had an owned Secret/borrow compile error; it
was corrected before verification. No assertion, timeout or security rule changed.
Exact pushed source and hosted CI status are recorded in AUTH-40; a local pass is
not a hosted CI result. AUTH-40 remains In Progress.
