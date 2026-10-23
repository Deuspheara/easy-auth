# Native consent library verification

AUTH-40, 2026-10-23. Explicit consent library operations extend the
[native policy](issuer-native-policy-verification.md). This does not complete
native confirmation HTTP/UI, refresh-family lifecycle or native browser acceptance.
See [ADR0038](../architecture/adr/0038-native-token-lifecycle.md).

Core separates the native input/request, trusted facts, safe preview, opaque Start,
port and service. Exact openid offline_access/prompt=consent reuse existing S256,
actual-return/state/nonce policy. Defaults still refuse the offline profile.
PostgreSQL migration0034 marks only new native rows and binds the immutable proposed
grant to its full realm/issuer/client/revision/owner/session/authorization tuple.
Prepared expiry never slides at approval; original source/session absolute caps,
existing short code/freshness/idle limits and a final database clock remain required.

Current client/policy locks precede existing source/owner/fresh-session/pending and
sidecar locks. Shared approval writes subject/code and the typed actual-owner-session
IssuerAuthorized audit in the caller-owned transaction; sidecar approval time matches
the code. Policy disable/reconfiguration permits only bound pending cancellation.
Client replacement, source/session narrowing, expiry, wrong owner/private bindings,
realm/issuer mismatch and default online-port misuse cannot approve native consent.
Account erasure cascades these rows and deidentifies existing audit attribution.
No refresh secret, extended access, local session or discovery/HTTP activation.

## Verification

- Behavior-preserving extraction275ea66 passed21core issuer and21real PostgreSQL
  code cases plus strict focused Clippy before behavior changes.
- Four isolated native core cases pass, including2new explicit request/port-fact
  boundary cases. Sixteen isolated native-consent PostgreSQL cases pass: real owner
  lifecycle and unchanged preview; permanent proposed bounds; old online refusal;
  prompt/scope/private proof; two actual realms sharing a client ID; client/policy
  invalidation; quotas; write/audit rollback; schema/full-tuple constraints; actual
  two-step account erasure; database-only approve/cancel race and observed policy/
  owner/sidecar/audit waits; historical online-grant preservation after restart.
- Final `cargo test --locked --workspace`:115passed,0failed,0ignored.
- Final `cargo test --locked --workspace --all-features`:930passed,0failed,0ignored,
  including554real PostgreSQL lifecycle and153HTTP cases.
- Formatting, locked strict default/all-feature all-target Clippy, warning-free
  all-feature Rustdoc, compiled advisory audit, all-feature cargo-deny, unchanged
  245file/11patch SAML inventory and11source/qualification checks pass. Scoped
  redacted Gitleaks, changed relative links, source sizes and diff checks pass.
  Hosted results must be tied to the exact pushed commit and recorded separately;
  earlier policy/access receipts do not qualify this source.

The new erasure test initially called a nonexistent convenience method; it now uses
the actual two-step repository flow. The migration test initially reused pre-DDL
SELECT * prepared results; it now reconnects before serving current operations,
matching startup migration order. Its expected subject count now explicitly proves
two independent native-client sectors. No published migration, existing assertion,
timeout, protocol/security check or advisory policy was weakened.

Core and SQL transactions stay in owning modules; crate entry files only reexport.
New/changed owned source/test files stay below300lines. Ordered transaction and
negative/positive/migration cases retain their invariants as function-size exceptions.
No new dependency/crypto, generic framework, public proof constructor or unrelated
cleanup. The marker's old-schema FromRow default serves historical online fixtures;
unsupported profiles and all default online operations independently refuse native
authority. No schema probing, retry or insecure compatibility fallback is added.

AUTH-40 remains In Progress. Actual confirmation HTTP/browser delivery, bounded
hash-only refresh families, atomic one-use rotation/reuse descendant revocation,
current source/owner/revoke-all checks, credential-actor lifecycle audit and owned
native browser/PKCE acceptance remain mandatory. A prompt string is not evidence
that a human reviewed a UI. Production and broader SDK/interoperability remain gated.
ADR0032 waived independent SAML review; it was not performed. Protected private
review/research/comparison work remains unchanged, unexecuted and unpublished.
