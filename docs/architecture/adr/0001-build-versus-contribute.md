# ADR 0001: Narrow independent product with an upstream contribution checkpoint

Status: accepted for alpha exploration, 2026-10-18.

Context: RustAuth demonstrates substantial existing implementation coverage, but its pinned snapshot explicitly declares it unmaintained with no planned security updates. The initial assessment missed that notice; AUTH-5 corrects the maintenance evidence. Better Auth RS is an independent alpha alternative; lucid-auth has wide protocol scope. Rauthy, Kanidm and Kratos are established service alternatives. Reimplementation increases security and maintenance cost.

Decision: proceed with an embedded and standalone architecture as a small SQLx/PostgreSQL-first core, independent v1 HTTP contract and deterministic revocation. Do not claim Better Auth compatibility. No enterprise feature paywall. Core and server share the same use cases. The first increment is email proof and opaque sessions, not six protocol stubs.

Alternatives: evaluate contributions to maintained Better Auth RS/lucid-auth for compatibility, or a clearly identified community RustAuth fork with its own maintenance obligations; adopt Rauthy for an existing standalone OIDC service, Kanidm for directory integration, or Kratos + issuer for a headless service ecosystem. Reuse protocol crates and submit reusable fixes upstream rather than copying code.

Consequences: larger release burden remains ours. M00 must verify footprint assumptions, advisory histories and SAML feasibility. Before M03 expansion compare a minimal integration against RustAuth and lucid-auth; record whether the independent contract materially improves setup, dependency count and revocation clarity. If not, propose upstream collaboration rather than feature-count competition. Production and conformance claims require evidence. No competitor security ranking is inferred from this review.

AUTH-5 checkpoint, 2026-10-19: the [native comparison](../../research/adoption-comparison.md) found a smaller compiled graph and executable for the narrow easy-auth probe, but higher sampled RSS. All three native integrations passed post-return revocation checks, and our explicit verification/realm composition did not establish simpler setup. Continue the independent alpha for its shared two-mode contract and inspectable realm-scoped policy; do not claim a general footprint or revocation novelty advantage. Maintained lucid-auth/Better Auth RS remain collaboration candidates, especially for reusable negative fixtures and protocol dependencies. Full HTTP/protocol and sustained-load measurements remain release work.
