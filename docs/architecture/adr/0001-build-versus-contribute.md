# ADR 0001: Narrow independent product with an upstream contribution checkpoint

Status: accepted for alpha exploration, 2026-10-18.

Context: RustAuth and Better Auth RS are credible existing libraries; lucid-auth has wide protocol scope. Rauthy, Kanidm and Kratos reduce the operational risk of adopting an existing identity service. Reimplementation increases security and maintenance cost.

Decision: proceed with the requested embedded + standalone direction as a small SQLx/PostgreSQL-first core, independent v1 HTTP contract and deterministic revocation. Do not claim Better Auth compatibility. No enterprise feature paywall. Core and server share the same use cases. The first increment is email proof and opaque sessions, not six protocol stubs.

Alternatives: contribute to RustAuth/Better Auth RS (best for compatibility), adopt Rauthy (best for immediate standalone OIDC), Kanidm (directory integration), Kratos + issuer (headless service ecosystem). Reuse protocol crates and submit reusable fixes upstream rather than copying code.

Consequences: larger release burden remains ours. M00 must verify footprint assumptions, advisory histories and SAML feasibility. Before M03 expansion compare a minimal integration against RustAuth and lucid-auth; record whether the independent contract materially improves setup, dependency count and revocation clarity. If not, propose upstream collaboration rather than feature-count competition. Production and conformance claims require evidence. No competitor security ranking is inferred from this review.
