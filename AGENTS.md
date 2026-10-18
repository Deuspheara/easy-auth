# Agent instructions

Huly project AUTH is the primary development tracker. Inspect actual Huly tools/statuses; never invent IDs or mark acceptance criteria complete without evidence. Work one scoped ticket at a time, link commits/PRs, and keep ticket status current. docs/planning is a synchronization/export record, not a competing roadmap.

Read docs/architecture/overview.md, relevant ADRs, docs/research/protocol-dependencies.md and docs/security/threat-model.md before behavior changes. Dependencies point into auth-core. Protocol handlers contain no persistence rules. Keep users/provider identities/credentials/sessions/tokens and application authorization separate. Scope all storage to realm. No matching-email account linking.

No custom crypto, XML signature verification, hidden insecure fallback, generic plugin framework or speculative micro-crates. Prefer established reviewed implementations; record dependency/license/advisory risks. Schema changes require explicit migrations and real PostgreSQL tests. Tests must cover changed behavior, negative protocol cases, concurrency and tenant isolation. Update public contracts and docs. Record meaningful architecture changes in ADRs.

Never claim production readiness, audits, protocol compliance or interoperability without evidence. SAML and outbound OIDC are hard release gates. Never log secrets, raw auth headers, email tokens, authorization codes, assertions, private keys or provider credentials. Production requires TLS and fail-closed configuration. Keep internal Huly workspace content and credentials out of public artifacts.

Before completing a ticket: cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace; real DB integration suite; relevant security checks. Record exact failures/blockers, never silently skip required DB tests. No need for parallel agents unless explicitly authorized by user or a later applicable instruction.
