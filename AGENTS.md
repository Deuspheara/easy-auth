# Agent instructions

Use `feat/` as the branch prefix. Do not use `codex/` in branch names.

## Maintainability and clean code

Maintainability is an acceptance criterion for every change. Read [the code organization guide](docs/architecture/code-organization.md) before adding or moving implementation code. Refactor an affected oversized module before extending it with another responsibility; do not keep appending features to crate entry files.

- Organize code by cohesive domain responsibility within the existing crate boundaries. Keep `lib.rs`, `main.rs` and module entry files focused on declarations, deliberate reexports and composition. Put handlers, use cases, persistence operations and test scenarios in named modules. Create subfolders when a feature has several related modules; do not create empty scaffolding.
- Each module should have one clear purpose. Prefer files under roughly 300 lines and functions under roughly 50 lines. These are review triggers, not mechanical limits: when exceeding them, split at a meaningful boundary or explain why keeping the unit together improves readability or security review. Do not compress code, hide logic in macros or scatter a transaction merely to meet a count.
- Keep functions readable, with descriptive domain names, explicit inputs/outputs, early validation and shallow control flow. Replace unexplained literals with named policy values. Comments explain invariants, security reasoning and tradeoffs; remove dead code and stale comments.
- Use the narrowest visibility that works. Keep implementation details private; do not make internals public just to split files or simplify tests. Prefer concrete code until repeated needs justify a shared abstraction. Avoid catch-all `utils`, `helpers` or `common` modules for unrelated production behavior.
- Keep HTTP handlers thin, business policy in core and SQL/transaction behavior in PostgreSQL. Extract cohesive helpers while keeping transaction boundaries, lock order, authorization and secret handling explicit. Never duplicate policy between embedded and standalone modes.
- Group integration tests by feature or invariant. Share only reusable setup/fixtures in `tests/support/`; avoid a single accumulating lifecycle/browser test file. Preserve meaningful negative, concurrency and realm-isolation coverage when moving tests.
- Keep structural refactors separate from behavior changes. Preserve public APIs and immutable published migrations unless the scoped issue explicitly requires a contract change. Run the existing relevant tests after extraction; do not rewrite assertions merely to make a refactor pass.
- Before completing a ticket, review the changed file tree, responsibility boundaries, duplication, visibility and naming alongside test results. Explain justified size exceptions and any deferred cleanup in the ticket. Passing formatting and tests alone does not establish maintainability.

AUTH-52 establishes the feature organization described in the guide. Extend the owning feature modules and tests for subsequent tickets; do not rebuild monolithic entry files or suites.

## Development and security workflow

Huly project AUTH is the primary development tracker. Inspect actual Huly tools/statuses; never invent IDs or mark acceptance criteria complete without evidence. Work one scoped ticket at a time, link commits/PRs, and keep ticket status current. docs/planning is a synchronization/export record, not a competing roadmap.

Read docs/architecture/overview.md, relevant ADRs, docs/research/protocol-dependencies.md and docs/security/threat-model.md before behavior changes. Dependencies point into auth-core. Protocol handlers contain no persistence rules. Keep users/provider identities/credentials/sessions/tokens and application authorization separate. Scope all storage to realm. No matching-email account linking.

No custom crypto, XML signature verification, hidden insecure fallback, generic plugin framework or speculative micro-crates. Prefer established reviewed implementations; record dependency/license/advisory risks. Schema changes require explicit migrations and real PostgreSQL tests. Tests must cover changed behavior, negative protocol cases, concurrency and tenant isolation. Update public contracts and docs. Record meaningful architecture changes in ADRs.

Never claim production readiness, audits, protocol compliance or interoperability without evidence. SAML and outbound OIDC are hard release gates. Never log secrets, raw auth headers, email tokens, authorization codes, assertions, private keys or provider credentials. Production requires TLS and fail-closed configuration. Keep internal Huly workspace content and credentials out of public artifacts.

Before completing a ticket: cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace; real DB integration suite; relevant security checks. Record exact failures/blockers, never silently skip required DB tests. No need for parallel agents unless explicitly authorized by user or a later applicable instruction.
