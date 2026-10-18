# Contributing

Read README.md, AGENTS.md, architecture ADRs and the threat model. Huly AUTH is the development tracker; public GitHub proposals may be triaged into Huly by maintainers. Work on one scoped issue with acceptance tests. No credentials or private workspace data in issues, code, fixtures or logs.

Maintainability is required for acceptance. Follow the [clean-code rules in AGENTS.md](AGENTS.md#maintainability-and-clean-code) and the [code organization guide](docs/architecture/code-organization.md). Keep entry files thin, organize implementation and tests by responsibility, use narrow visibility, and separate structural refactors from behavior changes. Files around 300 lines or functions around 50 lines require a responsibility review and either a cohesive split or a concrete justification. These thresholds are review prompts, not a reason to compress code or obscure security invariants.

Use Rust 1.95 and Docker. Start development services with docker compose up -d --wait, load .env.example, then cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace. Database tests create isolated test databases and require the development/CI DB role to have CREATEDB; production runtime roles should not.

Schema changes require new migrations. Authentication/protocol changes need negative, replay, tenant and concurrency tests plus documentation. No custom cryptography or XML signature validation. Keep protocol-specific checks visible and avoid speculative abstractions. A release needs the full-lockfile/compiled-graph audit in scripts/audit.py, cargo deny, secret scans and conformance evidence.

Original contributions are dual MIT OR Apache-2.0. Confirm third-party license compatibility and preserve attribution before introducing code/assets. Follow CODE_OF_CONDUCT.md; use SECURITY.md for vulnerabilities.
