# Contributing

Documentation fixes, bug reports, reproducible test cases and focused code changes
are welcome. Original contributions are licensed under MIT OR Apache-2.0.

## Start a contribution

Use [GitHub issues](https://github.com/Deuspheara/easy-auth/issues) for public bugs
and proposals. Describe the problem, expected behavior, relevant versions and a
minimal reproduction. Discuss substantial changes before implementing them.
Public contributors do not need access to the maintainers' internal tracker.

Keep each pull request focused on one problem. Explain the resulting behavior,
link the relevant public issue when available, and record validation and remaining
limitations. Never include credentials, private workspace data or personal account
details in issues, fixtures, screenshots or logs. Use the [security policy](SECURITY.md)
for vulnerabilities and follow the [code of conduct](CODE_OF_CONDUCT.md).

## Set up locally

Follow the [README quick start](README.md#quick-start) with Rust 1.95 and Docker
Compose. Database tests create isolated PostgreSQL databases; the development/CI
role needs `CREATEDB`. Production runtime roles should not have that privilege.
Optional passkey tests also require OpenSSL development libraries and `pkg-config`,
including for the test-only software authenticator.

## Code and documentation

Read the [architecture overview](docs/architecture/overview.md), relevant
[architecture decisions](docs/README.md#architecture-and-design), and
[threat model](docs/security/threat-model.md). The [code organization guide](docs/architecture/code-organization.md)
and [agent instructions](AGENTS.md) describe the implementation boundaries.

- Keep entry files thin and group implementation and tests by domain responsibility.
- Use narrow visibility and keep HTTP handling, core policy and PostgreSQL transactions separate.
- Separate structural refactors from behavior changes. Files near 300 lines or functions near 50 lines need a responsibility review, a cohesive split or a concrete justification.
- Preserve transaction boundaries, lock ordering, authorization and realm isolation.
- Add migrations for schema changes; do not edit published migrations.
- Cover changed authentication behavior with negative, replay, concurrency and tenant-isolation tests. Update affected contracts and guides.
- Reuse reviewed protocol implementations. Do not introduce custom cryptography or XML signature verification.

Write public documentation around current behavior, setup, limitations and technical
rationale. Keep personal requests, individual design approvals and private tracker
content out of it. Historical test records must retain their dates, source scope
and assurance limits; passing local tests does not establish an audit or production readiness.
Preserve third-party attribution and check license compatibility for new code or assets.

## Validate a change

With the development environment loaded, run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/audit.py
cargo deny --all-features check
```

Run default and all-feature test suites sequentially. SQLx derives fixture database
names from test paths, so overlapping feature variants can reset one another's
databases. The repository defaults to four test workers to fit SQLx's shared
20-connection budget; overrides must leave room for lock gates, concurrent actions
and observers. Individual scenarios still exercise concurrency.

Database tests must run against real PostgreSQL. Record exact failures or unavailable
services rather than treating skipped checks as passes. Run the relevant browser
or provider suites for affected features, and preserve negative coverage when moving tests.
With the application running, `python3 scripts/smoke.py` exercises the local flow.
CI also runs source secret scanning and dependency/license checks; see the
[CI guide](docs/guides/ci.md).

For website changes, follow [website/README.md](website/README.md). The website
publishes allowlisted guides from committed Git objects, so an uncommitted guide
edit is not included in a normal site preview.

Review the changed file tree, naming, visibility and responsibility boundaries
alongside test results. Document justified size exceptions and deferred cleanup.
