# Code organization

Maintainability is part of correctness: authentication code must be easy to locate, understand and review. The mandatory rules live in [AGENTS.md](../../AGENTS.md#maintainability-and-clean-code) and apply to human and agent contributions.

## Responsibility boundaries

Keep the four existing workspace packages. Add modules for implemented behavior inside them; a new feature does not automatically need a new crate.

| Package | Owns | Keep out |
| --- | --- | --- |
| `auth-core` | Domain types, policy, use cases and repository/delivery ports | Axum extractors, cookies, SQL and server configuration |
| `auth-postgres` | Realm-scoped queries, migrations, atomic transactions and locking | HTTP responses and duplicated business policy |
| `auth-axum` | Routing, request/response types, browser boundary and HTTP error mapping | SQL and independent versions of core policy |
| `auth-server` | Configuration, SMTP delivery, worker lifecycle and composition | Duplicated authentication workflows |

Within each package, group related code by the vocabulary used in the domain: email authentication, passwords, recovery, account lifecycle, sessions and notifications. Cross-cutting browser cookie policy can have its own focused module. Keep error conversion at the relevant adapter boundary.

## Growing a feature

Start with a focused module such as `sessions.rs`. If it gains several distinct responsibilities, move it to a folder such as `sessions/mod.rs`, `sessions/types.rs` and `sessions/revocation.rs`. Use names that describe the actual responsibility; do not manufacture that whole tree before the code needs it. The entry file declares modules and exposes the deliberate API; it does not accumulate unrelated implementations.

The same feature may have an HTTP module, a core use-case module and a PostgreSQL transaction module. Those modules follow the existing inward dependency direction. Keep related request types beside their handlers, domain types beside their use cases, and SQL helpers beside the transactions that own them. Expose only what another module or a consumer needs, using private or `pub(super)`/`pub(crate)` visibility where sufficient.

Keep transaction ownership and lock ordering visible in one place. A helper should name a meaningful operation and make its transaction/context dependencies explicit. Avoid layers of tiny forwarding functions that force a reviewer to jump between files to establish an authorization invariant.

## Tests and review

Organize integration suites into feature-named files or modules, with reusable setup in `tests/support/`. Keep feature-specific assertions and fixtures with their tests. Test external behavior and security invariants rather than exposing private implementation solely for tests. When splitting SQLx suites, retain their migration setup and isolated database behavior.

For every change, review:

- Can a contributor find the implementation and its tests from the feature name?
- Does each changed module have one clear responsibility, with a thin crate entry point?
- Are policy, error handling and setup shared only where the meaning is actually the same?
- Are authorization, realm scope, transaction boundaries and secret redaction still easy to inspect?
- Do oversized files/functions need a cohesive split, or is their size justified by keeping an invariant together?

The approximate 300-line file and 50-line function thresholds in AGENTS.md trigger this review. Generated files and published migrations are not extraction targets. A cohesive transaction may be longer; explain that decision rather than splitting it across opaque helpers. Formatting, linting and tests complement this review and cannot replace it.

## Implemented layout

AUTH-52 splits the original accumulating implementation files and test suites into these owning modules:

```text
crates/auth-core/src/
  lib.rs                    # Public facade
  auth/                     # Auth composition and feature use cases
  ports.rs                  # Repository and delivery contracts
  password.rs               # Bounded hashing and password policy
  passkeys/                 # Separate registration/assertion verification, private state, enrollment use cases and port
  email.rs, secret.rs       # Input and secret policies, with unit tests
  audit.rs, error.rs, identity.rs, notifications.rs, sessions.rs
crates/auth-postgres/src/
  lib.rs                    # Adapter construction and startup provisioning
  repository.rs             # Explicit core-port delegation
  locking.rs                # Email lock order and fresh-account locking
  audit.rs                  # Typed transactional recording and scoped deidentification
  email.rs, passwords.rs, recovery.rs, notifications.rs
  sessions/                 # Validation, inventory and revocation transactions
  passkeys/                 # Optional preparation/completion and locked admission/ownership policy
  account/                  # Email-change and deletion transactions
crates/auth-axum/src/
  lib.rs                    # Public facade
  router.rs                 # Routes and state composition
  browser/                  # Validated origin/cookies and request boundary
  handlers/                 # Feature handlers and transport types
  passkeys/                 # Experimental enrollment router, thin handlers and concrete schemas
  contract.rs, error.rs     # Generated OpenAPI and public error mapping
  pages/                    # Optional reference HTML and JavaScript
apps/auth-server/src/
  lib.rs, main.rs           # Public facade and server lifecycle
  configuration.rs          # Validated composition
  smtp.rs, notifications.rs # Delivery adapter and worker
```

The HTTP and PostgreSQL integration entry files declare feature modules under `tests/browser/` and `tests/lifecycle/`, respectively. Their `tests/support/` folders contain reusable setup; account-only proof fixtures stay in the account test module. The single test target per adapter preserves the existing SQLx test setup without duplicated fixture compilation across many integration binaries.

Passkey integration scenarios live under `tests/lifecycle/passkeys/`, separated
into protocol negatives, enrollment binding/admission, concurrency/rollback,
credential limits/deletion and observed lock-wait cases. The software authenticator
is a test-only dependency. Production protocol code does not implement a mock token.

Rust permits one implementation of a trait for a type. PostgreSQL's `repository.rs` therefore delegates directly to crate-private feature methods. It adds no policy, SQL or generic framework. The public adapter and core APIs stay unchanged. OpenAPI's generated path descriptors are imported locally in `contract.rs` so moving a handler does not accidentally publish Rust module names as API tags.

## Reviewed size exceptions

The PostgreSQL `finish_email`, `enroll_password`, `finish_password_reset`, `confirm_email_change`, `finish_account_deletion`, `list_sessions` and `revoke_all_sessions` functions exceed the approximate 50-line review trigger. Each keeps its lock acquisition, proof revalidation, identity/credential mutation, session invalidation, audit/notice write and commit in a single visible transaction. SQL and bind chains are laid out explicitly. Splitting these functions into arbitrary steps would hide ordering and rollback invariants; add a helper only for a meaningful operation whose dependencies remain clear.

`configured_auth` likewise keeps the ordered, fail-closed startup composition together. Longer integration scenarios keep their arrange/action/assert sequence together to prove complete state transitions, isolation and rollback. They are now grouped by feature rather than collected in one large suite file. These are reasons for the current exceptions, not exemptions from reviewing future growth.

Passkey enrollment `save` and `commit` likewise keep admission, ownership/freshness
revalidation, state mutation, credential insertion, audit and commit visible in
their owning transaction. Their SQL is laid out explicitly. They exceed the
approximate function-size review trigger without adding unrelated responsibilities.

The browser fixture lives under `examples/passkey-browser/`, with separate database
lifecycle, configured fixture and explicitly disabled mail modules. Its Node runner
keeps child/browser ownership and normal-completion cleanup in one visible try/finally;
case bodies live in a separate test module. These longer orchestration/test functions
retain ordered setup/action/assert/cleanup rather than hiding secret handling or
resource ownership in generic helpers.

The assertion verifier keeps trusted ownership/snapshot checks, its explicit
account-bound/discoverable branch, high-level signature verification and backup
policy together in `verify_authentication`. It exceeds the function-size review
trigger to retain that proof boundary in one place. Private ceremony encoding and
stored credential decoding have separate owning modules; no SQL or HTTP behavior
is added to the verifier.

Passkey sign-in use cases and their repository port are separate from assertion
verification. PostgreSQL `passkeys/authentication/` owns admission, preparation and
completion. Its `save` and `commit` exceed the function-size trigger to keep browser
count locking and user/key/ceremony lock order, exact snapshot and post-wait expiry
checks, credential mutation, session/audit insertion and rollback visible. Tests
group binding, concurrency, migration and unchanged-row wait invariants separately.
