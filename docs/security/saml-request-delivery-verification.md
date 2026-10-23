# Normal SAML request delivery acceptance

AUTH-33, 2026-10-23. This increment finishes delivery acceptance for the existing
metadata and correlated-request implementation. Production authentication code,
dependencies, migrations, the maintained verifier and all eleven patches are
unchanged. [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md)
permits explicit opt-in after the maintainer waived independent review. Review was
not performed; neither this acceptance nor CI closes unresolved assurance findings.

The startup fixture runs the normal standalone binary and embedded example in
production configuration against an owned disposable PostgreSQL database. Existing
public certificates are provisioned through the production administrative API.
The fixture never contacts the configured IdP or SMTP destination. It parses only
metadata and AuthnRequests emitted by the unchanged maintained library, and never
constructs or edits XML/signature fixtures.

Each mode must publish identical metadata with the exact trusted entity, one HTTPS
POST ACS, persistent NameID, unsigned-request and signed-Assertion flags, and no
other advertised endpoint/key. The endpoint has the correct media type and no-store
policy, issues no cookie and leaves database facts unchanged. The actual Redirect
request must retain exact SSO destination, SP issuer, ACS, POST response binding,+persistent NameID and ID/RelayState cookie correlation. Three independent private
proof cookies retain host/Secure/HttpOnly/Lax/path/lifetime restrictions.

Database observations establish that start adds only one pending request; an
unbound cancel returns401 without spending it; the original bound cancel returns204;
and repetition returns401 without another mutation. Original source revision,
enable/JIT/pins, users, sessions and audits remain unchanged. The existing disabled,
unsupported, unprovisioned, mismatched, operator-disabled and missing/expired-pin
startup checks remain in the same suite. Runtime current-source and final commit
checks remain required independently of startup.

## Reproduce

Use the repository's loopback PostgreSQL fixture and a writable Python bytecode
cache. Never substitute production credentials or a remote database.

```sh
docker compose up -d postgres mailpit
export DATABASE_URL=postgres://auth:auth-development-only@127.0.0.1:59473/auth
cargo build --locked -p easy-auth-server --bin easy-auth
cp target/debug/easy-auth /tmp/easy-auth-saml-unsupported
cargo build --locked -p easy-auth-server --bin easy-auth --example embedded --example saml-startup-provision --features saml-web,oidc-web
PYTHONPYCACHEPREFIX=/tmp/easy-auth-python-cache EASY_AUTH_SAML_UNSUPPORTED_TEST_BINARY=/tmp/easy-auth-saml-unsupported python3 scripts/smoke_saml_startup.py
```

CI already invokes this exact startup suite after the unsupported and enabled
builds, alongside the isolated request/certificate/verification/identity features,
full PostgreSQL suites, actual Keycloak/browser acceptance and advisory/secret
checks. No workflow condition or security gate is removed.

## Verification

Local verification on macOS arm64 / Rust1.95 passes:

- `cargo fmt --check` and strict locked default/all-feature workspace all-target
  Clippy (`-D warnings`).
- `cargo test --locked --workspace`:115 passed,0 failed,0 ignored.
- `cargo test --locked --workspace --all-features`:799 passed,0 failed,0 ignored,
  including all466 real PostgreSQL lifecycle cases.
- Isolated `saml-requests`:5 core and15 real PostgreSQL cases pass.
- `smoke_saml_startup.py`:31 cases pass; final database removal confirmed.
- Exact maintained source inventory:245files/11patches; all11 existing source/
  qualification-script checks pass. Python compilation, relative links and diff
  whitespace pass.
- `scripts/audit.py` and `cargo deny --all-features check` pass without new ignores.
  The inactive SQLx/MySQL `rsa0.9.10` RUSTSEC-2023-0071 entry remains reported.
  Tools: cargo-audit0.22.2 and cargo-deny0.20.2.
- Official-archive-checksum-verified Gitleaks8.24.3 finds no leaks in the four-file
  authorized change set. All73 pre-existing private/unfinished files remain
  byte-identical, excluded from commits and unexecuted.

The initial Python compilation encountered an unwritable macOS bytecode cache;
using the temporary cache above resolved it. Both final startup runs and the full
Rust suites pass without weakening assertions, timeouts or security policy.

Commit and exact-commit hosted CI evidence are recorded in AUTH-33 after delivery.
Activation commit `b791875dc45e283528a42c749509736eb2200f71` separately
passed [CI39930343186](https://github.com/Deuspheara/easy-auth/actions/runs/39930343186)
in Rust, saml-release and secrets. That run belongs to the activation source; it
does not substitute for the delivery increment's own CI.

## Responsibility review

`scripts/saml_startup_contract.py` owns outgoing XML and cookie contract assertions;
`scripts/saml_startup.py` keeps process composition and real-database observations.
Both remain below300lines, and new/extended functions below50lines. The fixture
continues to own and clean its database/listener. No production policy or SQL is
moved into HTTP, and no private review/comparison/bounds file is part of this change.
Unfinished independent assurance, native resource measurement and broader IdP
profiles remain with AUTH-32/35; outbound issuer interoperability remains a release
gate. These tests establish none of those claims.
