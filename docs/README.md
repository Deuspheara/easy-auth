# Documentation

easy-auth is experimental alpha authentication software. Start with the
[project README](../README.md) for local setup and available capabilities.
The [documentation website](https://deuspheara.github.io/easy-auth/) provides a
searchable selection of integration guides.

## Integrate and operate

| Task | Guide |
| --- | --- |
| Embed authentication in an Axum application | [Runnable example](../apps/auth-server/examples/embedded.rs) |
| Configure the standalone server | [CLI and diagnostics](guides/server-cli.md), [deployment](architecture/deployment.md) |
| Understand users, credentials, identities and sessions | [Domain model](architecture/domain-model.md) |
| Add passwords and recovery | [Passwords](guides/passwords.md), [recovery](guides/password-recovery.md) |
| Manage sessions and account lifecycle | [Sessions](guides/sessions.md), [email changes and deletion](guides/account-lifecycle.md) |
| Use the reference account interface | [Reference UI](guides/reference-ui.md) |
| Inspect HTTP contracts | [API contract](architecture/api-contract.md), [base OpenAPI](openapi.json) |
| Consume audit events | [Audit events](guides/audit-events.md) |

## Optional and experimental integrations

Each guide describes the required features, trusted configuration and remaining
acceptance limits. Compiling a feature does not automatically enable it.

- Passkeys: [enrollment](guides/passkey-enrollment.md), [sign-in](guides/passkey-authentication.md),
  [signup](guides/passkey-signup.md), [management and recovery](guides/passkey-management.md),
  [optional mailbox](guides/optional-mailbox.md) and [contact attachment](guides/email-attachment.md).
- Inbound OIDC: [provider setup](guides/oidc-web.md), [identity policy](guides/oidc-identities.md),
  [verification](guides/oidc-verification.md), [egress](guides/oidc-egress.md),
  [transactions](guides/oauth-transactions.md) and [account deletion](guides/oidc-account-deletion.md).
- Google: [code verification and native/browser components](guides/google.md).
- SAML: [integration](guides/saml.md), [provider profiles](guides/saml-providers.md)
  and [release configuration](guides/saml-release.md).
- Outbound OIDC: [standalone/embedded setup](guides/issuer-standalone.md),
  [client registration](guides/issuer-clients.md), [signing](guides/issuer-signing.md),
  [native clients](guides/issuer-native.md), [token management](guides/issuer-token-management.md)
  and [independent Rust client](guides/oidc-client.md).

## Architecture and design

- [Architecture overview](architecture/overview.md) and [authentication flows](architecture/auth-flows.md).
- [Code organization](architecture/code-organization.md): responsibility boundaries, feature ownership and reviewed size exceptions.
- Architecture decisions are numbered documents in [architecture/adr/](architecture/adr/).
  Start with the [product scope](architecture/adr/0001-build-versus-contribute.md),
  [sessions and PostgreSQL](architecture/adr/0002-sessions-and-postgres.md),
  [SAML activation policy](architecture/adr/0032-saml-maintainer-directed-activation.md)
  and [reference UI](architecture/adr/0042-reference-account-ui.md).
- [Reference UI design](design/reference-ui.md) and [implementation record](design/reference-ui-modernization.md).

## Security and verification

Read the [security policy](../SECURITY.md), [threat model](security/threat-model.md)
and [dependency assessment](research/protocol-dependencies.md) before evaluating adoption.
The [interoperability matrix](guides/interoperability.md) distinguishes automated,
virtual-device, manual and actual-provider evidence.

SAML is opt-in under an explicit [independent-review waiver](architecture/adr/0032-saml-maintainer-directed-activation.md).
The waiver does not establish independent approval or close the documented
assurance gaps. Outbound OIDC interoperability remains a release gate.

[Verification history](security/verification.md) and the focused records in
[security/](security/) preserve the scope of completed checks and unresolved work.
Their dates, source revisions, counts and ticket references describe historical
checkpoints; they are not a current build result or a release approval.

## Research and development records

[Ecosystem research](research/ecosystem.md), [adoption measurements](research/adoption-comparison.md)
and protocol investigations in [research/](research/) explain evaluated alternatives
and bounded experiments. Research findings are specific to their recorded sources
and do not constitute security endorsements.

The planning export in `planning/` is a maintainer synchronization record. Its
milestones and internal identifiers are historical context, not delivery promises
or a requirement for public contribution. Use [GitHub issues](https://github.com/Deuspheara/easy-auth/issues)
for public bugs and proposals; see [CONTRIBUTING.md](../CONTRIBUTING.md).

Test reproduction instructions live beside their suites in [tests/](../tests/).
See the [CI guide](guides/ci.md) for shared verification and [third-party provenance](../third-party/README.md)
for vendored code and license notices.
