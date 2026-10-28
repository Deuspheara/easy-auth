# Security policy

easy-auth is experimental alpha authentication software and is not suitable for
production identity infrastructure. No independent security audit or protocol
certification has been completed. SAML has an explicit independent-review waiver;
its unresolved assurance findings and outbound OIDC interoperability remain
release concerns. See the [SAML activation policy](docs/architecture/adr/0032-saml-maintainer-directed-activation.md).

## Reporting a vulnerability

Do not disclose exploitable details, credentials or personal account data in public
issues. Use the repository's **Security → Report a vulnerability** action if private
reporting is enabled. If it is unavailable, no alternative verified private
reporting channel is currently documented; do not send sensitive reports through
public channels. A verified private contact and response policy are required
before production adoption. No response-time guarantee is currently offered.

## Handling reports

Maintainers privately reproduce reports, prepare regression tests and fixes,
review affected versions and dependencies, coordinate disclosure, and publish an
advisory when appropriate. Review the [threat model](docs/security/threat-model.md)
and [dependency assessment](docs/research/protocol-dependencies.md) for known
limitations. Recorded tests and CI results establish only their documented scope.
