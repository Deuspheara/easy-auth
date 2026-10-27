# ADR0046: Default container inputs and independent client examples

Date: 2026-10-26. Status: accepted; bounded local implementation validation complete.

## Context

AUTH-45 requires reproducible container instructions, a concrete backup procedure
and minimal public Rust/TypeScript integrations. The root Dockerfile admitted a
working directory with broad `COPY . .`; its default runtime also carried shell,
curl and unrelated Debian utilities. The first owned image scan found one critical
and 69 high OS-package findings with the existing unsuppressed scanner policy.

## Decision

Build a committed-source export. Use a deny-by-default context allowlist and named
Rust input copies, admitting only source/manifests/configuration and shipped license
notices. An actual scratch/local-export regression uses owned ordinary text markers
to prove required inclusion and unrelated/private-file exclusion without reading
or executing the owner's private files. Filtering does not replace source review.

Use the existing pinned Rust 1.95 trixie builder and nonroot Debian 13 distroless
runtime already used by the maintained release. The default binary still has its
default feature graph; this does not enable SAML, providers, passkeys or the issuer.
Removing shell/curl shifts image health checks to actual external HTTP probes of
`/healthz` and `/readyz`. A running container alone proves neither readiness nor
SMTP/provider delivery. Reassess the resulting exact image; no advisory suppression
or independent security approval is introduced.

The disposable local Compose profile keeps development bind and SMTP strictly
loopback. App and a separately constrained proxy share Mailpit's private network
namespace. A fixed local HTTP nginx configuration forwards to the app's loopback
listener; only host 127.0.0.1 ports are published, with no host-network mode or trusted
forwarded identity/IP. Reuse the maintained nginx runtime with a read-only local
configuration rather than duplicate a proxy build or weaken production TLS policy.
This profile is development-only and has no registry/public deployment step.

Provide one independently locked, unpublished Rust HTTP probe outside the auth
workspace and one small typed browser fetch module. The concrete consumer example
is not a new authentication library/micro-crate or a replacement SDK. It proves
public HTTP health/readiness and absence of ambient browser authority. Existing
embedding and OIDC RP/native SDK examples retain their own contracts and release
gates. The browser module uses same-origin cookies and genuine public APIs, with
no framework, persistent secret storage or automatic completion retries.

Document protected PostgreSQL custom archives and restoration into a newly created,
quarantined database. Production recovery, key loss/rotation, revived credentials
and side effects remain separate AUTH-49/operational acceptance. Keep sensitive
archives outside repositories/build contexts; never restore over the running DB
as part of the documentation smoke test.

## Validation and consequences

Require a fresh owned Docker project, actual database migration/SMTP/browser
completion, independent Rust client, TypeScript session/logout, missing-Origin
refusal and normal scoped cleanup. Record the original loopback-bind startup
failure and failed image scan alongside corrected results. Run exact image
advisory and independent consumer dependency/license checks, backend required gates
and website publishing/link checks. Preserve SAML waiver limits and the outbound
OIDC release gate. This decision makes no production-readiness or conformance claim.

The [source-scoped verification record](../../security/container-client-verification-2026-10-26.md)
records the actual committed-source builds, client/SMTP/backup smoke, exact image
assessment, required repository/website checks, original failures and remaining
release obligations. These local results do not establish production acceptance.
