# Independent security review plan

This is preparation for AUTH-50, not a commissioned or completed review. No
reviewer has been contacted, no review date is booked and no independent approval
is claimed. The owner deferred real provider/OS/production verification. Scheduling
and any external disclosure require an explicitly authorized later step.

## Review input and scope

Freeze an exact proposed release commit and its selected feature/build profiles
before review. Record the source archive hash, toolchains, resolved dependency and
native-library inventories, SBOMs, deployment artifacts and all reproduction
commands. A changing development branch is not a review target. The current local
benchmark receipt does not select a release or supply provider acceptance.

Provide the existing [architecture](../architecture/overview.md),
[domain model](../architecture/domain-model.md), [API contract](../architecture/api-contract.md),
[threat model](threat-model.md), [protocol validation matrix](protocol-validation-matrix.md)
and [control-to-assertion review](threat-control-review.md). The reviewer should
trace the actual execution/transaction boundaries and challenge those claims,
rather than treating green tests or those documents as approval.

Scope the review across:

- Ownership and realm isolation; account/session/identity separation, no email
  linking, source-bound authorization, credential lifecycle and recovery downgrade.
- Database lock order, final deadline/source checks, one-use proofs and atomicity
  under concurrency, cancellation, rollback, incident restoration and maintenance.
- Browser Origin/cookie/CSP boundaries, deliberate cross-site handoffs and account
  switching; actual endpoint/body/time limits and absence of credential logging.
- Password KDF admission/cancellation, shared database abuse budgets, application
  and ingress resource bounds, bounded metrics cardinality and failure behavior.
- OIDC discovery egress, issuer/audience/nonce/code/PKCE binding, native delivery,
  signing-key rotation, refresh reuse, introspection and independent client limits.
- Apple grant custody/revocation, local versus remote erasure and worker leases;
  real registered-provider behavior remains separately unperformed.
- SAML maintained parser/signature/verified-content boundary, exact conditions,
  replay, certificates, native build provenance and the supported-profile limits.
- Resolved dependency/license/advisory findings, native packages, source/build
  provenance, protected configuration and the actual proposed delivery artifacts.

## Entry conditions and evidence treatment

Keep AUTH-47/48/49 prerequisites and the hard outbound OIDC release gate visible.
Select representative authorized disposable environments and synthetic identities.
Document what the reviewer may exercise and what is excluded. Never disclose real
accounts, provider credentials, private keys, retained previews, private research
or internal tracker/workspace content in an external packet.

For each area, distinguish implemented control, locally executed test, real
provider/OS observation, operator procedure and unperformed independent review.
Use exact source/image evidence; stale or inherited results retain their original
scope. Record every unavailable environment and failed assertion. The local
[performance workload](../guides/authentication-performance.md) has small closed-loop
samples and process-lifetime RSS, not a production-capacity or timing-security
claim. Supply its limitations and unresolved questions with the numbers.

## Findings and acceptance

Require findings to identify affected source/profile, attack preconditions,
reproduction, impact, severity rationale and remediation or explicit disposition.
Track each finding in the primary tracker without publishing sensitive exploit
material or credentials. Maintain a public sanitized limitations record separately.
Reproduce fixes and request reviewer retesting on the actual changed commit;
changing a test to accept insecure behavior is not remediation.

The owner must make any release/redistribution decision after the actual gates,
review scope, unresolved findings and retest evidence are known. This plan chooses
no automatic acceptable-severity threshold and grants no release exception.
ADR0032's SAML maintainer waiver remains a waiver of independent review, not its
completion. Neither this plan nor any benchmark establishes production readiness,
protocol compliance or independent security approval.
