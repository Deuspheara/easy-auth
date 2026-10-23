# ADR 0032: Maintainer-directed opt-in SAML activation

Date: 2026-10-23. Status: accepted maintainer release-policy decision.

## Decision and assurance status

The project maintainer explicitly directed activation without obtaining the
previously required independent review. Supersede the mandatory independent-review
prerequisite and unconditional startup/proxy lock in ADR0021, ADR0029 and ADR0031.
This is a maintainer waiver, **not completed independent review, an audit,
certification, general protocol compliance or a finding that all risks are closed**.
No independent reviewer, report or security approval is invented. Earlier packets
and CI receipts retain their original source, disabled-state and assurance scope.

Permit the normal standalone/embedded SAML router only when compiled with
`saml-web`, explicitly configured with `AUTH_SAML_ENABLED=true`, served through
HTTPS, and backed by the exact already-provisioned enabled registration, matching
JIT policy and currently active operator-approved certificate pins. Missing,
disabled, mismatched or expired trust fails closed. Startup does not provision,
rotate pins or re-enable a source. `configured_auth` still refuses provider
settings: consumers must use `configured_application` to mount the real router.

No approval environment variable is introduced. Unset configuration or only
`AUTH_SAML_ENABLED=false` keeps routes/schemas absent. Mixed disabled settings,
unknown keys and partial settings remain errors. JIT remains deny by default.
The dedicated release compiles SAML; Compose remains opt-in and forwards SAML
through the existing bounded TLS upstream when configured. No live provider,
production domain, credentials or deployment is created by this decision.

## Preserved requirements

Keep all eleven maintained patches, source pin, AWS-LC-only verification,
RSA-SHA256/SHA-256/reference/C14N policy, exact signed-payload binding, both issuers,
audience/recipient/destination/time/correlation checks, durable replay,
realm/current-source isolation and atomic user/session/deletion lifecycle.
Keep leaf-pin validity/approval windows, minimum RSA size and rollover bounds.
No verifier change, compatibility fallback, test-fixture generation or migration.

Keep deployment limits and unsuppressed dependency/image advisory gates. The
previous image scan found no high/critical entries but31 app/33 proxy medium/low
rows (27 distinct CVEs). Those observations belong to the recorded images and
scanner database, not future rebuilds. Rebuilds need their own scan/provenance.
Parser/C14N/reference review sufficiency, native/advisory applicability, selective
schema validation and unmeasured CPU/RSS/duration/availability remain documented
assurance limits. Native timeouts cannot kill a blocked verification task. The
maintainer chose to proceed without the independent assessment of these residuals;
this does not establish that they are harmless or independently accepted.

## Verification and delivery

Update only the obsolete closed-gate assertions to the documented opt-in contract;
retain all protocol/security tests. Exercise normal and embedded configured startup,
stable revision/no authority creation, no-feature/disabled/partial refusal, wrong
realm/registration/issuer/JIT refusal, operator disable and missing/expired pins
using owned PostgreSQL and existing public certificates. Run standard Rust, real
DB, existing provider/browser, source, secret and advisory checks. No new custom
adversarial XML/crypto, fuzz, stress or signature-concurrency experiments.

Record current test/CI results with the new source. Never transfer earlier
source-disabled receipts to enabled behavior. The unsent independent-review packet
remains available for a future review; lack of that review is disclosed rather
than relabeled as success. No PR, registry publication or human/upstream contact.
