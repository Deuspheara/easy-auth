# ADR 0031: Finalize the gated SAML profile and reference release deployment

Date: 2026-10-23. Status: accepted project engineering contract; independent
security approval and production activation remain pending under ADR 0021.

## Profile

Use the existing SP-initiated unsigned Redirect request and HTTPS POST response
profile. Require trusted exact IdP/SP entities, ACS/destination/recipient, original
request correlation, both authenticated Response-root and selected-Assertion
coverage, persistent NameID, complete scalar attribute projection, strict time
checks, durable realm/source-scoped replay and the existing atomic lifecycle.
Leaf DER pinning, approval/validity windows, RSA minimum 2048 bits and bounded
two-pin rollover stay unchanged. No PKI-chain, revocation or EKU claim is added.
JIT defaults to deny; email/attributes grant no linking or application permissions.

Keep the behavior-preserving issuer-policy extraction in patch0010 separate from
patch0011, which changes the configured login contract. Maintain patch0011: when the inbound flow has an expected issuer, both the login
Response Issuer and selected Assertion Issuer must be present and equal that IdP.
The existing `issuer` extraction remains Assertion-scoped; the additive
`responseIssuer` field is envelope-scoped. A private `flow/issuer.rs` owns policy;
the existing signature/backend checks and verified-view binding are unchanged.
Other message issuer contracts and flows without an expected issuer retain their
previous behavior. This deliberately narrows accepted configured login responses:
[OASIS Profiles §4.1.4.2](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
permits omission of the Response Issuer; this project profile requires it. Missing
issuer rejection is a project contract, not a claim that every SAML response must
include it. Existing library tests/fixtures are retained; new issuer unit cases use
ordinary extracted values, without XML, keys, signing or bypass experiments.

Finalize the current canonicalization contract without changing its algorithms:
SignedInfo uses exclusive C14N without comments; accepted authenticated signatures
use RSA-SHA256/SHA-256 and plain same-document ID references. Explicit reference
transforms are restricted to enveloped-signature/exclusive C14N. If no explicit
reference C14N is present, retain Bergshamra0.9.2's inclusive XML1.0 default without
comments. Its supported fast/generic processing paths remain in review scope.
[XMLDSig reference processing](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel)
defines implicit node-set canonicalization; this decision records the actual
selected implementation, without asserting general conformance. Explicit
reference C14N is not newly mandatory and no broader algorithm is enabled.

XML1.0, no DTD/entities, strict namespace/selectors, parser-view/range/value binding,
selected NodeId coverage, all-Assertion constraints and unsupported-feature
rejections from ADR0030 remain mandatory. Support is limited to the recorded
Keycloak/owned component profile, not Entra/Okta, encrypted assertions, unsolicited
login, SLO, Artifact, dynamic trust or compatibility crypto selection.

## Reference release and operational budget

Use the dedicated `deploy/saml/` build, independent of the default root Dockerfile.
Rust1.95.0 and Debian13 Trixie base indexes are pinned by digest. Build the existing
release profile with only `saml-web,oidc-web`; normal SAML remains source-disabled.
Run existing selected-graph SAML/core/C14N tests inside the native build environment.
Use pinned distroless Debian13 final images without a shell/package manager; retain
only the application/proxy and required runtime libraries and their package/license
records. Runtime packages and native libraries are inventoried from the actual image, with
separate image/binary/source/lock identities and unsuppressed advisory results.
APT security revisions are recorded, not falsely described as bit-reproducible
floating package inputs. A rebuilt image needs a new artifact receipt and checks.

Compose defines one app process and one proxy. App: 2 CPUs, 1GiB memory with equal
memory+swap limit, 128 PIDs and 1024 file descriptors. Proxy: 0.5 CPU, 128MiB memory
with equal memory+swap limit, 64 PIDs and 512 descriptors. Both use non-root UID/GID
65532, read-only roots, dropped capabilities, no-new-privileges, init and bounded
16MiB `/tmp` mounts. Docker inspection must confirm actual enforcement settings.
These are selected candidate limits, not measured capacity or approved budgets.

The proxy enforces body/connection/request-rate/inactivity limits, exact configured
hostname and TLS1.2/1.3, and explicitly blocks SAML routes. The app's source gate
independently rejects complete activation before database I/O. Existing body/XML
limits and two retained process permits remain. No hard per-signature cancellation
or worst-case CPU/RSS/duration guarantee follows from timeouts. Container stop has
a 30s grace period; any forced kill affects the process, not one native task.
Replicas, proxy overrides, embedding and other provider work require a separately
recorded deployment budget. Do not extend this reference's scope silently.

## Review and delivery boundary

Keep normal SAML disabled in image defaults, Compose, proxy and production source.
Do not expose a feature/env/approval override. Credentials, TLS keys, public domain,
database/SMTP destinations and operational approvals belong to the deploying
operator; none is invented or published with this reference. No running public
deployment or registry publication is part of this change.

The review packet must freeze the actual source/features, release artifacts,
package/advisory state, configured limits, regression receipts and remaining
SR-1–SR-4 questions. Independent review can use existing evidence with an explicit
applicability rationale; a new adversarial/resource campaign is not implicit.
Reviewer identity/independence, findings dispositions, report and explicit approval
remain mandatory. Activation follows only as a separate reviewed source/config
change and enabled-path verification. No PR or human/upstream contact is required
or performed to prepare these artifacts.
