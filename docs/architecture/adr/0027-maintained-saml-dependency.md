# ADR 0027: Maintain the patched SAML dependency in easy-auth

Date: 2026-10-22. Status: accepted maintenance decision; production security
approval remains pending under [ADR 0021](0021-saml-verification-and-approval.md).

## Decision

The easy-auth project owns maintenance and source distribution of its patched
`saml-rs` dependency. The project owner explicitly selected this approach rather
than waiting for upstream patch acceptance. This accepts maintenance responsibility;
it does not assert an independent audit or authorize production activation.

Continue distributing the source at `third-party/saml-rs` in this repository.
No separate repository, registry publication, pull request or upstream/reviewer
contact is required or performed by this decision. Keep the upstream MIT license,
source attribution, packaged vectors and migration documentation. The upstream
repository fields describe provenance; they do not imply that upstream maintains
our changes. Original easy-auth licensing does not replace the dependency's MIT
license or the backend's separate notices.

The maintained revision is identified by the upstream source revision, the exact
patch inventory, the vendored file inventory and the application lockfile. Upstream
package version `0.6.1` alone does not identify our distribution. The root path
dependency selects the maintained source; do not substitute crates.io's unpatched
package. These identities are recorded in `third-party/saml-rs-source.json` and
checked by `scripts/check_saml_source.py`. The three existing patches remain
unchanged: verified-profile extraction, exact RSA-SHA256/SHA-256 policy and complete
XML-document consumption. This decision changes none of their implementation.

The first ordinary maintenance patch, 0004, preserves the typed IdP NameID
qualifiers in the built-in Web Browser SSO producer. It does not modify signature
verification or application identity policy. Successful qualified responses reject
custom templates/hooks rather than silently omit qualifiers. The original import
archive hash remains historical; a separate maintenance patch inventory and the
complete current file inventory identify the extended source. Existing vectors
and the original three patches remain unchanged.

Subsequent patches 0005/0006 add a complete ordered scalar attribute projection
without changing the legacy aggregate API, plus trusted producer authentication
time independent of issuance. [ADR 0028](0028-saml-attribute-and-authentication-facts.md)
records these additive contracts and ordinary integration coverage. Neither
changes the cryptographic verifier or completes independent approval.

Patch0007 also declares every consumed qualifier/NameFormat field in the
existing unqualified-attribute validator. It closes a static field-list omission,
without changing signature verification or claiming a bypass experiment.

## Maintenance and release obligations

Easy-auth maintainers review each proposed source/patch change, retain the previous
provenance and test results, and update the patch/file inventory deliberately.
A dependency update must preserve trusted configured certificates, verified-payload
binding, exact algorithms/transforms, parser limits and the application identity,
request, replay and tenant invariants. No compatibility fallback is introduced.
Retain upstream tests and the existing security regression corpus.

Every proposed distribution must pass the source inventory, existing upstream
regressions on the selected core SAML dependency versions/features, ordinary
application/real-PostgreSQL/provider checks and unsuppressed compiled-graph
advisory/license policy. Native backend and license changes receive explicit review.
A source update invalidates prior source-scoped security approval; do not infer
approval from the upstream version number or from an earlier green build.

Run `python3 scripts/qualify_saml_dependency.py` for unchanged upstream tests and
core SAML tests. It stages a disposable workspace, admits the vendored package as
a test member, preserves the tracked Cargo configuration/test-worker budget,
starts from the application lock and verifies equality of the selected core SAML
normal/build package versions and features before testing. Cargo resolution
may add inactive optional entries for the additional workspace member; the actual
application lock and source are never modified. Tests then run locked with only
the selected AWS-LC path. Reports contain finite counts and provenance, never XML,
keys or arbitrary panic output. This is regression evidence, not independent review.

## Activation remains a separate decision

Ownership and maintainer acceptance no longer depend on an upstream merge.
[The security evidence review](../../security/saml-evidence-review.md) distinguishes
completed tests, internal source review and unresolved assurance requirements.
Independent review, findings resolution and an explicit source/profile-scoped
production decision remain required by ADR 0021. Attribute-selected identity policy,
qualified profile support and other IdPs gain no implied support from this decision.
Normal server/router SAML remains disabled until the mandatory gates are satisfied.
