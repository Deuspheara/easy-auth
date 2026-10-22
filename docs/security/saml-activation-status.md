# SAML activation status

Updated 2026-10-22 for the maintained seven-patch saml-rs source. This is an internal
engineering evidence record, not an independent audit or approval to deploy.

## Implemented and component-tested

- Easy-auth owns the pinned source, MIT attribution, patch inventory and AWS-LC
  dependency graph under ADR 0027. Waiting for an upstream merge is not a blocker.
- The existing backend verifies required signatures and exact algorithm/reference
  policy. Core consumes typed facts from its selected verified Assertion. Configured
  leaf pins/windows, issuer/audience/recipient/destination/time/correlation checks,
  original request caps, durable replay, realm/source/subject ownership and final
  atomic user/session/deletion transactions remain implemented and tested.
- Patch 0005 adds complete ordered scalar attribute records while preserving the
  old aggregate API. Core requires completeness, retains NameFormat/value groups
  and redacts/zeroizes facts. Two signed real-PG scenarios establish exact format
  handling, JIT deny, no email/role linking, subject stability/separation and realm
  rejection. No attribute-selected role/contact/presentation policy is enabled.
- Patch0006 separates established authentication from response issuance using the
  existing writer/signer. Three signed real-PG scenarios establish ten-minute-old
  sign-in authentication/original 24-hour cap, rejection beyond 24 hours, denied
  deletion with ten-minute-old authentication and successful deletion with a
  recent signed two-minute event. Neither verifier nor DB clock is replaced.
- Selected-graph library/core qualification passes 1,115 tests with zero failures or
  ignores across 46 result groups. Existing vectors/tests and original patches are
  retained. The scoped source, compiler, lock/features and count evidence is in
  [the current source receipt](../../tests/provider/saml/rust-policy/results/2026-10-22-consumed-field-policy.json).
  These counts are regression evidence, not 1,115 independent security experiments.
- Previous hosted Keycloak 26.8.1 evidence covers ten rollover/realm cases and eight
  confirmed-deletion cases, including retained-SSO reauthentication. Local new-source formatting, strict default/all-feature all-target Clippy,
  warning-free workspace docs and full workspace suites pass:111 default and 788
  all-feature result counts, including 462 real-PG lifecycle tests under normal
  scheduling. Eleven source/runner checks and exact incremental reconstruction
  also pass. Hosted new-source application/provider/CI receipt is still required; an earlier green
  build is not silently attributed to these patches.

The final static review also added NameFormat and the consumed NameID qualifiers
to the existing unqualified-attribute validator (patch0007), before local-name
projection. This corrects field metadata wiring; it is not a demonstrated bypass
or independent namespace/security approval. Historical six-patch receipts remain
unchanged and are not silently attributed to the new source.

## Mandatory blockers to production activation

1. **Source/profile-scoped XML/signature/backend review is unfinished.** AUTH-32
   still requires review of canonicalization, namespace/ID/reference resolution,
   configured certificate trust, exact algorithms/transforms and binding of every
   consumed field, including the new attribute records, to verified content. The
   quick-xml projection and uppsala/backend trees remain a specific equivalence
   boundary. Internal source inspection and passing existing vectors do not close it.
2. **Documented parser/native resource assurance is unresolved.** Existing XML
   limits and worker admission are implemented, but do not by themselves establish
   a native CPU/memory/concurrent-path assurance claim. Record the assurance
   assessment and any required remaining validation explicitly. No new stress,
   fuzz, resource or signature-concurrency experiment was performed here.
3. **There is no named independent review report, findings resolution or explicit
   security approval decision for this exact source/features/configuration.**
   AUTH-32 requires those records. Agent review, maintainership, CI and owned IdP
   interoperability are separate evidence, not an independent audit. No reviewer
   was contacted and no PR/request was sent.
4. **Normal production composition remains intentionally absent.**
   `apps/auth-server/src/application.rs` and `crates/auth-axum/src/router.rs` do not
   compose SAML. Existing explicit experimental components/examples are available;
   approval alone does not add trusted production configuration or mount an ACS.
   After approval, production composition must select only the approved
   registration/trust/profile and retain TLS, fail-closed configuration, private
   browser binding, current-source and lifecycle policy before activation.

## Limits rather than implied support

The implemented application profile remains persistent NameID, exact configured
IdP/SP namespaces, RSA-SHA256/SHA-256 and the documented short message/session/
freshness limits. Scalar attributes preserve exact text, formats and grouping;
XML-valued/nil data has no complete scalar projection and rejects this profile.
Other NameID/attribute policies, additional IdPs and broader qualified-profile
interoperability are not approved by these tests. Entra/Okta remain documented
integration requirements, not tested providers. These are AUTH-35's broader
feature requirements; they must not be presented as support already delivered,
or as arbitrary prerequisites for every possible narrower approved profile.

AUTH-32 remains In Progress for the approval blockers. AUTH-33/34 implementations
remain release-gated by it; AUTH-35 retains broader provider/profile policy work.
[The evidence review](saml-evidence-review.md),
[ADR 0021](../architecture/adr/0021-saml-verification-and-approval.md) and
[ADR 0028](../architecture/adr/0028-saml-attribute-and-authentication-facts.md)
record scope and the separation between implemented, tested, internally reviewed
and independently approved. Production SAML remains disabled.
