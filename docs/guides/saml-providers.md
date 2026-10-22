# Gated SAML provider acceptance

This is configuration and acceptance evidence for the experimental component,
not permission to activate production SAML. [The component guide](saml.md) and
[ADR 0021](../architecture/adr/0021-saml-verification-and-approval.md) retain every
mandatory dependency, XML/backend and independent-approval gate. Normal server
startup exposes no SAML provider.

| Provider/profile | Evidence | Remaining boundary |
| --- | --- | --- |
| Keycloak 26.8.1, pinned image, persistent NameID, unsigned Redirect request, signed POST Response and Assertion | Ten sign-in/rollover and eight confirmed-deletion browser/PostgreSQL cases passed on macOS arm64/Chromium156 | Other profiles/platforms, actual-provider older-authentication profile coverage, explicit qualified NameID/attribute acceptance and independent approval |
| Microsoft Entra enterprise SAML | Official configuration reviewed; no tenant/account exercised | Documented lifetime policy conflicts with the current five-minute signed-validity ceiling; no compatibility or production-support claim |
| Okta SAML application integration | Official field reference reviewed; no org/account exercised | Exact profile/time/qualified identity, rollover and lifecycle need actual acceptance; no interoperability claim |

## Keycloak: observed profile

The owned [acceptance suite](../../tests/browser/saml-keycloak/README.md) uses the
existing official Keycloak image pinned by digest, real username/password login,
real SAML POST, the unchanged concrete verifier and PostgreSQL grant. No XML is
edited and no verification result/proof/local authority is fabricated. Public
certificates come through owned administration and explicit approval, not callback
KeyInfo or untrusted remote metadata.

Configure the SAML client ID as the exact SP entity, its allowed return and POST
consumer URL as `{origin}/saml/acs`, and require persistent NameID with format
forcing. Enable both document and Assertion signatures, RSA-SHA256 and exclusive
canonicalization. Enable AuthnStatement and POST binding; set assertion lifetime
to 180 seconds. The supported request is explicitly unsigned Redirect; encryption,
artifact, SLO and IdP-initiated grants are not supported. These settings use the
[Keycloak administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html)
and [26.8.1 SAML configuration names](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/saml/SamlConfigAttributes.java).

The suite first confirms no grant under default-deny JIT, then explicitly allows
it. Normal provider key rotation fails against the old-only pin set, succeeds with
approved old/new overlap, accepts the still-enabled original signer during that
overlap, and succeeds with new-only pins. Changing source revision invalidates
older sessions. The exact persistent subject resolves the same owner across these
changes, including after returning to JIT deny. Two realms with identical local
connection/client and IdP/SP entities resolve that same subject to distinct owners.
Disabling one source leaves the other usable. The record contains only finite
outcomes, version/source hashes and aggregate counts.

The six grants also retain actual signed authentication time and the stricter
signed SessionNotOnOrAfter bound through PostgreSQL; the session lifetime is
distinct from short admission expiry. This covers the provider's actual normal persistent-subject output. It does not
establish all explicit NameQualifier/SPNameQualifier cases or lossless qualified
attribute extraction for all actual provider profiles. Maintained scalar
NameFormat/value-group projection and ordinary old-authentication wire scenarios
are now implemented and component-tested under
[ADR 0028](../architecture/adr/0028-saml-attribute-and-authentication-facts.md),
separately from this actual Keycloak evidence. Attribute-selected policy remains
unsupported; attributes cannot choose ownership, contact, roles or account linking.

Purpose-bound deletion preparation is implemented separately, with an actual
initiating SAML session and retained original caps. The separate gated core/PostgreSQL
verification/erasure and explicit HTTP confirmation services are implemented;
eight actual Keycloak/Chromium cases now cover signed return, no erasure before
second confirmation, wrong phrase, cancellation, real different-subject rejection,
exact-subject local erasure/replay retention and remote-account preservation.
The retained-SSO case obtains a real password challenge and a newer signed
AuthnInstant without clearing provider SSO cookies; its proof is observed only
around unchanged production completion.
ForceAuthn intent alone establishes no freshness. See
[ADR 0025](../architecture/adr/0025-saml-account-deletion.md) for the implemented
boundary and remaining approval work. These are separate from the ten sign-in
cases and do not establish older signed authentication-time wire rejection.

## Microsoft Entra: documentation only, lifetime incompatibility

For a future registered enterprise application, the Identifier must equal the
configured SP entity, Reply URL must equal the exact ACS, and trusted issuer/SSO
values must come from that application's administrative configuration. Require both
Response and Assertion signing with SHA-256; Microsoft documents that combined
[signing option](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options).
Its [SAML protocol contract](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol)
supports persistent pairwise NameID. Do not substitute email/unspecified format or
accept a matching email as ownership.

A concrete incompatibility remains. Microsoft documents a one-hour SAML default,
a ten-minute minimum for its configurable lifetime policy, and an extra five-minute
factor on Conditions expiry. Subject-confirmation expiry is separate. See
[configurable token lifetimes](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes).
**Inference:** that documented policy cannot satisfy this library's current maximum
signed validity of 300 seconds from Assertion issuance. A short local request cap
does not by itself change that signed condition. Do not claim that a five-minute
Entra setting exists or silently relax the verifier/time policy. A separately
reviewed compatible profile/architecture decision and actual tenant evidence are
required. These enterprise-app observations do not describe B2C/custom-policy
products.

Any future certificate rollout needs explicit current/next leaf approval and
windows within real validity, fresh source revision, rejection before approval and
fresh sign-in/session checks afterwards. No automatic trust in downloaded metadata,
inline certificates or a platform root bundle is introduced. No Entra tenant was
contacted or production activation attempted in this session.

## Okta: documentation-only operator checklist

The [SAML application field reference](https://help.okta.com/en-us/content/topics/apps/aiw-saml-reference.htm)
describes POST SSO, recipient/destination, SP audience, NameID and independent
Response/Assertion signature settings. A future integration must use the exact ACS
for return, recipient and destination; exact configured SP entity for audience;
persistent NameID matching the request policy; both signatures with RSA-SHA256 and
SHA-256 digest; and an unencrypted Assertion. An immutable subject, not email,
must remain the identity key.

Leave application default RelayState/return overrides out of the sign-in flow:
return the initiating opaque RelayState unchanged. Do not enable IdP-initiated,
SLO, encrypted/artifact or custom inline-hook behavior as a fallback. Explicitly
verify real issuer, request correlation, actual signed time bounds and session
age, qualifier behavior, pin rollout and disable before recording support. This
is the library's required profile/checklist; the field documentation alone does
not prove every requirement is attainable in a particular Okta org. No org was
accessed. Keep actual acceptance and independent approval open.
