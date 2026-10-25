# ADR 0043: Explicit Apple code-flow boundary

Date: 2026-10-25. Status: implementation in progress for AUTH-24. No Apple
activation, registered-provider acceptance or independent security approval.

## Context

Apple needs a separate provider profile, not another issuer spelling in Google's
profile. Its [published discovery](https://appleid.apple.com/.well-known/openid-configuration)
advertises RS256 identity tokens and client_secret_post. It advertises neither
S256 nor authorization-response issuer support. Do not relax the generic or
Google requirements to make that metadata pass. Apple-specific web/native
request, nonce, callback and token rules need explicit implementation and tests.
No unsupported PKCE/native interoperability claim follows from sending parameters.

Owner directed Apple engineering before unfinished Google/manual qualification;
the AUTH-23 dependency and its unresolved acceptance are retained. This permits
engineering against the implemented shared primitives, not release or activation.

## Signing keys and client secrets

Reuse pinned josekit0.10.3/OpenSSL; add no cryptographic primitive or dependency.
The optional core Apple feature owns cohesive key, fixed-payload signing and
provider modules. Trusted operator composition supplies one protected PKCS8 P-256
private key, explicit key/team/client identifiers and a finite validity interval.
Do not load keys from requests, accept other formats/curves, infer identifiers,
expose private projections or supply a default/fallback key. Selecting a replacement
means constructing a new explicit signer; failure never retries a retired key.

Apple's [client-secret contract](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret)
requires ES256 and fixed team issuer, client subject and Apple audience. Issue
short-lived five-minute secrets, capped by the operator's key window, rather than
caching six-month credentials. The authoritative operation clock must be supplied
by the calling use case; issuance time never proves provider authentication age.
Only fixed claims can be signed. Bound blocking work and keep its permit alive
through cancellation. Raw input/output buffers zeroize on owned drop; native-library
copies are not claimed erased. Errors and Debug never include key/JWT/parser data.

## Identity and transaction boundaries

Retain the existing realm/source/client/revision/purpose/private-browser/one-use
state and original final deadlines. Exact issuer, configured App/Services ID and
initiating nonce must survive exchange and actual RS256 verification. Native
nonce convention and web nonce must be explicitly selected by trusted composition,
never inferred from an uploaded token. Callback delivery cannot grant authority.
First-consent name/user data is untrusted presentation, not signed identity. Relay
email and verification flags never become local contact or email-based linking.

Reuse existing verified/mapped proof and PostgreSQL commit boundaries only after
the Apple profile establishes its required facts. No public proof constructor,
generic provider framework, persistence policy in handlers or weakening of existing
claims/PKCE/cookie checks is permitted. Provider grant custody/revocation remains
the separate AUTH-26 scope; ordinary activation cannot strand provider-only users.

## Evidence and remaining work

Required evidence includes fixed-key independent JWT verification, key/window/
rotation controls, signed Apple token negatives, real PostgreSQL isolation and
one-use/concurrency, and actual registered Apple web/native checks. Offline signed
fixtures are not those provider checks. Keep AUTH-24 In Progress until its complete
criteria are evidenced. No PR, merge, deployment or production-readiness claim is
authorized by this design. SAML waiver limits and the outbound OIDC gate remain.
