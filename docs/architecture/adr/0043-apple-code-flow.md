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

The implemented optional backend now composes that signer with exact Apple
discovery/endpoints, client_secret_post and RS256 code-result verification. A
private verifier profile admits Apple's exact boolean/text email flag encodings
and explicitly selected native plain/SHA256-hex nonce convention. Generic/Google
still reject text flags at their original signed-parsing stage and retain S256.
Apple's documented token contract supplies no code_verifier; this new explicit
profile uses signed nonce/code-injection defense and dedicated return/private
state binding, rather than silently switching generic policy after a failure.
No interoperability or general protocol-compliance claim follows.

`AppleAuthorization` aligns the exact transaction and code-component snapshots.
Preparation returns public web form-post/native authorization inputs separately
from original private proof. Completion verifies retained state/actual dedicated
backend route before consuming/cancelling; native delivery itself remains with a
future reviewed OS adapter. First-consent profile is bounded unsigned presentation,
separate from the existing opaque verified identity. Missing later profile is not
an identity failure or a signal to overwrite data. Ordinary routers are unchanged.
Changing client kind/nonce policy requires trusted reconfiguration, a fresh
connection revision and replacement services; never choose it per request.

PostgreSQL's Apple feature only composes existing state/mapping/session ports.
It adds no storage implementation or migration. Owned signed/real-DB tests cover
one-use/private/browser/route binding, code request credentials, no email linking,
JIT denial, returning subjects, realm isolation, concurrent consume/subject commit,
audit rollback, source disable during token I/O and observed final-wait expiry.
These fixtures establish local behavior, not Apple registration/OS/key acceptance.

Required evidence includes fixed-key independent JWT verification, key/window/
rotation controls, signed Apple token negatives, real PostgreSQL isolation and
one-use/concurrency, and actual registered Apple web/native checks. Offline signed
fixtures are not those provider checks. Keep AUTH-24 In Progress until its complete
criteria are evidenced. No PR, merge, deployment or production-readiness claim is
authorized by this design. SAML waiver limits and the outbound OIDC gate remain.
