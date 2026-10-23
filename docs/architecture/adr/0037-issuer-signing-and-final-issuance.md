# ADR 0037: Issuer signing and final issuance

Date: 2026-10-23. Status: accepted optional crate implementation for AUTH-39.
Key registry, concrete signed issuance, HTTP transport, bounded in-process RP/
rollover and owned HTTPS browser/client cases are implemented and locally verified.
Exact-source CI is recorded separately in the tracker; no earlier source receipt
qualifies this increment. Normal server activation and outbound release approval
remain separate gates. See [the local receipt](../../security/issuer-signing-verification.md).

## Dependency and key boundary

Reuse the pinned josekit0.10.3/OpenSSL implementation selected in ADR0015, with the
same lockfile, license notices and unsuppressed advisory policy. The first issuer
profile is explicitly RS256. No token-selected algorithm, HMAC/unsecured alternative,
custom signature implementation or generic crypto-provider interface is introduced.
The earlier inbound dependency review is source evidence, not an independent audit
of this new outbound use.

`IssuerSigningKey` accepts trusted bounded PKCS8 PEM operator input with a deliberate
non-nil key UUID. It admits one unencrypted RSA private-key block only; it does not
invent, generate or silently convert configuration into another key type. Native
OpenSSL checks the actual private key after2048–8192bit/component bounds. Input text
is zeroizing; native dependency copies are not claimed erased. No raw private
projection, Clone, serialization or arbitrary-payload signing API is exposed.
The server library's optional `load_issuer_signing_key` loads a trusted operator
path using Unix NOFOLLOW/NONBLOCK, then checks the opened regular file, owner-only
permissions and16KiB bound. Paths/native errors never escape. Trusted composition
must control parent directories and storage ownership; this is no secret manager,
ACL audit or protection against a compromised process. Non-Unix loading fails
closed. The memory constructor alone cannot establish at-rest protection.

Only an explicit allowlisted public JWK projection can leave the private key type.
Public metadata requires exact canonical UUID kid, RSA/RS256/sig/verify, bounded
canonical unsigned n/e and a32bit ordinary odd exponent. Raw JSON admission rejects
duplicate fields before map conversion, private/unknown members and certificate/key
URLs. The metadata alone grants no signing authority and must match the current
protected private key before use. Key IDs must not be reused with different material.

## Registry and lifecycle

A realm/issuer-scoped persisted public-key registry retains full revisions,
operator disable and explicit active selection. Migration0030 stores public material only. Bound
live publication to four keys. Prepublish replacement keys for300seconds before
activation; only the initial bootstrap has no preceding cached set. Preserve operator
disable on reconfiguration; never fall back to an old key if the selected private
material is absent or mismatched. Keep retired public keys for at least the maximum
300second token lifetime after their signing window; reconfiguration cannot shorten
already-promised retention. All windows use the database clock. A persisted
readiness deadline restarts when a disabled key is re-enabled or an expired public
publication is reopened, including the same selected key ID. Current loading and
explicit enable/activate all require readiness; only the first namespace bootstrap
can set an immediate deadline. Reaffirming uninterrupted live publication preserves
its matured readiness. Live capacity also
applies to re-enabling/reopening keys; a previously active key cannot be replaced
by reusing its identifier with different material. Global issuance disable keeps
retained public verification keys available. Emergency per-key disable removes
that key from current JWKS; consumers may retain older cached snapshots.

Public metadata and a loaded current snapshot are configuration facts. Preparation
releases all SQL locks before native signing. Only the concrete core signer can
construct `IssuerSignedCode`; it exposes no raw token to the persistence adapter.
The final transaction rechecks the exact current client/key revision, original
source/owner/session/code tuple, PKCE/actual URI, whole original code snapshot and
all caps. It inserts a hash-only distinct access credential, consumes/scrubs the
code and records typed audit before the last database-clock check and commit.
Migration0031 binds ledger rows to that complete code-owner tuple and public key;
erasure cascades rows. A previously redeemed opaque code result is not signing
authority. Any failure rolls back all final writes and returns no staged token.

Claims fix exact issuer, client UUID audience, stored pairwise subject, nonce,
iat/exp and original auth_time. Issuance never claims fresh authentication or MFA.
Expiry is conservatively clipped to the original code/session/freshness and key
windows plus the300second policy maximum, rounded down to a whole second. Thus
the current60second code cap also bounds tokens. The final check requires at least
one second remaining. Two cancellation-safe native leases and a15second operation
timeout bound work; no custom signature-concurrency experiment establishes this
as a load or scheduling guarantee.

## Optional protocol composition and evidence limits

`issuer-web` composes the existing consent delivery with exact HTTPS root-issuer
discovery, public-only JWKS and an8KiB closed form token POST. Basic authentication
decodes form-encoded components, checks canonical client identity and rejects
conflicting body identity or duplicate fields. Public clients require explicit
body identity. There is no cookie fallback or browser Origin requirement for this
client endpoint. The server must provide actual `ConnectInfo<SocketAddr>`; missing
peer information fails closed and forwarding headers cannot select admission.
Other local cookie endpoints retain the existing Origin boundary. Errors distinguish
invalid_client, invalid_grant, invalid_request, unsupported_grant_type and temporary
failure; no-store/no-cache and sanitized finite envelopes apply.

Real PostgreSQL cases cover registry/propagation/overlap, ordinary sequential signed
rollover, one-use issuance, policy changes, final expiry/audit rollback, erasure and
historical upgrades. HTTP cases cover actual local email consent and public/Basic/
native token posts. The existing inbound RP uses real PostgreSQL transactions and
actual issuer discovery/form/token/JWKS responses through a test-only in-process
transport. Unaltered production tokens are refused for individually wrong audience,
nonce and configured algorithm. This shares the josekit verifier: it establishes
bounded internal integration, not independent conformance, real DNS/TLS transport
or acceptance by an external RP. Owned HTTPS Chromium consent and a separate
cookie-free Node HTTPS client also pass: the client explicitly trusts the private
fixture certificate, retains hostname verification and verifies the unchanged RS256
token with Node crypto and fixed claims. Broader interoperability remains work.
Use reviewed implementations, ordinary production outputs and existing
established fixtures; no adversarial XML/cryptographic producer, bypass/fuzz/stress or
signature-concurrency experiment is authorized. Production operations remain under
maintainer supervision. SAML ADR0032's review waiver is not an independent audit or
outbound issuer approval. M07/full token interoperability gates remain open.
