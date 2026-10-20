# Experimental OIDC identity mapping and JIT

The core/PostgreSQL `oidc-identities` features add local provider identity resolution
after the [transaction-bound verifier](oidc-verification.md). They enable no public
callback route or ordinary server configuration. AUTH-30's backend boundary has
passed local and hosted acceptance; provider linking/unlinking is AUTH-25 and
stronger-account recovery gates remain open.
[ADR 0016](../architecture/adr/0016-oidc-identity-mapping.md) records policy.

## Trusted setup

Configure one exact issuer per persisted realm/connection/local-client. The trusted
tenant issuer allowlist is explicit, bounded to eight and compared exactly. It never
permits an incoming token to choose an issuer, tenant, callback or owner. Multi-tenant
use requires separate exact-issuer configurations/services; no wildcard/common issuer
template, dynamic tenant discovery, groups or application permission mapping exists.

```rust
let input = OidcIdentityPolicy::new(
    connection,
    &["https://issuer.example"],
    OidcDisplayNameClaim::Name,
)?.with_jit(OidcJitPolicy::Allow); // Deliberate administrative opt-in.
let policy = repository.configure_oidc_identity_policy(&input).await?;
```

Deny is the default; choose Allow only through trusted configuration. Construct the
OAuth transaction, document/code exchange and token verifier from the **returned**
configuration. Every policy application allocates a new revision and cancels prior
pending state, retaining disable. Reapplying on restart also invalidates existing
provider sessions; do not promise restart-preserved sessions with this API. Explicit
re-enable requires the latest returned configuration. Never expose these methods to
browser request input or restore an old revision after disable.

## Resolve a verified callback

Complete real state/browser/purpose checks, original S256 code exchange and mandatory
ID-token verification first. Then consume the opaque verified identity:

```rust
let mapped = policy.map(verified_identity)?;
let (user, session) = OidcSignIn::new(repository.clone()).finish(mapped).await?;
```

Only a successful committed result returns the local session secret. Handle it via
protected application transport; never log or put it in a URL. A lost finish response
requires a new provider flow. Opaque proofs cannot be cloned/serialized or reconstructed
from callback JSON. Linking-purpose proofs are rejected by both core and PostgreSQL.

Deny rejects a new subject, but permits an already-bound subject under current policy.
Allow provisions one owner per exact realm/connection/local-client/issuer/subject key.
Concurrent distinct valid proofs for the same subject resolve one user and may each
issue their own session. Subject and issuer comparisons remain case-sensitive regardless
of database locale. Changing issuer never transfers a matching subject to another owner.
Provider email, even asserted verified, never selects/merges a mailbox account or becomes
verified local contact. New users have null email and explicit provider_required policy.

Display selection is only initial presentation: sub, name or preferred_username, with
no email/alternate fallback. New owners require a usable selected field (nonblank,
control-free, at most 256 UTF-8 bytes). Existing users keep stored display metadata and
can sign in if the provider omits it. `OidcMappedIdentity::display_name()` returns an
optional candidate; its presence alone grants nothing. No UserInfo fetch is introduced.

## Session authority and lifecycle limits

Provider sessions record genuine oidc method, exact identity ownership and configuration
revision. Validation checks current enabled source and account policy before touching
idle state. Disable/reconfiguration invalidates old sessions; re-enable does not restore
them. Existing in-flight operations may commit before a waiting disable, after which
subsequent session validation fails.

Authentication time is the signed optional auth_time, never iat or local session creation.
Missing time appears as null in inventory; old time remains old. Reads can succeed while
fresh sensitive operations reject. A genuine recent time can authorize existing owned
session revocation. amr/acr are not local passkey/MFA or application-permission authority.
Logout can dispose of an owned bearer even if its provider source is disabled.

Provider-required users do not acquire mailbox/password, passkey sign-in or saved-code
passkey recovery fallback, even if trusted storage later has verified contact. No public
provider contact attachment, policy transition or provider-only deletion endpoint is
provided here. AUTH-55 owns provider-only deletion; AUTH-56 owns supported embedded
and standalone OIDC web composition and depends on that lifecycle boundary.
Ordinary provider activation and complete first-release lifecycle remain
separate gates. Applications must not fabricate contact or weaken policy to work around
an unavailable lifecycle operation.

Deletion cascades external identities and sessions and installs a scoped five-minute
cooldown. A vanished existing owner cannot fall through to JIT; original proofs remain
capped. Fresh flows during cooldown also reject; after expiry a new flow may create a
new UUID. Cooldown stores no raw subject/user reference, but its hash is pseudonymous
metadata. Expired hashes are pruned opportunistically in bounded batches on new-user
JIT; this is not an autonomous five-minute retention guarantee. Device/provider-side
credentials, backups and audit timing have independent retention policies.

## Errors and evidence

Unauthorized covers invalid/stale/disabled configuration or proof, JIT/mapping denial,
wrong purpose/ownership and expired authority. Unavailable denotes storage/infrastructure
failure; RateLimited remains the bounded OAuth/verification admission outcome. Never treat
any error as an expected authorization rejection. No SQL/provider payload appears in the
public failure. Failed identity/session/audit writes roll back together without reviving
consumed OAuth state. No database lock spans provider I/O or signature verification.

Use [verification evidence](../security/verification.md) for exact test commands and
limits. Signed software fixtures are not live-provider interoperability or an independent
security review. No conformance, MFA/AAL certification or production-readiness claim is made.


The [owned Keycloak acceptance](../../tests/browser/oidc/README.md) now runs nineteen
cases, including actual local JIT/session commits, matching-email separation, signed
missing-profile login, new-subject denial and live held-proof revision/disable
rejection. It uses no production-provider credentials or user-device prompts. Its
mailbox control is repository-bound proof, not SMTP delivery. This does not enable
ordinary provider routes or complete linking/provider-only lifecycle gates.

Local sessions retain the existing thirty-minute idle and seven-day absolute policy.
ID-token/original-transaction expiry caps the minting commit; it does not become the
local session lifetime. Current-source checks use local enabled configuration and
revision, without per-request remote-user introspection or provider logout support.
