# ADR 0039: Explicit native introspection consumers

Date: 2026-10-24. Status: implemented for AUTH-40; verification recorded separately.

## Decision

Keep public native registration, refresh possession and resource-consumer
authentication separate. A known native ID/token, browser cookie or local owner
cannot authenticate introspection. A trusted operator may persist an
`IssuerNativeConsumerPolicy` binding one exact current confidential Basic consumer
to one exact current native-refresh audience under the same realm/HTTPS issuer.
The consumer differs from the audience. Installing migration0036 creates no policy;
new policy is disabled. Replacement rotates revision and preserves disable.
Explicit enable requires both complete current enabled client definitions and the
exact saved policy. Disable rotates revision and remains available after either
client is stale/disabled. A new policy is configuration, never consent or a token.

[RFC7662 sections2.1–2.3](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1)
require authorized inspection and inactive output for tokens outside that consumer's
permission. This profile uses actual current Basic credentials and explicit audience
permission. Authentication failures remain401; infrastructure faults remain errors.
Unknown, foreign, revoked, expired or unauthorized tokens return only active=false.
No application business roles or implicit resource-server permission is introduced.

## Transaction and lifetime

Snapshot reads select client/source lock paths only. Deterministically lock the
consumer and candidate audience by immutable UUID order, then validate the actual
current consumer credential before any active/inactive result. Unknown tokens still
authenticate the consumer. No later client lock follows source/owner/family locks.
Provisioning and disable share the pair order. No pool connection is opened while
transaction locks are held.

For an active result, lock the complete current audience, exact enabled consumer
policy, original native policy, retained access key/global issuance namespace,
current original provider source/optional email/owner/session, native family, exact
committed refresh generation, access row and original consumed native authorization. Recheck immutable snapshots and
full realm/issuer/client/family/owner/session/subject/generation bindings. Original
consent/source caps remain enforced by the published full-tuple family/consent FKs.
Check the final database clock after every wait:access expiry, family idle and
absolute expiry must all remain live. Family/key/policy/source/session disable or
revocation prevents active metadata. Ordinary retained-key rollover can preserve
unexpired access; explicit key disable cannot. Inspection performs no grant, audit,
session idle update, refresh rotation or authentication-time extension.

Explicit native delegation can outlive code/cookie freshness, within its original
source/session absolute cap. Reuse the existing delegated-session guard; never
validate refreshed native access through the short online-code path or a cookie
idle check. Spent refresh credentials are not inspectable access; family reuse
revocation invalidates all access generations. Unexpired earlier access generations
may remain active until their own expiry while the family remains live.

## Explicit transport

`IssuerNativeWebServices::with_native_introspection(repository)` opts into a separate
POST `/oidc/native/introspect`. Its authority derives from the same base issuer;
the builder neither provisions nor enables policy. Without the builder, route and
live contract are absent. `issuer_native_consumer_openapi` describes this explicit
composition. Existing `/oidc/introspect` retains confidential own-audience online
semantics; no failed inspection falls through to another authority model.

Reuse strict4KiB status forms, actual peer/source admission, closed input, current
Basic method, matching body ID, no ambient-cookie/Origin fallback, deadlines,
no-store/no-cache and finite sanitized errors. Hints are ignored. Active output has
only active/iss/aud/client_id/pairwise-sub/iat/exp/Bearer/scope. Audience/client_id
remain the native audience, not the authenticated consumer; native scope is the
original openid offline_access. No owner/session/raw token/hash/email/nonce/role is
projected. The metadata is not a local session or a business authorization proof.

## Evidence and limits

Feature tests use existing genuine account/provider/signing producers and real
PostgreSQL. They cover initial disabled/current revision/restart behavior, actual
credentials even for unknown tokens, exact audience/realm separation, one-use
rotation/replay/cleanup, cookie/freshness separation, provider source/method denial,
retained key/policy/session changes, migration preservation, observed database-only
revoke/disable/expiry waits, storage errors and explicit HTTP/live contracts.
Initial signatures finish before database races. No new adversarial XML/crypto
producer or custom signature-concurrency experiment is introduced.

No runtime dependency, advisory ignore, older migration rewrite, generic framework
or standalone activation change. AUTH-41 still owns Rust SDK/standalone client parity;
production operation remains supervised. This decision supplies engineering
behavior, not independent audit, external certification or production readiness.
SAML independent review remains waived under ADR0032, not performed.
