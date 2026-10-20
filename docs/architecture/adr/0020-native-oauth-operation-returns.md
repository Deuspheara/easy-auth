# ADR 0020: Stable native OAuth registration and exact operation returns

Date: 2026-10-20. Status: implemented component; acceptance evidence is recorded
in the verification history. Ordinary native/provider activation remains gated.

## Problem and evidence

ADR0019's exact native connection snapshot includes an ephemeral listener port.
Registering a new port administratively therefore rotates source revision and
invalidates existing source sessions. Retaining one fixed port would not satisfy
normal reopen/concurrent desktop behavior. The original exact-configuration
regression remains valid and must not be weakened.

[RFC8252 section7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3) describes
available loopback ports selected per request and both IP families. Google's
[desktop guide](https://developers.google.com/identity/protocols/oauth2/native-app)
also describes a listener on an available port. This research does not establish
registered Google interoperability or ordinary native activation.

## Decision

Keep stable provider configuration separate from the exact return of one operation.
`OAuthConnection` defaults to `OAuthRedirectPolicy::Exact`; existing HTTPS and
exact native constructors retain their behavior. The explicit trusted
`with_desktop_loopback_returns()` builder selects `DesktopLoopback` only for an
already canonical literal-loopback HTTP anchor with `RequireIssuer`. Registration
retains that anchor and fixed callback path. It does not prove socket ownership.

The profile admits only canonical `127.0.0.1` or `::1`, an explicit nonzero/nondefault
port and the identical registered path. It rejects localhost/domain names, other
loopback/wildcard addresses, credentials, query, fragment, encoded/noncanonical
paths and HTTPS overrides. This is an explicit desktop profile, never a web fallback
or a callback-selected policy. Linking/deletion purposes are not supported by it.

After binding an actual owned listener, trusted composition constructs
`OAuthTransactions::for_desktop_return` with the stable configuration and exact
listener URI. Readonly `redirect()` exposes that operation return. State, browser,
nonce, S256, purpose, source snapshot, owner/session and original deadline remain
bound as before. Consume/cancel requires the exact retained return; admission of
other ports under the registration profile does not make them interchangeable.

Additive migration0020 persists `redirect_policy` on the source and the exact
`redirect_uri` on pending transactions. It defaults all old registrations to exact
and backfills their old exact return without changing proofs, revisions or caps.
No published migration or global registry URI uniqueness constraint changes.
Deploy the matching adapter/schema together and drain older OAuth writers before
applying0020: older SQL omits the new required return field and is not supported
after this migration. No mixed-version rolling upgrade or downgrade is claimed.
PostgreSQL still locks full current configuration before owner/session/pending
state and checks final database time after blocking writes. The profile is part
of full definition comparison, including stable startup loading. Disable and actual
administrative policy changes still invalidate old contexts and sessions.

`OAuthStart` and `OAuthRequest` public fields stay unchanged. New repository methods
accept the exact return; default implementations reject a return differing from the
registered anchor and delegate only the old exact case. Unextended backends cannot
silently collapse a changed port into an older operation. PostgreSQL implements
all three methods with the same shared transactions and bound SQL value.

The opaque consumed `OAuthExchange` retains the exact return separately from its
stable configuration. Google authorization uses the transaction's return; captured
callback completion checks that same exact URI. Code exchange sends the retained
return, not the registration anchor. Anchor-only public authorization-URL helpers
reject the new desktop profile before I/O; a bare start does not carry its return.
Existing exact-profile helpers remain unchanged. Identity proof/mapping and final local
session/audit commit retain stable source authority, unchanged realm/subject and
one-use/final-cap checks. No new verified-proof constructor or local grant appears.

## Consequences and acceptance limits

Reopening or concurrently owning another permitted port no longer requires an
administrative reconfiguration. Sessions retain their original source revision.
An actual administrative change still rotates revision and invalidates them.
The old exact native profile remains available and keeps its deliberately stricter
configuration-change semantics.

Tests must include real PostgreSQL upgrade/backfill, exact callback/cancellation
negatives, private proof/realm separation, one-use races, configuration/profile/
disable checks, infrastructure failure classification, current-source invalidation,
and actual signed/process/socket positive controls through final commit. Historical
migration fixtures seed original columns and finish later schema before invoking
today's adapter; they are schema fixtures, not new protocol-proof APIs.

This does not deliver remote application tokens, an installed-client DB credential
model, mobile callbacks, provider registration, usable Google freshness/deletion,
actual OS browser acceptance, independent review or production readiness. The
existing bounded opener, private proof retention and cancellation/drop semantics
remain unchanged. No user credential-manager or system security settings change.
