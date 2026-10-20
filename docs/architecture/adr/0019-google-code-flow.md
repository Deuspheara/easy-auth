# ADR 0019: Google authorization-code profiles

Date: 2026-10-20. Status: proposed for Google web/native activation in AUTH-23.
This records the implementation and acceptance boundaries before behavior changes.
Existing generic OIDC/Keycloak evidence does not establish Google interoperability.

The first implementation checkpoint adds only explicit desktop return metadata:
`OAuthRedirect`, exact loopback binding, preserved administrative revision rotation
and native-configuration PostgreSQL regressions. No Google profile, native callback
listener or web/native activation is implemented by that checkpoint. The remaining
proposal below must still be resolved and verified.

The next checkpoint implements an opt-in core `GoogleCodeExchange`: canonical
issuer/RequireIssuer, fixed three Google endpoint origins, RS256 without additional
audiences, fixed openid/email/profile scopes and explicit Basic/Post registration.
It reuses the existing opaque sign-in exchange and verifier, rejects other purposes
and adds no browser/native transport or local grant. Offline actual-signature
component evidence is separate from supported web/native lifecycle,
registered native client and manual provider acceptance. The
[component guide](../../guides/google.md) states its exact supported boundary.

Real PostgreSQL acceptance now includes ten Google-profile scenarios through actual
state consumption, offline RS256 code/JWKS responses, verified mapping and the
existing identity/session transaction. Exact provider request assertions and signed
response counters prevent infrastructure/fixture failures from standing in for an
authorization rejection. Independent one-connection lock/clock observers cover a
real final audit wait; no new persistence policy or schema is introduced. This is
not a real Google, browser, registered-client or native OS-return result.

## Context

Google web and native system-browser flows need the existing one-use OAuth state,
S256, constrained discovery/JWKS transport and reviewed signature/claim verifier.
They must carry the original configuration and deadline through local identity
resolution, rather than introducing another token verifier or accepting uploaded ID
tokens as substitutes for an initiated, bound authorization-code flow.

The primary references inspected for this decision are Google's
[OIDC protocol](https://developers.google.com/identity/openid-connect/openid-connect),
[discovery document](https://accounts.google.com/.well-known/openid-configuration),
[installed application flow](https://developers.google.com/identity/protocols/oauth2/native-app),
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) and
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).
Provider metadata is a dated observation, not a permanent compatibility guarantee.
Actual registered-client and platform behavior still require the manual matrix.

[ADR 0013](0013-oauth-state-transactions.md),
[ADR 0014](0014-oidc-egress.md),
[ADR 0015](0015-oidc-token-verification.md),
[ADR 0016](0016-oidc-identity-mapping.md),
[ADR 0017](0017-provider-account-deletion.md) and
[ADR 0018](0018-oidc-web-composition.md) retain their security invariants.

## Proposed shared boundary

The shared-use-case checkpoint implements `GoogleAuthorization` within core's
owning Google feature: exact-snapshot composition, sign-in-only start, bounded
decoded callback completion and explicit cancellation. It compares retained and
returned state plus actual issuer/redirect before dispatch, and uses the existing
OAuth transaction for every database/private-proof binding. URL-construction
failure attempts exact-operation cleanup; failed cleanup is an observable error.
Bound provider denial/failure performs cancellation without token I/O. Success
returns the existing verified proof after one-use exchange, retaining every
original cap and granting no local session. Web and native adapters share this
policy rather than copying consume/cancel orchestration into transports.

Request network source retains ADR0013's admission-only meaning, distinct from
the exact configured provider source. It is not an IP-based account credential.
Real PostgreSQL controls include roaming with an independent admission budget,
wrong private bindings, cancellation storage failure, provider/document faults,
actual signed negative/positive controls and concurrent one-use callbacks. No
transport or Google activation is inferred from this use-case evidence.

Keep the existing four crates and inward dependencies. Put Google-specific trusted
configuration, callback decoding and orchestration in named modules within core's
owning OIDC feature. Reuse the existing opaque exchange, signature verifier and
verified/mapped identity types; do not add a public verified-proof constructor.
PostgreSQL continues to own realm-scoped state consumption, revision checks,
subject serialization, identity/session/audit commit and final database deadlines.
Axum owns only reviewed browser transport, with server configuration shared by
standalone and embedded composition. No new cryptographic dependency is planned.

Trusted configuration selects the realm, connection, local client, registered
Google client, client wire-authentication method and exact redirect. Provider
selection cannot come from query parameters, an incoming URL, token claims or
forwarded headers. Use the established constrained discovery and token transport;
Google's multiple endpoint origins do not justify a second permissive HTTP client.
Retain explicit signing-algorithm policy and require S256 without a plain fallback.

The first profile should use Google's canonical HTTPS issuer with exact comparison.
Google also documents a legacy issuer spelling; do not add global URL normalization
or silently accept aliases. Any additional spelling or native presenter policy must
be explicit, narrowly scoped, tested and carried through the authoritative source
configuration. Unreviewed variants fail closed and remain documented limitations.

Signed subject is the external identity key within the existing realm/source
namespace. Email and its correctly typed verification flag remain attributes, never
local verified contact, account ownership or automatic-link authority. Missing or
false email verification cannot enable a weaker method. Existing generic audience,
authorized-presenter, nonce, time, signature and key-rotation checks stay in force.

## Web callback and client registration

The core callback-decoding checkpoint adds `GoogleAuthorizationResponse` and its
untrusted code/denied/provider-failure outcome. It bounds the raw query and decoded
values, requires actual canonical response issuer on successes and failures per
[RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207#section-2), and preserves the
canonical returned state for subsequent private operation binding. It rejects
duplicate decoded members, malformed encoding, contradictory results and unsupported
inputs. Only the existing redacted code type reaches a later code exchange.
Google's documented scope/authuser/hd/prompt metadata and optional session state
are bounded and discarded; foreign error descriptions/URIs are never retained or
used for output, fetching or authorization. Unknown members fail closed in this
supported subset; this differs from general OAuth unknown-member tolerance and
does not establish conformance or provider interoperability.

The decoder creates no authority and performs no cancellation, consume or I/O.
Actual route/private browser-proof/source/purpose/current-configuration binding
remains with the transport and `OAuthTransactions`; error classification alone
cannot authorize cancellation. Real PostgreSQL callback cases exercise that
boundary and one-use code verification without introducing a public route. Generic
OIDC callback contracts remain unchanged. Google web/native delivery and genuine
provider-required lifecycle evidence remain open.

The current closed callback contract admits state, code, issuer and session state.
Google's documented callback also includes scope. Add only a reviewed Google-specific
bounded decoding contract; do not permit arbitrary response members or weaken the
generic callback by default. Ignored presentation/protocol metadata grants no scope,
contact, role or ownership. Reject duplicate, contradictory, malformed and oversized
security inputs before provider exchange. Successful and error callbacks need exact
state/browser/purpose/source binding; provider error text must not enter the page,
logs or durable reports.

Keep the existing deliberate same-origin start/finish/cancel model, protected
host cookies, immediate query/fragment scrubbing and no script storage. A callback
GET issues no local session. Only committed local success may deliver its cookie.
Ambient sessions require the explicitly reviewed behavior from ADR 0018; no silent
account switch. Configuration must not expose secrets or fixture TLS/address knobs.

Google discovery currently advertises Basic and Post token authentication. Select
the actual registered method explicitly and load backend credentials through the
existing protected-file boundary. Never fall back to public authentication because
configuration, metadata, credential loading or token exchange failed.

## Native system-browser boundary

The `google-desktop` server-library checkpoint owns an ephemeral literal IPv4/IPv6
loopback socket before exposing typed redirect metadata. It bounds HTTP parsing,
state/issuer/Host/path validation, sequential connections and deadlines using the
already selected Hyper stack; no handwritten HTTP parser or detached task is added.
Actual delivery alone creates `GoogleDesktopCallback`, whose completion supplies
its captured URI to the shared core flow. All final private bindings and database
caps remain in that flow. Cancellation/drop closes transport only; original pending
state requires explicit core cancellation. Finite transport failures are distinct
from application proof/storage failures. Fixed no-store/no-referrer/CSP responses
scrub the browser URL without reflecting protocol values or issuing cookies.

Actual-socket and owned Chromium evidence is a transport checkpoint, not registered
Google/native authentication, OS default-browser launch or full PostgreSQL/signature
acceptance through this listener. Those tests and the genuinely usable lifecycle
gate remain required. Normal startup and generic web callbacks are unchanged.

Native support is part of AUTH-23, not implied by a working web callback. Use an
external system browser and the registered platform's supported return mechanism.
An app-owned WebView, arbitrary pasted callback URL or unsolicited token upload is
not an equivalent implementation. The original state, nonce and PKCE verifier must
remain bound to one initiated operation in protected transient storage, with bounded
lifetime, cancellation and cleanup. No callback returns the PKCE verifier to a URL.

`OAuthConnection::new` remains canonical HTTPS-only; the implemented explicit
`OAuthRedirect::desktop_loopback` carries trusted native redirect metadata without
relaxing that web constructor. A desktop listener must own its concrete loopback
address/port before authorization, retain the exact URI through state consumption
and token exchange, and reject aliases, external addresses, wildcard ports, URL
credentials, fragments and injected parameters. Persistence must retain that exact
binding and current revision; configuration now preserves validated metadata through
`reconfigured`, retaining disable and pending cancellation. Published migrations
remain immutable; demonstrate any schema need before adding a migration.

Loopback handling must not become a mobile fallback. Android/iOS require their
supported registered platform mechanisms and separate evidence. Desktop emulation
cannot establish mobile SDK, app-link or OS-return interoperability. Any hybrid
audience/presenter registration must have explicit trusted client bindings; never
accept an arbitrary `azp` or infer trusted presenters from an ID token.

Installed-client credentials may participate in Google's required wire exchange,
but cannot prove that the calling native application is confidential or genuine.
Review that registered profile explicitly; do not bypass generic discovery's
authentication checks or ship a backend secret as an application-authenticity proof.
The native adapter does not create remote application access/refresh tokens: the
outbound issuer and native token-family contracts remain the separate M07 gate.

## Account lifecycle and activation

Primary-source follow-up on 2026-10-20 narrows the remaining lifecycle question.
Google's [Security Bundle](https://developers.google.com/identity/siwg/security-bundle#authentication_time)
documents optional signed `auth_time`, requested through the OIDC `claims` member
and enabled for a published, verified provider application. It also explicitly
states that Google Account reauthentication requests are not supported. Therefore
the generic OIDC deletion request's `prompt=login`/`max_age=0` cannot simply be reused
as a supported Google reauthentication contract. Optional claim availability does
not prove a genuinely fresh event or a usable deletion path for an existing Google
session. No provider-console/browser settings are changed and no claims request,
deletion method or weaker fallback is activated by this research. Actual registered
profile/lifecycle evidence and a reviewed usable policy remain required.

Preserve provider-required policy and the existing fresh provider deletion path.
Google's availability of signed authentication-time claims must be established for
the registered profile. Neither ID-token issuance time, a requested prompt, an
exchange response nor a newly rotated local session proves provider authentication
freshness. Never fabricate `auth_time`, relax deletion to weak mailbox/password
proof or activate an integration that strands a provider-only account.

Until genuine lifecycle evidence exists, component success is not permission for
ordinary Google activation. Linking/unlinking remains AUTH-25; Apple grant handling
remains AUTH-26. This ticket must report any unresolved acceptance criterion instead
of treating those boundaries or unavailable manual evidence as completed.

## Regression and acceptance plan

Before changing behavior, preserve existing relevant tests and add independently
observable negative cases with actual signed offline JWKS/token controls. Required
coverage includes:

- Exact registered issuer/client/redirect, S256/state/nonce, subject, audience and
  authorized presenter; wrong signatures/keys/algorithms and rotation controls.
- Missing, duplicate, null or incorrectly typed security claims and email flags;
  unchanged local identity/contact policy when email is absent, false or shared.
- Closed web callback decoding, provider cancellation/errors, Origin and ambient
  session behavior, secret-free errors, cookie/referrer/log/storage boundaries.
- Native operation/return binding, actual listener ownership, cancellation,
  concrete redirect/port substitution and cross-operation replay denial.
- Real PostgreSQL realm/client isolation, one-use races, disable/revision changes,
  original deadline crossings and atomic identity/session/audit rollback/commit.
- Explicit infrastructure failures distinct from authorization rejection, including
  independent bounded lock observers and valid positive controls after faults.
- Provider-required downgrade denial and genuinely usable fresh account deletion.

Run formatting, strict default/all-feature/all-target lint, default/all-feature
real-PostgreSQL workspace suites, existing native/SMTP/Keycloak regressions and
dependency/license/secret checks. Record exact commands, results, source provenance
and final-head hosted CI. Offline provider-shaped fixtures prove component behavior;
they must not be described as actual Google login or platform interoperability.

The separate manual matrix must identify actual registered web/native profiles,
system browser/platform and relevant lifecycle outcomes without saving credentials,
codes, tokens, assertions or private keys. Production credentials are not required
by default CI. No user browser, credential-manager or security-setting changes are
part of automated acceptance. No Google flow has been run or accepted by this ADR.

## Decisions still requiring evidence

Resolve native registered-client wire semantics, supported platform return methods,
any hybrid presenter requirements and genuine signed freshness before claiming
those profiles supported. Revise this ADR around the tested final implementation;
do not turn unresolved questions into permissive switches or speculative modules.
Manual provider/device evidence, independent review, SAML and outbound issuer remain
separate release gates. This proposal is not an audit, protocol certification or
production-readiness claim.
