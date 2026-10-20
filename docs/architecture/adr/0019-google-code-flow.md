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

Actual-socket and owned Chromium evidence initially covered transport only. Nine
additional server integration scenarios now carry actual owned IPv4/IPv6 receives
through shared core completion, real PostgreSQL consumption, offline RS256/JWKS,
mapping and final session commit. They preserve exact URI/revision/private proof,
one-use concurrency, cancellation semantics, error attribution and final audit
rollback/deadline checks, with positive signed controls. Provider-shaped fixture
responses are not registered Google/native authentication or OS default-browser
launch. Those outcomes and the genuinely usable lifecycle gate remain required.
Normal startup and generic web callbacks are unchanged.

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

## Experimental shared HTTPS transport

Axum `google-web` now implements a separate explicit experimental composition,
requiring the eligible-client profile for both sign-in and deletion, matching source
snapshots, HTTPS and the exact `/google/callback`. Named service/routing/sign-in/
deletion/binding/callback/page/contract modules keep HTTP separate from core policy
and PostgreSQL transactions. Existing OIDC anonymous-session and revocation-proof
cookie guards were extracted and verified in a prior behavior-preserving commit.
Generic OIDC callback members, DTOs, routes and OpenAPI remain unchanged.

Dedicated protected host cookies hold original private browser/state/nonce/PKCE
proof. GET parses through the bounded Google decoder only to choose fixed UI by one
purpose-state match; malformed/ambiguous returns receive fixed error bytes. Neither
GET nor page rendering consumes state or creates authority. POST retains all core
bindings and deliberately processes code or provider error; stale/malformed state
cannot clear newer proof cookies. Existing ambient-session sign-in is refused and
deletion uses the actual current owner/session, never a body-selected account.
Both deletion stages require the exact confirmation phrase. Only existing committed
sign-in/deletion produces success or clears current session authority.

Reference scripts scrub query/fragment immediately, keep callback only in memory,
require explicit POST and drop/abort it on navigation/restoration. CSP, no-store,
no-referrer and protected cookie rules remain shared. Metadata/error fields are
never reflected, fetched or used as authority. HTTP64KiB input includes JSON escape
overhead; the core8192-byte query/2048-byte decoded-value bounds remain in force.

Real HTTP/PostgreSQL tests and owned private-TLS Chromium cases use actual offline
RS256/JWKS responses from public authorization inputs. They establish component
behavior only. The runner blocks real external traffic, changes no system trust or
provider setting, and removes only its owned database/TLS files. Ordinary standalone
Google configuration/activation, registered/manual profiles and usable genuinely
fresh lifecycle, supported OS browser launch/return and broader release acceptance
remain open. This composition does not force a Google authentication event.

## Account lifecycle and activation

The explicit session-age profile is selected only by trusted composition for an
eligible registered application. Converting a validated Google code component to
`GoogleSessionAgeCodeExchange` requests only fixed essential ID-token `auth_time`
through Google's documented `claims` parameter, preserving original S256/state/
nonce/redirect and all existing source/key checks. It supplies no prompt/max-age
reauthentication parameter or arbitrary caller claims. Metadata endpoint `claims`
collisions reject rather than overriding either input. The base sign-in-only
component and generic OIDC request behavior remain unchanged.

`GoogleAuthorization::new_session_age` selects that concrete profile for the shared
sign-in start/completion/cancel use case. Its default constructor remains ordinary
Google sign-in. A private concrete dispatcher delegates protocol exchange while
retaining one implementation of state/proof/route/cancel policy; it is not a generic
provider framework. Exact snapshot equality remains mandatory at construction.

The selected profile requires an actual correctly typed signed authentication-time
claim. An otherwise valid response missing it is a provider-profile failure, not
proof that a user failed authentication. Separate sign-in and account-deletion
exchange methods reject cross-purpose/linking contexts before token I/O. A deletion
exchange yields only the existing opaque purpose-bound identity proof; exact owner/
subject/current-session/source, genuine age and original deadline checks remain in
`OidcAccountDeletion` and PostgreSQL. Old signed authentication time stays old.
Requesting the claim neither makes it fresh nor establishes provider feature
eligibility. Registered-client/manual proof of a usable lifecycle remains a gate;
this component does not activate ordinary Google login or deletion routes.

`GoogleAccountDeletionAuthorization` supplies bound start/completion/cancel for
the deletion purpose using only the explicit session-age client. Both public
sign-in constructors continue to reject deletion; the deletion constructor rejects
sign-in and linking before admission or provider I/O. Its private operation reuses
the same state/issuer/actual-route/private-proof checks and cancellation as sign-in,
with a third concrete dispatcher case selecting the deletion exchange method.
Exact configuration snapshots must match. A callback error can cancel only the
original deletion operation; cancellation does not revoke its initiating session.
Neither a successful callback nor a denied provider response deletes an account.
The verified identity must still pass current-policy mapping and the existing
atomic deletion transaction. Failed cleanup/storage remains Unavailable, not a
successful provider denial. This adds no browser route or provider activation.

Primary-source follow-up on 2026-10-20 narrows the remaining lifecycle question.
Google's [Security Bundle](https://developers.google.com/identity/siwg/security-bundle#authentication_time)
documents optional signed `auth_time`, requested through the OIDC `claims` member
and enabled for a published, verified provider application. It also explicitly
states that Google Account reauthentication requests are not supported. Therefore
the generic OIDC deletion request's `prompt=login`/`max_age=0` cannot simply be reused
as a supported Google reauthentication contract. Optional claim availability does
not prove a genuinely fresh event or a usable deletion path for an existing Google
session. This research changes no provider-console/browser setting or route. The
explicit claim-request component does not force a new event or establish eligibility.
No weaker fallback is activated. Actual registered
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
part of automated acceptance. The later registered native checkpoint below records
one Desktop/base-profile sign-in; the remaining web, platform and lifecycle matrix
is not accepted by that result.

## Decisions still requiring evidence

Resolve native registered-client wire semantics, supported platform return methods,
any hybrid presenter requirements and genuine signed freshness before claiming
those profiles supported. Revise this ADR around the tested final implementation;
do not turn unresolved questions into permissive switches or speculative modules.
Manual provider/device evidence, independent review, SAML and outbound issuer remain
separate release gates. This proposal is not an audit, protocol certification or
production-readiness claim.


## Bounded native launcher checkpoint

An additional optional server `google-desktop-launch` feature owns one native
sign-in attempt around the existing exact listener/core authorization boundary.
`operation.rs` retains protected proof and coordinates concurrent callback capture
and successful opener exit before verification; `launch.rs` owns first-command
selection and bounded child lifecycle; `operation_error.rs` exposes finite errors.
No SQL, migration, core policy or public HTTP contract changes are introduced.

Use pinned `open`5.4.4 only for command construction, selecting its first command.
Execution belongs to Tokio, with null streams, five-second/original-expiry cap,
kill-on-drop and explicit one-second reap on returned error. No fallback iteration,
raw command errors, provider selection or system changes are allowed. The OS's
configured handler is trusted; its successful exit establishes no identity or grant.
Private Python process actors permit real process/socket/PG/signature acceptance
without launching a browser. Actual OS/registered-provider evidence remains open.

Explicit operation cancellation retains original private proof; transport failure
or dropping a future cannot promise SQL cleanup. Final local authority still needs
the existing mapping and atomic sign-in transaction. Reconfiguring an ephemeral
redirect rotates source revision and deliberately invalidates previous source
sessions. That existing guard is preserved and regression-tested; stable registration
and concurrent native lifecycle require further design before ordinary activation.
See the [native operation guide](../../guides/google.md#owned-native-sign-in-operation).

Command-selection errors must also close the listener, before any child exists.
The private prepared-command boundary now applies that cleanup before delegating
to capture. A deterministic unavailable-selection case must observe actual socket
refusal, unchanged pending expiry/no authority, explicit SQL cancellation and a
subsequent signed commit under the same stable registration. This is error-path
resource cleanup, not supported-OS or registered-provider acceptance evidence.


The subsequent [ADR0020](0020-native-oauth-operation-returns.md) adds an explicit
stable native registration profile and exact per-operation return persistence. It
resolves port-only reopen/concurrency invalidation without weakening the existing
exact profile or actual administrative source-revision invalidation. This is a
component boundary, not ordinary Google/native activation or OS interoperability.


## Public-provider transport evidence

The explicit `google-provider-preflight` example now checks real public Google
discovery/JWKS over production TLS with current PostgreSQL registry checks and an
owned native authorization/cancellation cycle. It accepts no registered client
credentials and blocks all token POSTs. This narrows the previously untested public
metadata/TLS boundary only; signed/registered-client and actual browser/OS evidence
remain mandatory. Its disposable database lifecycle closes after success or probe
failure, with independent failure and catalog controls. See the
[preflight guide](../../guides/google.md#public-metadata-and-transport-preflight).


## Registered native acceptance preparation

A separate opt-in example now prepares the registered Google/OS matrix, using
protected registered-client inputs, actual owned native operation and existing
opaque proof/mapping/PG commit. It validates/revokes only its transient local session
and removes the exclusive disposable database. Input-only and owned-setup checks
cannot invoke the opener or claim registered acceptance; a separate explicit
operator-consent mode is required for real sign-in. Offline/public-setup evidence
does not complete that manual mode. No ordinary activation, provider setting,
remote token endpoint or security-policy fallback is introduced. The
[manual procedure](../../../tests/provider/google/manual-native.md) retains actual
platform/client, genuine freshness and usable lifecycle gates.

The subsequent [registered native result](../../../tests/provider/google/results/2026-10-20/registered-native-signin.json)
records one successful Desktop/base-profile operation on macOS with operator-reported
Helium. Existing verification and transaction boundaries produced the local session,
validated and revoked it, and removed the owned database. No signed `auth_time` was
returned. This evidence narrows the basic native interoperability gap; it does not
change the freshness/deletion policy or authorize ordinary activation.
