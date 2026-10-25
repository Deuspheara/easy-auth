# ADR 0044: Explicit social identity linking and retained-factor unlink

Date: 2026-10-25. Status: implementation in progress for AUTH-25.

## Authority and scope

The owner directed continued locally verifiable engineering while deferring real
provider/production acceptance. AUTH-24's recorded AUTH-23 prerequisite and the
AUTH-24 -> AUTH-25 -> AUTH-26 acceptance dependencies remain visible. This work
does not activate ordinary Apple, establish provider interoperability, supply grant
custody/revocation, waive independent review or authorize a PR/merge/deployment.
SAML waiver limits and the outbound OIDC release gate remain unchanged.

Reuse existing OAuth transactions, Google/Apple code profiles, opaque verified
identity, scoped OIDC identity storage and source-aware session authorization.
Do not introduce a provider plugin framework, public proof constructor, token-upload
link API, email merge or custom cryptography. Exact realm/connection/client/issuer/
subject ownership remains authoritative. OIDC's
[claim-stability rules](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability)
and Google's [identity guidance](https://developers.google.com/identity/openid-connect/openid-connect)
separate subject ownership from email/profile attributes. First-consent Apple
profile remains unsigned and ignored by local mapping.

## Explicit proof purpose

Default Google/Apple authorization and exchange remain sign-in-only. Add explicit
linking constructors/entry points that accept only `OAuthPurpose::Link` with the
original initiating owner and session verifier. Start, consume, verification after
provider I/O and final mutation all revalidate current source/owner/session,
genuine existing freshness and original deadlines. A linked proof cannot sign in
or delete; sign-in/deletion proofs cannot link. Desktop loopback linking stays
rejected. Requests do not infer fresh provider events from `iat`, local issuance
or an account-selection prompt.

The final core linking use case consumes a mapped proof plus the original current
session; it does not create/rotate a session, provision an owner, change contact,
rewrite display metadata or modify account policy. Recheck complete current target
configuration/policy, serialize exact subject, then lock source/email/owner/session
and compare the purpose's owner/session. Existing ownership, even by the same owner,
is a conflict rather than a transfer, overwrite or fresh grant. JIT settings do not
authorize linking; explicit verified proof of both accounts does.

## Existing account policy

Persist an additive explicit-linked marker on OIDC identity rows, default false
for all historical/JIT identities. Only the new linking transaction sets it.
Mailbox-policy accounts may authenticate through an explicitly linked OIDC identity;
changing an old JIT owner's policy does not silently make its identity eligible.
Provider-required accounts retain current provider checks. Passkey-required accounts
retain their passkey requirement: recording an external identity does not enable
provider fallback. No policy-transition API is added.

Source-aware validation, inventory, freshness and revocation must recognize the
exact eligible linked source. Local mailbox/password/recovery credential mutations
continue to require genuine local-method freshness; an OIDC session cannot enter
a local-only helper without its current-source checks. Signed provider `auth_time`
is mandatory wherever provider-session freshness is used; Apple claim absence is
not repaired using token/session creation time. Backend-disabled builds fail closed.

## Unlink and last usable credential

Unlink selects only a public identity UUID owned by the current session's realm
and owner. It requires fresh authentication through a credential that will remain.
An OIDC session cannot remove its own source identity: the user must first
authenticate with another retained method. This is stronger evidence of a usable
remaining credential than counting inventory rows or accepting disabled methods.
Provider-required single-identity accounts therefore cannot remove their last
credential. Another genuinely fresh active provider or local method can authorize
removing a different identity under the account's unchanged policy.

Serialize the target subject before source/email/owner/session locks. Recheck target
ownership after waits, retain the caller's original idle/absolute/freshness caps,
and remove only the target identity. Revoke its sessions and detach only their
identity UUID before deletion, preserving original OIDC method/revision/timestamps
and historical session rows required by composite audit foreign keys. An additive
constraint admits missing OIDC identity only on revoked historical rows; current
source validation still requires an actual bound identity, even if a row were
improperly unrevoked. Do not rewrite history as a local authentication method or
deidentify unrelated account audit. Ordinary account-deletion cascades remain.
Unrelated sources and realms remain intact. Reciprocal unlink attempts
serialize on owner: after one removes a source, the other's retained-source recheck
must reject. A disabled target may be removed using another still-valid method.

Install the existing scoped five-minute deleted-subject cooldown on unlink so a
previously prepared/verified callback cannot reattach or JIT a replacement owner.
This retains the established maximum original OAuth lifetime, with no raw subject
or erased-owner reference in retention metadata. It is not remote Apple revocation;
AUTH-26 remains required for provider grants.

## Atomicity, audit and transport

Add explicit immutable migrations for the marker and closed audit/notice kinds.
Link/unlink, finite owner/session audit attribution and an optional existing verified
contact notice commit together. No notice recipient comes from provider claims.
Recheck every original deadline after all blocking writes; any failure restores
identity/session/audit/notice state. Previously consumed OAuth state stays consumed.

Explicit experimental web composition uses separate purpose cookies and routes,
exact-Origin same-origin mutations, a trusted current session and deliberate
confirmation. Callbacks only deliver data; they do not mutate identity ownership.
Apple retains its non-authoritative cross-site POST handoff and Lax cookies;
Google retains issuer/S256/nonce checks. Stale/malformed returns cannot clear a
newer operation; callback-aware cancellation checks original public state. Keep
proofs out of URLs, browser storage, diagnostics and reports, and never auto-retry
credential completions. Ordinary activation remains separate.

## Selected web composition and callback purpose

The concrete experimental social web composition is implemented using the existing Google/Apple
web services, their explicitly constructed matching link authorizations and one
core linking use case. Share a single ordinary base router and attach extracted
provider routes; do not merge duplicate base routers or infer activation from a
compiled Cargo feature. Default provider builders expose no linking operation.
All realm/configuration/HTTPS callback checks remain in the owning provider.

It uses separate host-only protected Link cookies, explicit Google/Apple link
start/finish/cancel routes and an owner-authorized OIDC unlink route. Start/unlink
carry an expected owner UUID only as a consistency check against the trusted
current session; it selects no owner. Require deliberate fixed confirmations.
Changed-owner/session, stale state and malformed inputs cannot silently retarget
an operation. A fixed account page consumes normal session/inventory reads and
renders issuer/UUID metadata as text, with no issuer-derived navigation.

The same persisted provider namespace and exact callback must serve sign-in and
linking so a linked subject can later authenticate through the normal matching
connection. Do not invent a second redirect, rewrite subject namespaces or relax
exact-return validation. Google GET delivery can select a fixed purpose page from
uniquely matching protected public-state hints, only when linking is explicitly
selected; this remains presentation and never consumes a proof.

Apple's cross-site POST cannot read cookies or storage and its protected Lax
cookies are correctly absent. Retain the same inert escaped handoff. After removing
raw data from DOM and scrubbing location, a fixed script may make an exact-Origin
same-origin POST carrying only returned public state to select a presentation
operation from uniquely matching private state cookies. This hint performs no
authentication, database access, consumption, code exchange or mutation. Default
composition can select sign-in only; selected social composition may select link.
Unknown/ambiguous state fails closed without clearing cookies. It never substitutes
for full state/private proof/original owner/session/provider/final-commit checks.
Only a deliberate subsequent confirmation sends the actual response to finish.

Hint/manager/return scripts retain owned cancellation/generation fences, drop
payloads before finish and on navigation/restoration, and never retry credential
completions. No return secret enters browser storage, diagnostics or a new URL.
An operation hint, expected owner, API capability or inventory row grants nothing.
Local unlink is not represented as Apple grant revocation.

## Required evidence

Use maintained signed producers and actual committed local authentication, never
seeded verified proofs/sessions. Real PostgreSQL tests must cover both purposes,
matching-email isolation, stale/revoked/switched sessions, ownership/conflict races,
source disable/reconfiguration, final lock-wait expiry, audit/notice rollback,
cross-realm constraints, retained-factor/self-source denial, reciprocal unlink,
session invalidation and migration preservation. HTTP/genuine owned browser tests
must exercise both providers and deliberate same-origin completion. Default and
isolated/combined feature builds, strict Clippy, workspace tests and existing
security gates remain required. Record failures/limits and exact pushed evidence.

## Maintainability

Extend core `oidc/identities/` and provider-owned authorization modules; PostgreSQL
owns visible linking/unlinking transactions. Reuse source-aware owner authorization
and subject/cooldown operations through separately verified structural extractions.
HTTP owns only closed types, cookie transport and delegation. Named test modules
separate proof, lifecycle, policy, ordering, rollback and migration invariants.
Keep new behavior out of crate entry files and existing accumulating suites.
