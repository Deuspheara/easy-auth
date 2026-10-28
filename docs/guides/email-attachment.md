# Experimental verified contact attachment

An email-free `passkey_required` account can attach a verified contact address.
This preserves its opaque ID, credentials and stronger authentication policy.
Core/PostgreSQL and experimental HTTP tests pass. A separate native Chromium
platform/USB suite now proves signup through real SMTP confirmation and later login. Ordinary server activation and stronger-account
management/recovery remain separately gated.

## Composition and HTTP

Migrate through `0011_email_attachment.sql`. The required repository port adds
`begin_email_attachment` and `finish_email_attachment`; custom delivery adapters
must implement `EmailDelivery::email_attachment`. There are no permissive defaults.
The server SMTP adapter sends the proof through its existing bounded transport.
Its configured trusted origin determines the confirmation URL.

Enable `easy-auth-axum/passkey-signup` and explicitly compose
`experimental_passkey_signup_router` as described in the [signup guide](passkey-signup.md).
Earlier experimental constructors and the ordinary router do not mount these routes.
The full [signup OpenAPI](../architecture/openapi-passkey-signup.json) includes them.

| POST path | JSON | Success |
| --- | --- | --- |
| `/v1/account/email/attachment/start` | `{email}` | 202 `{status:"accepted"}` and independent HttpOnly attachment cookie after delivery succeeds |
| `/v1/account/email/attachment/finish` | `{token}` | 204 fresh session cookie and cleared attachment cookie after commit |

Both require exact configured Origin, JSON, an 8 KiB body bound and the current
session cookie. Input objects reject unknown fields. The account must still have
no email and require passkey authentication. The session must have a genuine
passkey method, original authentication within five minutes, and live idle/absolute
expiry. Rotation does not refresh that authentication time. Another session of the
same account cannot redeem a proof issued for the initiating session.

The separate binding cookie is `__Host-auth-attach` under HTTPS or `auth-attach`
in explicit localhost development. It has HttpOnly, SameSite=Lax, Path=/, no Domain,
Max-Age=300 and Secure under HTTPS. It is independent of signup, login, password
recovery and email-change bindings. Logout/revoke-all clear it along with other
authentication bindings. It is not a credential for an anonymous email login.

Public errors use the existing redacted codes: 400 input, 401 rejected ownership/
method/freshness/binding/proof/expiry/occupied target, 403 Origin, 413 body size,
415 media, 429 admission, 503 delivery/storage failure and 504 timeout.

## Proof and commit rules

Start normalizes the address and takes the same delivery path for occupied and
available targets. There is no ownership-dependent response or account merge.
A new request replaces the owner's previous pending proof; only one row is retained
per owner. The target-address budget is shared with email sign-in (five starts per
ten-minute realm/address window). Existing sensitive-action admission also applies:
ten per owner and forty per source per ten-minute realm window.

The high-entropy token and independent browser secret are stored only as verifiers.
Proofs expire after five minutes of database time. The original passkey session's
five-minute freshness is independently required at completion, so a proof can become
unusable before its own expiry. Sign in again with a passkey and request a new proof.
Delivery failure returns no binding cookie and changes no identity/session; a
pending row may remain until replaced or canceled. SMTP delivery cannot be rolled
back with the database transaction; an unusable delivered link grants no authority.

The email points to `/email-attach#token=...`. GET consumes nothing. The optional
reference page removes the fragment before any POST and requires explicit
confirmation. Open the link in the requesting browser while its session is fresh.
The page uses an external same-origin script and the existing no-store/CSP boundary.

Completion locks target email, owner, initiating session and pending proof in that
order, then revalidates exact bindings, absent email, policy, freshness and target
availability. It attaches the verified email, revokes old sessions and cancels
owned pending enrollment/authentication/lifecycle proofs plus outstanding mailbox
sign-in/reset proofs for that address. It inserts a replacement session preserving
the original passkey method/time and records a closed `email_attached` audit fact
with owner, initiating session and replacement session IDs. Final proof consumption
rechecks time after all writes, including audit waits. Any failure rolls the whole
transaction back; no replacement secret is returned before commit.

The shared target-email lock serializes mailbox signup and competing attachments.
If another account owns the address, completion rejects without transferring any
identity or credential. If attachment wins first, mailbox login still rejects the
stronger account. Email/password login, password enrollment/reset and mailbox-only
lifecycle/recovery remain unavailable for that policy after contact verification.
A confirmed contact address does not become a recovery factor.

## Evidence and limits

Fifteen PostgreSQL attachment tests cover migration/data preservation, exact realm/
owner/session/browser/token binding, weak/stale/future/expired/revoked sessions,
replacement and admission bounds, occupied targets, concurrent one-use completion,
both mailbox-signup race orderings, rollback, revocation cleanup and time crossing
during observed row/audit waits. Three HTTP cases cover captured-mail completion,
rotation, generic initiation, opt-in routes, boundary guards and delivery failure.
These storage fixtures deliberately arrange passkey-method sessions; they do not
claim native private-key proof or actual SMTP delivery. Existing native signup and
sign-in evidence is documented separately. The [native SMTP suite](../../tests/browser/passkeys/attachment/README.md)
now proves original resident/UV anonymous platform/USB signup, actual configured
SMTP delivery, independent binding rejection, explicit reference-page confirmation,
fragment removal/no GET mutation, preserved owner, old-session revocation, replay
denial, occupied-target rejection, weaker-path denial and later bound/discoverable
passkey login. Aggregate database facts verify preserved method/time and policy.
See its [canonical evidence](../../tests/browser/passkeys/results/2026-10-19/chromium-email-attachment.json).
Owned database and three recipient messages are removed; no raw proofs or cookies
are persisted. Other browsers, physical devices and full stronger-account
lifecycle/recovery remain open.
