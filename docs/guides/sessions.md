# Managing browser sessions

Passkey sign-in additionally records an internal authentication method in migration
0008: email, password, passkey or legacy_unknown. It is separate from the public
inventory/time fields. Migration does not infer historical methods, and password
enrollment rotations preserve their initiating method/time. Migration 0009 adds
account policy: passkey-required accounts accept only passkey-method sessions,
including for fresh revocation, and inventory excludes weaker-method sessions.
Owned session controls also work without email. Complete stronger-account
lifecycle/recovery remains an M03 gate before ordinary passkey composition.
See the [optional-mailbox guide](optional-mailbox.md).

The embedded router and standalone service share the same session controls. A valid session can list its own user's active sessions in the configured realm. Revoking an individual session or all sessions requires authentication within five minutes. Touching a session or rotating it does not reset that window; sign in again when a sensitive operation returns 401. Ordinary logout remains available without fresh authentication.

## HTTP API

| Request | Result |
| --- | --- |
| `GET /v1/sessions` | Up to 50 owned active sessions and an optional `next` UUID cursor |
| `GET /v1/sessions?after=<next>` | Continue in ascending public-session UUID order |
| `POST /v1/sessions/revoke` with `{"id":"<session UUID>"}` | 204; revoke an owned active session |
| `POST /v1/sessions/revoke-all` with `{}` | 204; revoke all owned sessions, including the caller, and cancel outstanding proofs |

Use the existing HttpOnly session cookie. Every POST requires the exact configured Origin and JSON content type. Unknown JSON/query fields, duplicate cursors, malformed UUIDs and duplicate cookies are rejected. Shared account/source admission may return 429; internal failures use generic errors. There is no client-supplied user or realm parameter.

An unknown, foreign, expired or already-revoked target UUID has the same 204 no-op result. No other user's session changes and no target-specific existence information is returned. Revoking another owned session leaves the caller's cookie intact. Revoking the current session or all sessions clears all five alpha authentication/action cookies. Cookie clearing alone is not revocation: replaying an old cookie fails subsequent server validation.

## Inventory fields

Every entry has `id`, `current`, `created_at_ms`, `last_seen_at_ms`, `expires_at_ms`, `idle_expires_at_ms` and `authenticated_at_ms`. Timestamps are Unix milliseconds; `authenticated_at_ms` is null for legacy sessions without trusted authentication provenance. `idle_expires_at_ms` is the earlier of last activity plus 30 minutes and absolute expiry. Absolute lifetime remains seven days. The UUID is a management identifier and cannot authenticate a request.

No bearer secret, verifier, password, mailbox, IP or user agent is returned. Listing validates and updates activity for the caller only; it does not keep other devices alive. Expired/revoked sessions are omitted. A current session may appear on a later page because ordering is by UUID. Cursors are public IDs, not credentials; supplying another user's cursor never widens ownership. An invalid caller gets 401 even if the cursor would yield an empty page.

Pages reflect an evolving inventory. Concurrent sign-ins, expiry and revocation may change later pages; UUID order is not chronological and this is not a cross-request snapshot. Restart pagination to refresh the view. The API bounds returned data, while historical-row retention and load tuning remain operational release work.

## Revocation and concurrent work

Revoke-all atomically revokes the user's sessions, removes pending email sign-in/password-reset/email-change/deletion proofs, and writes one `all_sessions_revoked` audit event. Other users and realms are unaffected. Individual changes use the existing `session_revoked` event; no event is added for a no-op target. Audit failure rolls back the session/proof mutations.

Email/user/session locks serialize revoke-all with credential and session issuance. A login committed before revocation is included. A genuine login ordered after the revocation commit can establish a new session: the credentials themselves are still valid. Two concurrent revoke-all requests using previous sessions have one winner; the other fails authentication. These operations do not permanently block a device or replace a compromised credential.

Subsequent validations reject revoked cookies across replicas. Requests already authorized can finish, and the consuming application remains responsible for its business authorization/transaction policy. This controls easy-auth browser sessions, not future native refresh families, provider sessions or outbound OIDC tokens. Stronger-factor step-up and complete device-management reference UI remain later milestones.

Migration `0005_session_management.sql` adds the active-session pagination index and audit kind. Apply it through the normal shared startup migration path; published earlier migrations are unchanged. See [ADR 0006](../architecture/adr/0006-session-management.md) for ordering decisions.

Rust callers use `Auth::list_sessions`, `Auth::revoke_session` and `Auth::revoke_all_sessions`. Custom `Repository` adapters must implement the new bounded listing and atomic revocation operations; there is no permissive default. The individual operation returns true only when the initiating session was revoked. Derive sensitive-action source keys from trusted connection context.
