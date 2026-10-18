# ADR 0006: Owned session inventory and serialized revocation

Status: accepted for alpha, AUTH-15, 2026-10-18.

A session's opaque UUID is a public management identifier, never an authentication credential. The secret and its verifier are excluded from inventory DTOs. Listing validates the caller and returns only active sessions belonging to its user in the configured realm. Pages contain at most 50 items in UUID order, with an optional UUID cursor; a foreign cursor cannot widen ownership. Timestamps are Unix milliseconds; legacy unknown authentication time is null. Listing touches only the caller's last-seen time, not other devices. Pagination is an evolving inventory, not a snapshot across requests.

Individual revocation requires authentication within five minutes, locks the user before revalidating the caller, and updates only an owned target session. Unknown, foreign, expired and already-revoked targets have the same no-op response. Revoking the current session clears browser authentication cookies. Ordinary logout remains idempotent without a freshness requirement.

Revoke-all takes the current email advisory lock, then the user and fresh initiating session locks. It revokes all that user's sessions, including the caller, removes outstanding email sign-in/reset and account-action proofs, and writes one safe audit event in the same transaction. Existing session issuers lock the user, so session creation is ordered with this commit. A concurrent login that commits first is revoked; a genuinely new login ordered after revocation can create a session. This is not a credential-disable or permanent device-block operation. Concurrent revoke-all requests using old sessions have one successful winner.

Database time governs strict idle, absolute and freshness bounds. Every subsequent validation rejects revoked sessions across replicas; operations already authorized may finish. Freshness is authenticated_at, preserved across rotation. Shared sensitive-action admission remains bounded by account and source. Transaction failures roll back revocation, proof cleanup and audit together.

No client-supplied user or realm, IP/user-agent inventory, JWT/refresh credential or external application session is introduced. The API is headless; the later reference application milestone will provide complete device-management UX. Stronger-factor step-up policy remains a release gate before adding higher-assurance credentials.
