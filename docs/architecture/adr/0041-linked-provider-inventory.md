# ADR0041: Owner-scoped linked-provider inventory

Status: accepted boundary; full reference-UI delivery is tracked separately.
Date: 2026-10-24.

## Context

The reference account page needs actual linked-provider metadata. A configured
sign-in button or session list cannot establish which external identities belong
to the account. Browser input must never choose another owner or realm, and an
inventory result must not become authentication, linking or current-trust proof.

## Decision

Add a concrete `Auth::linked_providers` use case and repository operation inside
the existing crates. The PostgreSQL implementation reuses the normal source-aware
active-caller transaction: source, owner and session locks, current policy and
original idle/absolute deadline checks. It reads only the locked owner's identity
rows in the configured realm, checks the retained deadline after the query and
commits the session touch with the read. Storage errors roll back and remain
Unavailable. Existing repository implementations default to Unavailable until
they implement this optional read; no empty-success fallback is invented.

The HTTP GET `/v1/account/providers` returns at most 50 public records containing
an opaque identity UUID, fixed `oidc`/`saml` kind and immutable linked issuer.
It excludes subjects, claims, email, provider credentials, source revisions and
local owner/session secrets. A closed protocol-plus-UUID cursor orders both
namespaces without losing records when their UUIDs coincide. No owner, realm or
source selector is accepted. Use the existing no-store/no-referrer and browser
security boundary. No mutation, external request or new table/migration is needed.

An existing identity can remain linked after source disable or reconfiguration.
Its inventory metadata therefore makes no enabled/current trust claim. The caller
must still have a genuinely current usable session; a disabled provider cannot
validate its old source session or enable a weaker fallback through this read.
Presentation must render issuer strings as text, never HTML or navigation targets.

`Auth::passwords_enabled` exposes only whether trusted composition selected the
existing password service. It permits accurate reference-page presentation and
grants no password, enrollment, recovery or account authority. Optional method
presentation likewise cannot activate an HTTP constructor or select provider policy.

## Verification and limits

Real PostgreSQL tests cover bounded compound-cursor pages, equal UUIDs across
protocols/realms, owner isolation, revoked caller rejection, observed owner-lock
revocation ordering, original-deadline expiry during a blocked inventory read and
session-touch rollback. HTTP tests cover closed selectors,
partial/duplicate cursors, missing/duplicate cookies, public response shape and
OpenAPI. Existing unchanged normal OIDC/SAML producers establish genuine sign-in,
successful inventory and refusal after operator disable; no new cryptographic or
adversarial fixture is introduced.

This is read-only inventory, not social linking/unlinking, provider availability,
complete UI acceptance, protocol certification or independent review. SAML's
ADR0032 waiver is unchanged; unresolved assurance remains separate. Record final
workspace/browser/security and exact-source CI evidence with AUTH-43 delivery.
