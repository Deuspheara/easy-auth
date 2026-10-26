# Incident revocation and restored-snapshot reconciliation

Keep a restored database quarantined from application traffic, SMTP and provider
workers until the incident's affected identities, credentials, keys and queued work
are reconciled. A successful migration, exact table comparison or retention pass
cannot make an older snapshot authoritative. The local AUTH-49 incident drill is
under qualification; it does not approve promotion or production recovery.

## Record the reductions outside the snapshot

Maintain a separately protected incident record of the exact affected realm,
issuer/key identifiers, account/session scope, client or native grant scope, and
required configuration/credential changes. Record the selected backup's provenance
and time and which reductions occurred later. Do not put bearer credentials,
private keys, provider tokens or raw private database rows in tickets or logs.
A snapshot cannot contain revocations that occurred after its capture. An incomplete
incident record is a reason to retain quarantine, not evidence that nothing changed.

Use the existing trusted configuration and revocation operations. Their authority
boundaries differ:

- Owner session revocation requires a genuine current fresh owner session. The
  existing `Repository::revoke_all_sessions` revokes that owner's sessions and its
  documented pending local proofs. It is not an operator-wide realm revocation API;
  a database UUID, matching email or incident note cannot manufacture owner proof.
- Native family revocation requires current matching client authentication and
  possession of a matching refresh/access credential. It reduces that family and
  descendant access even after the owner session or grant policy becomes unusable.
  Public client identity alone does not authorize introspection or select a foreign
  family's authority. Unknown/repeated revocation is deliberately nondisclosing.
- Trusted `Postgres::disable_issuer_key` scopes an explicit key to realm/issuer.
  Current local issuance and retained-key access checks fail closed. Disabling the
  sole key makes current key metadata unavailable; it does not publish a usable
  empty set or silently pick another signer. Namespace disable and individual key
  disable have different publication semantics; see [issuer setup](issuer-standalone.md).

Apply only reductions supported by the actual retained authority and current trusted
configuration. Stop if required proof, credentials or incident scope is missing.
Do not inject a session hash, rewrite authentication time, edit migrations, treat
an unavailable response as successful revocation, or re-enable a key to make the
procedure appear successful. Repeating a reduction cannot clear its first recorded
revocation time. A revoked session cannot authenticate a second owner operation.

## Recover and verify while isolated

Follow the [encrypted archive](backups.md) procedure into a new quarantined database.
Verify the exact schema and reviewed configuration; schema administration requires
[separate privileges](database-roles.md). Keep the current live database and its
revocation history separate from the restored target. Replay each applicable
recorded reduction against the target through its owning operation, using genuinely
retained authority where that operation requires it. Recheck stale credentials
against the exact local acceptance path, with positive controls in an unaffected
realm. Verify that target operations do not modify the live source.

Account deletion, changed credential ownership, consumed one-use proofs, provider
trust changes, notification leases/delivery and Apple revocation jobs need their
own incident decisions. Revoking sessions does not restore those decisions, reset
recovery codes safely or prove remote provider revocation. Do not run restored
workers as a way to discover whether their old jobs are still appropriate. There
is no generic automatic promotion/reconciliation command in this implementation.
Keep quarantine until every relevant decision has been reviewed and applied.

Local key disable cannot recall an already cached public key or erase a signed ID
token and downstream application session. Such a token's signature can remain
mathematically valid. Consumers need their own expiry, incident deny/configuration
and session invalidation policy; do not claim immediate offline JWT revocation.
Ordinary rotation still requires the existing publication/overlap windows and
protected private-key distribution. Emergency disable does not waive propagation
checks for a replacement. Losing a required backup reading key cannot select a
plaintext or alternate-crypto fallback.

## Local drill boundary

The new real-PostgreSQL incident scenario uses the maintained normal account,
RS256 signing, native consent/issuance and authenticated-consumer fixtures. A
physical PostgreSQL copy of its own stopped SQLx test database captures authority
before an incident. No runtime listener or worker uses that copy. The same genuine
credentials first work on the source, are revoked there, and then work again on
the older copy until the recorded reductions are reapplied. Separate families show
that family revocation and key disable each reduce their own authority; another
realm remains usable. The test also demonstrates cached ID-token signature
verification surviving local key disable, making that limitation explicit.

This is a database snapshot/revocation regression, not a new backup format,
production cloning recipe, encrypted-archive assessment or independent provider
qualification. The separate encrypted backup drill covers actual archive creation,
authenticated decryption, restoration and runtime CONNECT refusal. Complete local
workspace/security gates and exact qualification evidence remain required before
accepting the incident increment. Real provider/OS/production acceptance, AUTH-47/
AUTH-48 prerequisites, SAML waiver limits and outbound OIDC release gate remain open.
