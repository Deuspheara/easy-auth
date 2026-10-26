# ADR0048: Authenticated encryption and quarantined backup restoration

Date: 2026-10-26. Status: proposed implementation for AUTH-49; full recovery
validation pending. Production/provider/OS acceptance and release prerequisites
remain deferred; this decision authorizes no deployment or release.

## Scope and dependency choice

Use the existing PostgreSQL custom archive with the maintained age command for
offline backup encryption. Keep this outside authentication core/HTTP and normal
server startup. No custom cipher, envelope format, signature, plugin framework or
runtime Go dependency is introduced. Native X25519 recipients/identities are the
explicit initial operator profile; SSH/plugin/passphrase selection is not inferred.
Use the reviewed command's own key parsing and encryption implementation.

The installed OpenSSL3.6.2 is below the CMS AuthEnvelopedData integrity fix in3.6.3
([CVE-2026-34182](https://www.cve.org/CVERecord?id=CVE-2026-34182)); no CMS handler is
added. [Upstream age1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2)
source stays unchanged. A build-only module selects x/crypto0.56.0 for the
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354)/
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) fixes. Its raised minimum Go
version is satisfied by checksum-pinned Go1.27.3; source/binary metadata and exact
locks are checked. Pinned govulncheck1.9.0 assesses source and all three binaries.
Affected imported packages fail even if symbols are uncalled. Unimported OpenPGP's
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) stays reported, with explicit
package-graph evidence; there is no advisory ignore or application-policy waiver.
Capture the exact BSD-style notices/Go patent grant and retain them with binaries.
This is bounded dependency assessment, not legal or independent security approval.

## Archive and key boundary

Stream `pg_dump --format=custom --no-owner --no-acl` into encryption, checking both
process exits. Create new ciphertext files privately and refuse overwriting. The
dump remains a consistent single-database snapshot, not a backup of cluster roles,
external configuration or encryption/signing/provider keys. Keep recovery identities
in protected separate custody; test identities are owned and disposable. Rotation
needs retained old reading keys for still-retained archives; losing them cannot
select an insecure fallback. File unlinking does not promise physical erasure.

Record the selected snapshot's ciphertext digest and schema/source/tool metadata
in separately protected inventory. Require its expected digest before decryption.
A hash is not a signature: age encryption authenticates ciphertext integrity, not
the sender, and anyone with a recipient can create a new encrypted file. Restoration
therefore accepts only explicitly selected trusted backups and trusted metadata.
It does not decide which snapshot is current or reconcile lost revocation history.

The [age format](https://age-encryption.org/v1) authenticates streaming chunks and
requires a valid final chunk. Its [command contract](https://github.com/FiloSottile/age/blob/v1.3.2/doc/age.1)
permits authenticated partial output before a later error. Do not stream decrypted
bytes directly into PostgreSQL. Bound/time-limit decryption into a new private
quarantine file; require full successful completion before checking custom-archive
format/listing and invoking restoration. Delete failed/partial plaintext without
ever passing it to PostgreSQL. Private file permissions do not establish production
disk encryption, secure deletion or key-management qualification.

## Restoration and qualification

Restore only into a newly created quarantined database with no app/notification/
provider-revocation process using it. Reject an existing destination; do not use
`--clean`. Use transactional, error-stopping `pg_restore --no-owner --no-acl` and
review schema, migration state, counts and scoped identity invariants without
printing private rows. Even a valid archive executes SQL and must be trusted.

A snapshot can revive revoked/deleted credentials, one-use proofs or side effects.
Quarantine is mandatory until incident/session/key/configuration and pending-job
policy is reconciled. Ordinary startup/realm verification does not perform that
reconciliation. Existing live accounts/passkeys and preview services must remain
untouched. Do not claim remote provider revocation from local restore/erasure.

Require actual owned PostgreSQL data round trips, wrong/missing key, tampering,
truncation, key rotation, full-length failure cleanup and proof that invalid
decryption never invokes restoration. Required repository/security gates,
maintainability review and exact evidence remain before ticket completion.
Retention, failed-DDL recovery/upgrade and incident stale-key/token drills remain
part of AUTH-49. The SAML waiver's limits and outbound OIDC release gate remain.
