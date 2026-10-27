# Retention cleanup assessment

AUTH-49, 2026-10-26. The initial schema38 assessment below preceded implementation.
The explicit maintenance boundary now follows
[ADR0050](../architecture/adr/0050-bounded-realm-retention.md), with exact
[local/workspace/upgrade/security evidence](../security/retention-verification-2026-10-27.md). Use the
[retention guide](../guides/retention.md), not ad hoc production deletes from this
matrix. Historical source/catalog evidence below retains its original scope.

## Scope and observed schema

A new disposable database was created inside the verified goal-owned local
PostgreSQL container. The existing schema-administration executable applied all
38 migrations. Each applied version/success/checksum was compared with the
immutable source SQL using SQLx's SHA-384 checksum. Catalog inspection found
47 `auth_*` tables, 80 foreign keys and 123 indexes. The owned database was removed
and absence checked. No existing database, account, credential or preview was used.

Source: clean `408794384bbd83e261f275bf22c4534887a67000`.
The reused, previously qualified schema38 executable SHA-256 was
`974b9046d9a7c246df0487de41c5336e924cdb904d819d5cd3d9a6409e1dc2a4`;
this is explicitly a reused build, not a fresh build of that documentation commit.
Private catalog receipt: `auth49-retention-catalog-20261026.json` (metadata,
definitions and migration hashes; no application-row extraction).

All proposed operations are realm scoped. Stored final database caps are used in
addition to the conditions below. In-memory/browser expiry alone is insufficient.
Eligibility never means a parent may cascade-delete arbitrary children. Prune
eligible children separately, and retain referenced parents until no child/audit
reference remains. Supporting indexes and actual query plans are still to be
qualified; a row limit alone does not bound scan work or lock wait time.

## Cleanup eligibility contract

| Table | Eligibility and preservation requirement |
| --- | --- |
| `auth_email_challenges` | Stored `expires_at` passed; retain live browser-bound sign-in proofs. |
| `auth_password_resets` | Stored `expires_at` passed; never mutate the credential/version. |
| `auth_email_changes` | Stored `expires_at` passed; confirmation/cancellation alone is not an earlier cap. |
| `auth_account_deletions` | Stored `expires_at` passed; maintenance cannot delete the user. |
| `auth_email_attachments` | Stored `expires_at` passed; maintenance cannot attach or detach an address. |
| `auth_passkey_enrollments` | Stored `expires_at` passed; preserve usable ceremony state. |
| `auth_passkey_authentications` | Stored `expires_at` passed; preserve usable assertion state. |
| `auth_passkey_signups` | Stored `expires_at` passed; maintenance cannot create an account. |
| `auth_passkey_recovery_setups` | Stored `expires_at` passed; preserve the actual recovery-code state. |
| `auth_passkey_recovery_replacements` | Stored `expires_at` passed; do not promote a candidate credential. |
| `auth_passkey_recovery_claims` | Original claim expiry passed and no notice/replacement children remain. Preserve consumed code/version state; deletion is not cancellation or completion. Audit claim UUID metadata is not a foreign key. |
| `auth_oauth_transactions` | Original `expires_at` passed, including consumed transactions; never reset a consumed capability while its original cap can still be used. |
| `auth_saml_requests` | Original `expires_at` passed; no change to source or signature policy. |
| `auth_saml_replays` | `retain_until` passed. Keep both response/assertion reservations through their original replay window across revision changes or account deletion. |
| `auth_oidc_deleted_subjects` | `blocked_until` passed; preserve the full existing callback cooldown. |
| `auth_saml_deleted_subjects` | `blocked_until` passed; preserve the full existing callback cooldown. |
| `auth_rate_buckets` | All current dimensions use ten-minute windows. Keep current and immediately previous windows, and future rows; prune only older windows. No active-budget reset. |
| `auth_oauth_admission` | Same ten-minute window preservation; no active-budget reset. |
| `auth_issuer_token_admission` | Existing core policy uses one-minute windows. Keep current/previous/future windows. Existing request-time pruning is separate and unchanged. |
| `auth_security_notifications` | Ordinary exhaustion (`attempts=8`), expired/absent lease and explicit operator age horizon. Retryable work survives. For expired recovery claims, obsolete bound notices may be removed separately only after their lease ends; no SMTP delivery/receipt is inferred. |
| `auth_audit` | Only the selected explicit operator age horizon; preserve all remaining fields, attribution and constraints. Supporting sessions/grants can outlive their authority because of retained events. No arbitrary export/read API is added. |
| `auth_issuer_access_tokens` | Original absolute access expiry passed, including revoked rows. Retention is not a replacement for authenticated introspection/revocation. |
| `auth_issuer_native_refresh_tokens` | Family's original absolute expiry passed and no retained audit generation reference. Keep spent generations while a family may detect replay. Do not use the short code or access-token expiry here. |
| `auth_issuer_native_families` | Original absolute family expiry passed; no retained access, refresh-generation or audit references. Revoked/idle-expired alone is not an earlier physical-deletion cap. |
| `auth_issuer_native_consents` | Original grant expiry passed and no family child. Remove separately before authorization; do not cascade a live offline family. |
| `auth_issuer_authorizations` | Original authorization expiry passed and no consent/family/access/audit references. Short code expiry never permits deleting a longer native grant. |
| `auth_sessions` | Original absolute session expiry passed and no audit/authorization/ceremony/proof children. Do not cascade retained grant/audit state or choose cookie idle expiry as the physical-deletion cap. |
| `auth_apple_grants` | Reuse existing owning maintenance: erase expired queued ciphertext, recover exhausted expired leases and later prune terminal metadata. Preserve active captured grants, live leases and original final caps; expiry is not remote revocation. |

## Durable records excluded from general expiry cleanup

| Table | Reason |
| --- | --- |
| `auth_realms` | Trusted realm provisioning/decommissioning is a different operation. |
| `auth_users` | Expiry does not authorize account deletion. |
| `auth_password_credentials` | Credential lifecycle belongs to password/account operations. |
| `auth_passkeys` | Credential lifecycle belongs to passkey/account operations. |
| `auth_passkey_recovery_codes` | Includes consumed/version state that prevents code reuse; no generic credential expiry. |
| `auth_oauth_connections` | Trusted provider configuration and disable history. |
| `auth_oidc_identity_policies` | Trusted default-deny/JIT/link policy; expiry does not reset it. |
| `auth_oidc_identities` | External identity ownership; deleting can queue captured Apple grants. |
| `auth_saml_registrations` | Trusted protocol configuration and disable history. |
| `auth_saml_certificates` | Explicit operator-approved trust windows/pins; no automatic trust deletion or rollover. |
| `auth_saml_identity_policies` | Trusted default-deny/JIT policy. |
| `auth_saml_identities` | Exact external subject ownership; no matching-email relinking. |
| `auth_issuer_clients` | Trusted registration/revision and disable policy. |
| `auth_issuer_sectors` | Durable pairwise-subject namespace. |
| `auth_issuer_subjects` | Stable pairwise subject; cleanup must not silently allocate a different identity. |
| `auth_issuer_key_sets` | Active-key selection/global issuance policy; incident reconciliation is separate. |
| `auth_issuer_keys` | Retained verification/revocation metadata and JWKS windows; private keys are external. |
| `auth_issuer_native_refresh_policies` | Explicit offline grant policy/revision. |
| `auth_issuer_native_consumers` | Explicit authenticated audience/consumer configuration. |

## Reference and concurrency findings

Beyond durable realm/user ownership, the catalog confirms four audit parent
categories: sessions, authorizations, native families and refresh generations.
Session references distinguish initiating
and target sessions. Native audit facts also retain a family/generation; a cleanup
implementation must check those references even when the initiating-session field
is null. Nulling audit metadata merely to permit deletion would violate immutable
event shapes and change the recorded fact.

Recovery claims have cascading notice/replacement children. The ordinary SMTP
receipt path locks owner, claim and notice in that order and rechecks both proof
and lease deadlines after waits. Maintenance must not invert that order across
multiple table operations or erase a currently leased child via its parent.
Each category needs its own bounded commit; errors may follow earlier committed
batches. Locked rows can be deferred; zero deletions does not prove no backlog.

Issuer families and authorization parents also have cascading children. Independent
leaf pruning avoids turning a limit of 64 parents into many thousands of generation
deletions. The original family cap, rather than consent/code/access expiry, protects
reuse detection. Retained audits can deliberately keep those verifier rows longer.

Apple maintenance is already owned by
`maintenance/apple.rs` (extracted unchanged from the Apple revocation module).
General maintenance must make
that same lifecycle available without depending on an active provider worker or
silently enabling Apple. Its current counts cover expired ciphertext, not every
maintenance action; any public report must name what was counted accurately.

## Required implementation evidence

The implementation must add real PostgreSQL positive/negative, realm-isolation,
bounded-batch, lease and concurrent-wait cases, including retained issuer/audit
graphs and actual reuse/replay rejection. Every matrix row needs coverage; checking
only email challenge expiry cannot establish complete retention. Standalone and
embedded paths must share core policy. Run required workspace, real-database and
security gates after behavior changes, and update public contracts/operator guides.

Add immutable new migration indexes where needed and update upgrade/recovery
fixtures for the resulting schema; previous schema38 overlap evidence must not be
relabeled. This section records the eligibility/reference assessment. Current
maintenance has bounded local qualification recorded above. The separate
[incident qualification](../security/incident-recovery-verification-2026-10-27.md)
records stale-authority recovery controls; production recovery and complete
incident-inventory/promotion decisions remain operator responsibilities.

## Structural preparation

At structural checkpoint `4855fa7c75b8fee2ef608d8aeff8dd520fc71c88`, Apple maintenance
was extracted separately to `crates/auth-postgres/src/maintenance/apple.rs` with bytes
matching the previous module exactly (historical SHA-256
`8ea5c167b79ddfb2c14d5f3b9af19059eea0d911e53117e168791b9d2607b1f2`).
The `apple-grants` compile boundary and public method are unchanged. This prepares
an owning maintenance location without adding general cleanup or enabling a
feature. The entry files contain declarations only; no public visibility is added.

Local checks on this extraction over design commit
`5f6d5121e46c1898d180bc7af7012498d0856e92`:

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked -p easy-auth-postgres --all-targets -- -D warnings`: passed.
- The same strict Clippy command with `--all-features`: passed.
- `cargo test --locked -p easy-auth-postgres --all-features --test lifecycle
  'oidc::apple::grants::'`: 23 passed, zero failed/ignored, using owned real
  PostgreSQL databases. Existing assertions were unchanged, including actual
  lease recovery/backoff, expiry after waits and realm isolation.
- Scoped redacted secret scan and whitespace checks: passed. The original 73
  protected files retained their hashes and exact modified/untracked set; the
  original index remained empty.

The first invocation used an incorrect `lifecycle::` filter and selected zero
tests; it is not accepted as test evidence. The corrected run asserts the actual
23-test result, not merely Cargo's successful exit. Private qualified receipt:
`auth49-retention-extraction-qualified-results.json`; initial logs remain retained.
This is focused structural validation, not a fresh full-workspace, release or
hosted-CI result. Complete retention behavior still requires the gates above.
