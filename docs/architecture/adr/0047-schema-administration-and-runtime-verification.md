# ADR0047: Separate schema administration from runtime verification

Date: 2026-10-26. Status: accepted for the bounded local schema/role increment;
AUTH-49 operational recovery and production acceptance remain incomplete.

## Context and scope

The owner directed locally executable operational work while deferring real
provider/OS/production acceptance. AUTH-48/AUTH-47 release prerequisites remain
open; this decision neither clears them nor authorizes deployment or release.
Separate migration/runtime PostgreSQL roles are part of AUTH-49, together with
recovery, encrypted backups, retention and incident/key drills that remain separate
work in the same ticket. SAML waiver limits and outbound OIDC's release gate remain.

Configured startup currently invokes the public PostgreSQL migration method.
The pinned SQLx implementation first executes `CREATE TABLE IF NOT EXISTS
_sqlx_migrations`. An owned PostgreSQL 17 probe confirmed that this fails without
schema CREATE privilege even when the history table already exists. The probe's
new database/role were removed; it is not production-role qualification.

## Decision

Keep the public `Postgres::migrate` administration API and immutable migrations.
Move its existing implementation into the owning private `schema` module in a
separate, regression-tested structural commit before adding behavior.

Add `Postgres::verify_schema` for an already-migrated runtime profile. Use SQLx's
existing migration lock/history APIs and embedded migration checksums. Require
every known up migration, no dirty/future/missing row and exact library-produced
checksums; never repair, create history or apply DDL in verification. A dedicated
checked-out connection closes on success/error/cancellation, preserving the pool
budget and preventing session locks/timeouts leaking into later requests. Bound
verification and server-side lock/statement waits; errors remain credential-free.
Apply that connection-lifetime safety to administration as well; SQLx retains
ownership of migration SQL, transactions, checksums and serialization.
An observed cancelled administration waiter survived socket close until its lock
could be acquired. Administration therefore also has a two-second server lock
wait limit; statement execution is not given the short verification limit.
Contention fails rather than silently retrying or relaxing migration integrity.

Trusted `AUTH_DATABASE_MIGRATIONS` selects exact `run` or `verify`, default `run`
for the existing compatibility contract. Unknown/empty/non-Unicode input fails
before database connection, with no fallback from failed verification to DDL.
Both executable/embedded composition use the same configured repository. Normal
realm initialization and auth operations still require their ordinary DML grants.
Verification is not a general PostgreSQL privilege audit or application permission.

Add explicit `easy-auth migrate` administration using only required DATABASE_URL,
with a bounded one-connection pool, no HTTP listener, SMTP/provider loading or
notification worker. The operator runs it with migration credentials in a separate
process, then serves with separately provisioned runtime credentials and `verify`.
No role or credential is automatically created or installed by application startup.
The new library administration operation uses the same database composition, not a
second migration engine. Help/version remain configuration/database-free; extra
arguments still fail without reflection. Never put a credential in CLI arguments.

## Evidence required and limits

Real PostgreSQL must prove missing/dirty/future/checksum refusal with unchanged
history/data, current-schema success, actual separately authenticated role grants
and forbidden DDL/history changes, bound/cancelled migration-lock waits and normal
auth/realm behavior. Genuine subprocesses must exercise administration and shared
configured startup, with sanitized failures and no unintended listeners/workers.
Existing migration/HTTP tests remain unchanged; a matching schema is not evidence
of mail/provider delivery, disaster recovery or arbitrary rolling-DDL compatibility.
Fresh connections after DDL preserve ADR0038's prepared-statement boundary.

Reuse already locked Tokio/SQLx; adding a direct Tokio runtime edge to PostgreSQL
introduces no package/version or crypto implementation. Keep metadata/locking in
PostgreSQL, selection in server configuration, and CLI dispatch as composition.
No SQL/persistence rule moves into HTTP/core, new crate/framework or migration rewrite.
Required workspace/PG/security and maintainability gates remain mandatory for
subsequent changes.

The [local verification record](../../security/database-role-verification-2026-10-26.md)
now records passing required Rust/real-PG/security checks, exact committed role CI
replay, real SMTP/HTTP/realm/logout observations, source identity and the failures
corrected without assertion/policy relaxation. This accepts only this decision's
schema/role boundary; the remaining AUTH-49 requirements are not completed.

## Responsibility review

The private PostgreSQL `schema` module owns SQLx metadata, locking and connection
lifetime. Server `configuration/database` owns the shared pool factory and explicit
runtime selection; its crate-only visibility supports the separate `administration`
command module without exposing internal APIs to consumers. The library reexports
only the deliberate operation. Owned OIDC examples can continue compiling the
configuration module without unused administration code or warning suppressions.

New PostgreSQL tests separate history integrity from observed lock/cancellation
scenarios. Python fixture modules separate service ownership, principals, process
lifetime, mailbox behavior and source/receipt evidence. Handwritten new modules
are below300 lines and Python functions below50; existing entry files retain only
declarations, reexports and dispatch. No schema migration or lockfile version is
changed, persistence rule duplicated in HTTP/core, or structural cleanup deferred.
The initial schema extraction remains its own commit before behavior changes.
