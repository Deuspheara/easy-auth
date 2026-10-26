# Realm retention maintenance

The explicit core/PostgreSQL maintenance boundary and one-shot server command are
implemented locally; AUTH-49 qualification is in progress. This guide does not
establish production recovery, legal retention periods or independent review.
No scheduler or HTTP administration route is enabled automatically.

## Select a realm and explicit retention choices

Use the exact intended non-nil realm UUID and a protected `DATABASE_URL` already
supplied through your operator environment. The command uses auth-table DML and
read-only migration history; it does not need schema DDL privileges. Keep that
credential outside ordinary application SQL and browser input. See
[database roles](database-roles.md).

After separately applying the current schema with `easy-auth migrate`, run:

```sh
AUTH_REALM_ID="$REALM_ID" \
AUTH_RETENTION_AUDIT=keep \
AUTH_RETENTION_NOTICES=keep \
easy-auth retention
```

Both horizon settings are required, even when the choice is to keep the records.
`keep` retains audit events or ordinary exhausted notifications indefinitely.
Alternatively, supply a positive canonical decimal age in whole seconds, from
1 through 3153600000. Fractional, signed, whitespace-padded, zero, leading-zero,
non-Unicode and excessive inputs fail before a database connection. The upper
bound is an input/resource limit, not a recommended evidence or legal policy.
Choose the two horizons independently; there is no default deletion period.

`AUTH_RETENTION_NOTICES` controls ordinary notices after all eight automatic
claims are exhausted. Retryable notices remain. A recovery-start notice whose
original recovery claim has expired is obsolete: maintenance may remove it once
its lease ends, even with `keep`. Removing that notice cannot acknowledge delivery,
start a recovery delay, complete a claim or reset a consumed recovery code.

The command validates exact current migration history before cleanup. An older,
missing, future, dirty or checksum-mismatched history fails without migration or
cleanup fallback, even if `AUTH_DATABASE_MIGRATIONS=run` is set. It does not
provision a realm, start a listener, construct SMTP/provider services or select
protocol activation. Runtime server settings do not authorize maintenance.

## One finite pass and committed effects

One invocation visits 28 closed lifecycle categories. A normal category selects
at most 64 rows, locks them with `FOR UPDATE SKIP LOCKED`, then rechecks its expiry
and references in a new SQL statement before deletion. This newer snapshot sees
children committed while candidate locks were being acquired. Every query keeps
realm scope. Table/SQL identifiers are fixed implementation data, never arguments.
Each owned transaction explicitly selects Read Committed; a different embedded
pool session default cannot silently remove the fresh-snapshot guarantee.

Each category commits separately. The transaction closes its owned connection on
completion/cancellation; lock/statement waits and the total category operation are
bounded. The total category deadline is five seconds including pool acquisition;
server lock and statement limits are one and two seconds respectively. These are
operational resource limits, not authentication lifetimes or an entire-command
five-second promise. Errors stop later categories and return a fixed diagnostic.
Earlier batches, and a commit whose acknowledgment was lost, may already have
committed. Rerunning is safe; there is no unbounded internal drain/retry loop.

Successful output contains only fixed category names and scalar committed effects:

```text
EmailChallenges: deleted=12 expired_ciphertexts=0 exhausted_leases=0
AppleGrants: deleted=1 expired_ciphertexts=2 exhausted_leases=0
```

The Apple category reuses its existing three-stage lifecycle, with up to 64 rows
per stage in one transaction: erase expired queued ciphertext, exhaust ended final
leases and later delete terminal metadata. Counts distinguish those effects.
Active captured credentials and live original caps/leases survive. Expiry is
never reported as confirmed provider revocation. This maintenance also works in
a default build without selecting an Apple worker; schedule it independently of
active provider sources. See [Apple grant custody](apple-setup.md#protected-grant-capture-component-in-progress).

The output is not an inventory or a proof that the realm has no backlog. Retained
audit references, live children, locked rows, concurrent arrivals and batch limits
can all leave rows behind. Repeated scheduling and aggregate backlog monitoring
belong to the operator. A valid but absent realm receives no provisioned state.

## What expires, and what remains

Pending mailbox/password/WebAuthn/OAuth/SAML state uses its original stored expiry.
Replay reservations use their full `retain_until`; erased-subject cooldowns use
`blocked_until`. Local/OAuth admission keeps the previous and current ten-minute
windows; issuer admission keeps the previous and current one-minute windows.
Future-window rows also remain. Cleanup never resets a current abuse budget.

Expired access tokens can be removed. Native refresh-generation history, including
spent tokens, stays through the family's original absolute expiry so replay still
revokes a live family. Retained audit references can keep expired generations,
families, authorizations and sessions longer. After eligible audit removal, child
rows are pruned independently before parents. Parent cascades do not substitute
for the batch limit. Session idle expiry, revocation, short authorization-code
expiry or cancellation alone do not permit earlier parent deletion.

Maintenance keeps durable users, credentials, consumed recovery-code state,
external identity ownership, pairwise subjects, issuer keys and trusted provider/
client/policy configuration. It cannot delete an account, link by email, disable
an issuer key, replace a private key or recall already delivered mail/downstream
sessions. Backup/log retention, incident revocation and restored-snapshot
reconciliation are separate procedures. A restored old snapshot can revive state
that cleanup already removed from the live store; [backup quarantine](backups.md)
still applies.

## Embedding and upgrade boundary

Trusted embedded consumers call the same `auth_core::run_retention` with a
`RetentionPolicy`, or `RetentionRepository::retain_batch` for one named category.
Use `RetentionHorizon::keep()` or validated `RetentionHorizon::after(Duration)`;
there is no default policy. PostgreSQL implements the shared port. The server
library exposes `retain_database` for the same environment-based composition.
These operations confer no application authorization or local authentication proof.

Migration0039 adds realm/expiry and reference indexes without changing earlier
migrations, rows or foreign keys. Apply schema changes with writers drained and
fresh connections as described in [upgrades](upgrades.md). Historical schema38
software-overlap evidence does not establish that an older executable accepts
schema39. Current upgrade qualification must use the separately pinned schema39
ancestor and actual current software; that requalification remains in progress.

The [complete table assessment](../design/retention-cleanup.md) distinguishes all
47 auth tables and their retention/exclusion rules. [ADR0050](../architecture/adr/0050-bounded-realm-retention.md)
records implementation/qualification boundaries. Full workspace, real database,
security, upgrade and operator acceptance remain pending until their exact evidence
is recorded. SAML's maintainer waiver and the outbound OIDC release gate are unchanged.
