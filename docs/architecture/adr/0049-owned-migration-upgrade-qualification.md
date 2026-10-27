# ADR0049: Qualify schema failure and replica replacement with owned revisions

Date: 2026-10-26. Status: accepted for the selected local recovery/software-upgrade
increment; complete AUTH-49 operational/production acceptance remains pending.

Use the committed schema37 ancestor
`0783ff48b6409d362fbcae527f46a483ca66fb55`, the validated pre-operations schema38
revision `e6a061f9e6804eda323ce1af78b0369c73cdd021`, and the current schema38 executable
for an actual owned upgrade. Export the two old public sources into new private directories;
verify ancestry, unchanged dependency/toolchain inputs and identical immutable
migrations1–37/38. Build with the existing pinned Rust/locked dependencies and separate
target output. No published migration or protocol assertion is rewritten.

Create a new labelled PostgreSQL/Mailpit fixture and disposable accounts/replicas.
The old binary bootstraps its own schema37 using its existing administration-capable
startup; this legacy behavior is not least-privilege runtime qualification. Current
runtime verification must refuse that old schema without DDL/fallback. After an
encrypted snapshot, stop old writers and observe their database connections gone.
[ADR0038](0038-native-token-lifecycle.md) requires fresh connections after DDL;
this decision does not establish mixed-version in-place DDL compatibility.

An owned fixture index on an owned probe table deliberately occupies migration38's
later index name. Run the real current migration command. It must fail after the
original earlier ALTER/CREATE statements, leaving neither their effects nor a new
history row. Compare private legacy rows/history and actual catalogs, then observe
no abandoned migration lock/connection. Do not fix this by editing checksums/history,
ignoring errors or changing migration assertions.

Exercise two recovery paths: restore the selected encrypted pre-failure snapshot
into a newly created quarantined DB and migrate it; separately inspect/remove only
the deliberate owned conflict and rerun the original migration against the source.
Preserve legacy identities, sessions and source isolation. A restored snapshot stays
disconnected from runtime until incident reconciliation; successful schema upgrade
alone cannot promote it. External key/configuration custody remains separate.

After successful administration and privilege review, start the prior schema38
software with its legacy administration-capable startup, then replace it one
instance at a time with the current restricted-runtime/explicit-verification
composition. Both actual software versions must serve the same original sessions
during overlap on unchanged schema38. Continuous owned session probes must retain
request progress, identity and availability while peers start/stop. Then also
replace a current replica with another current replica while a survivor serves.
The schema37 binary must refuse the future schema.
The schema-changing step has a deliberate writer-drain window; no zero-downtime,
arbitrary-version/downgrade or production orchestration claim follows.

Require real SMTP/HTTP/PG observations, negative and working controls, full scoped
cleanup, exact source/binary receipts and public operator limits. Keep owning
fixture responsibilities separate from application policy; add no HTTP admin route,
generic migration engine, new crate or crypto. Retention and stale-key/token incident
work remain AUTH-49 requirements. AUTH-48/AUTH-47 release prerequisites, SAML waiver
limits, outbound OIDC release gate and real provider/OS/production acceptance remain.

The [verification record](../../security/migration-upgrade-verification-2026-10-26.md)
records exact committed CI replay, source/binary/immutable-input identities, actual
transactional failure/recovery, selected software overlap, continuous session probes,
cleanup and remaining limits. It accepts this selected boundary without completing
retention or incident reconciliation.
