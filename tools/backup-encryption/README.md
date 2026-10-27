# Offline backup encryption tool inputs

This build-only Go module pins upstream age1.3.2 and selects x/crypto0.56.0 to fix
GO-2026-6354/6355. It adds no application/runtime package or Go source. Original
upstream source and module checksum remain visible in binary metadata. The version
suffix explicitly identifies the changed dependency selection. `go.mod`/`go.sum`
must remain unchanged during read-only builds.

`age.json` pins the two supported platform toolchain archives, upstream/scanner
versions/checksums and input hashes. `notice-policy.json` binds all selected module
notices and Go LICENSE/PATENTS. No application license/advisory exemption is added.
The prepared directory includes the complete captured notices for its binaries.

With Python3.12+, prepare a new directory outside source:

```sh
python3 scripts/prepare_backup_tool.py --destination /private/tmp/easy-auth-backup-tool
```

The script isolates Go caches/environment, verifies source/binary scanner inventories,
rejects affected imported packages even if uncalled, and retains every finding.
GO-2026-5932 remains reported for unimported OpenPGP code in x/crypto. Its absence
from the actual package graph is checked; there is no ignore. A private receipt
binds source, inputs, binaries, notices and scan logs. Exact-commit CI refuses dirty
or mismatched GITHUB_SHA. Existing destinations are never reused or overwritten.
This is tooling assessment, not independent security or legal approval.

See [ADR0048](../../docs/architecture/adr/0048-encrypted-backup-quarantine.md).
