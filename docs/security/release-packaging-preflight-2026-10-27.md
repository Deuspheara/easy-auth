# Release packaging preflight — 2026-10-27

Offline packaging inspection of committed source
`c4d0fe9bd263b31ef946d4aeb36d41c1a9914cff`, exported with `git archive` into an
owned temporary directory. This is preparation for the hardening milestone,
not release acceptance. The [machine-readable receipt](release-packaging-preflight-2026-10-27.json)
records commands, exit codes, manifest observations and artifact/listing hashes.
No private working-tree files, credentials or retained runtime data were inputs.

## Observed packaging behavior

For each package, ran `cargo package --offline --locked -p PACKAGE --list`, then
`cargo package --offline --locked -p PACKAGE --no-verify`. No build scripts or
package build verification were requested. No registry upload, publish command,
manifest edit or dependency substitution was performed.

| Package | Listed files | List exit | Archive exit | Result |
| --- | ---: | ---: | ---: | --- |
| easy-auth-core | 313 | 0 | 0 | Local archive created; build unverified |
| easy-auth-postgres | 593 | 0 | 101 | Internal core dependency lacks a version requirement |
| easy-auth-axum | 437 | 0 | 101 | Internal core dependency lacks a version requirement |
| easy-auth-server | 152 | 0 | 101 | Internal Axum dependency lacks a version requirement |

Listing success does not establish archive success. PostgreSQL's listing includes
39 SQL migrations; this is an inclusion observation, not migration execution or
packaged-database acceptance. All four commands warn about missing description,
documentation, homepage or repository metadata.

The core archive still declares `publish = false`. Its normalized manifest has
`saml-rs` version `=0.6.1`, optional, with default features disabled, but no local
path. The maintained `third-party/saml-rs` source and eleven patches are outside
the archive. Cargo removes path locations during packaging; a versioned path
dependency becomes a registry dependency. See the official
[packaging description](https://doc.rust-lang.org/cargo/commands/cargo-package.html#description)
and [multiple-location dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations).
The archive therefore does not establish preservation of the maintained verifier
for a downstream registry consumer. No registry resolution or SAML archive build
was attempted. Do not treat an optional/default-disabled feature as satisfying
the all-required-method release gate.

All four listings omit the project's root `LICENSE-MIT` and `LICENSE-APACHE`
texts and have no package README. Axum does include eight shipped UI/brand
license files. SPDX metadata alone is not evidence that intended archive notices
are complete. The existing source and image supply-chain reviews retain their
own scopes; this inspection does not replace their license or advisory evidence.

## Required release work

Before release, define versioned internal dependency coordinates and validate
their publication order or a separately chosen distribution mechanism. Establish
an explicit packaging solution that retains the maintained verifier and its
integrity checks. Do not silently replace it with upstream registry `saml-rs`;
[ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md)
requires all eleven maintained patches and preserved protocol/trust checks.

Prepare consumer-facing package metadata, README and license/notice inclusion,
then inspect actual normalized archives and run clean extracted/default and
relevant feature consumer builds, artifact smoke and real PostgreSQL tests.
Adding version strings alone cannot prove registry portability or acceptance.

The root `CHANGELOG.md` already exists, with an Unreleased section. It needs
release-specific reconciliation rather than an assertion that no changelog
exists. The two current workflow files provide CI and website checks, including
bounded SAML image provenance/evidence. They do not implement crate publication
or signed crate-release provenance. Existing local image IDs and source hashes
are not signed release attestations or registry digests.

`SECURITY.md` still conditions private reporting on availability and requires a
maintainer contact/response policy. A working private reporting channel was not
verified; no report or external contact was sent.

Release implementation remains dependent on the hardening/security prerequisites,
including the hard outbound OIDC gate, deferred provider/native/device acceptance
and independent review requirements. This preflight grants no publication,
merge, deployment, production-readiness or independent security approval.

## Validation scope and failures

The three archive failures above are retained verbatim apart from replacing the
owned export path with `SOURCE_EXPORT`. Assertions, security gates and manifests
were not weakened. A receipt-drafting script initially read archive metadata
after closing the archive; it was corrected to read while open. The packaging
commands were already terminal and their original logs were retained unchanged.

Only documentation and this receipt change. Rust/real-PostgreSQL suites are not
rerun for the prose-only audit, and no ticket is completed by it. Prior source
validation remains scoped to its recorded commits. No compiled artifact,
provider, database, native image or release has been newly qualified here.
