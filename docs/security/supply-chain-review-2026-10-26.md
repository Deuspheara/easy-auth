# Supply-chain evidence checkpoint — 2026-10-26

AUTH-48 remains subject to its AUTH-47 prerequisite and release dispositions.
This is bounded local source/artifact evidence, not production acceptance,
independent legal/security approval or protocol compliance. Real provider/OS
acceptance remains deferred. The SAML maintainer waiver retains every protocol/
trust/lifecycle check and supplies no independent approval; outbound OIDC remains
a hard release gate.

## Evidence boundaries

`scripts/record_supply_chain.py` records declared licenses, checksums and normalized
dependency references without cache paths, authors or workspace contacts. Cargo
metadata is a resolver overapproximation. A separate locked, offline, all-feature/
all-target normal/build/dev `cargo tree` identifies selection; neither claims
successful compilation for every target. The compiled advisory check remains
`scripts/audit.py`, and the unchanged root deny policy remains mandatory.

The initial current inventory records 403 workspace packages, 380 selected and 23
resolver-only, including RSA. The independently locked consumer records 155/127/28.
Every Cargo package declares a license expression. The npm lock inventories contain
529 website locations (526 unique identities), 33 presentation-tool packages and two
browser-test packages, including development/optional packages; all declare licenses.
Twenty-one committed shipped notices/assets have source hashes. Declared checksums
are not claims that all cached package bytes were independently verified.

The published default-container/client implementation and its required Rust/PG/
website gates are recorded in the
[AUTH-45 evidence](container-client-verification-2026-10-26.md). This checkpoint
adds tooling, CI and documentation only; it changes no backend crate, application
dependency, migration, authentication API, verification or transaction policy.

## Standard SBOMs and coverage

The [official Cargo generator](https://docs.rs/crate/cargo-cyclonedx/0.5.9) emits
CycloneDX 1.5 with feature/target-aware package licenses. The pinned existing Trivy
0.76.1 scanner emits CycloneDX 1.7 for npm and exact scanned image packages, with
network disabled, no upload and explicit empty ignore/config inputs. It receives
only owned copies of committed manifests/locks or already assessed image JSON.

The initial complete local run generated thirteen Rust, three npm and four image
SBOMs. Coverage requires every selected normal/build identity, all workspace roots,
and valid/unique component/dependency references. Resolver-only packages remain
visible; they are never removed merely to suppress an advisory.

| Rust source profile       | Selected normal/build identities | Observed package identities across its SBOMs | Resolver overapproximation |
| ------------------------- | -------------------------------- | -------------------------------------------- | -------------------------- |
| Default server            | 213                              | 246                                          | 33                         |
| Explicit SAML/OIDC server | 332                              | 354                                          | 22                         |
| All-feature workspace     | 368                              | 388                                          | 20                         |
| Independent consumer      | 127                              | 155                                          | 28                         |

All four profiles use target `all`; these are source inventories, not actual binary
linkage/reachability claims. Dev dependencies remain in the separate full source
inventory. npm SBOM checks cover all 526/33/2 unique identities with no missing
dependency-license fields. Scoped npm names retain their namespaces.

The generator embeds temporary paths in opaque source component IDs and omits
the project's own root license. The wrapper records raw/output hashes, maps only
exported absolute source IDs to `file:///source/<source-commit>`, and supplies a
missing own-root license from exact Cargo metadata using the
[standard SPDX expression field](https://cyclonedx.org/docs/1.5/json/).
Dependency PURLs, versions, licenses and hashes remain unchanged. It checks graph
references before/after and rejects unexpected paths or changed source lockfiles.
Nested lib/bin targets are not separately licensed dependency packages.

## Actual images and native provenance

The default application and local proxy retain their separately recorded AUTH-45
IDs. Fresh opt-in reference artifacts built from committed public source
`01556c04d5c28649d395251957d217d0724ad9ab` are:

| Artifact         | Actual image ID                                                           | Inventoried package URLs |
| ---------------- | ------------------------------------------------------------------------- | ------------------------ |
| Default app      | `sha256:115170d078ed486c927324e19d2a75bcd44d7a13ece7155c3f7e595f46a80088` | 14                       |
| Local proxy      | `sha256:a31a38c8c4ee49657a49f79106f2fbec904346da1392e062e9e8e705892d8bab` | 17                       |
| Opt-in SAML app  | `sha256:556b7c293e39597cbd9ebe856309d51168caa7934c82820281b64f06ba866d28` | 14                       |
| Opt-in TLS proxy | `sha256:a7ad408eb885835bc815aac0da0866a18705d6245179db70bd34b5d69cce649e` | 17                       |

Image coverage compares the exact package URL, retaining Debian epoch, revision,
architecture and distro. Trivy's separate `Version` field can omit epoch/revision;
comparing only that truncated field would misidentify packages. No package is
dropped to make coverage pass.

The fresh opt-in build ran its existing maintained C14N qualification. Actual
packaged native hashes, source inputs, selected dependency graph and embedded
qualification match current source through the existing inventory checks. Native
OpenSSL and bundled AWS-LC provenance remain distinct; packaging a library does
not prove it is loaded. No old SAML image inventory is transferred to new source.

Both fresh reference images pass the unchanged high/critical gate with zero
ignores: application 23 medium/8 low, proxy 23 medium/10 low. Default image results
remain scoped to their own earlier scan. Advisory databases change; these are
observations, not vulnerability-free or production-security claims. Lower findings
remain visible and require release-specific disposition.

The image SBOMs lack machine license fields for `libgcc-s1`, `libgomp1` and
`libstdc++6`; proxies also lack one for `libcrypt1`. Actual image export confirms
retained copyright texts, without executing binaries:

- `/usr/share/doc/gcc-14-base/copyright`: 69,004 bytes,
  SHA-256 `20390f8a6f3b1e4d7cb45dd8652dabb259bbef688cbad839bcdb0b9ba7252f79`.
- Proxy `/usr/share/doc/libcrypt1/copyright`: 6,010 bytes,
  SHA-256 `5a5e7ca0e9f3f9679977e3a3e9ede45ad92885a3297ea78e766979f9866c5a16`.

The wrapper checks matching GCC-runtime/base package versions and records related
notice paths/hashes for each missing field. New unmapped gaps fail for review.
It does not invent a SPDX expression or conclude redistribution compatibility;
the detailed GPL/LGPL/runtime-exception and other package obligations remain in
their retained texts and release review. Do not replace these with a blanket MIT
label or treat a scanner's list as independent license approval.

## Tool trust and retained failures

The [tool inputs and narrow license decision](../../tools/supply-chain/README.md)
pin the official Apache-2.0 generator archive and a separate patched tooling lock.
The original bundled lock failed current audit on `time 0.3.36`
([RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009.html)), unsound
`anyhow`/`rand` warnings and a yanked entry. The refreshed tool graph passes with
zero vulnerabilities/warnings; no advisory ignore or application policy change.
The separately scoped exact MIT-0 tooling package decision is explicit, not a
hidden widening of the authentication runtime's allowlist.

Trivy's initial lock-only Rust experiment omitted 32 registry identities relative
to the full source inventory; all workspace manifests reduced that to fifteen,
with no Cargo license fields. Those incomplete experiments were not accepted as
complete Rust evidence. Official source SBOMs plus the separate selected graph
retain both package coverage and resolver-only risks. New guards also exposed and
corrected scoped npm naming and Debian-version representation assumptions.

## Reproduction and remaining acceptance

Use Python 3.12+, Rust 1.95, Docker, installed cargo-audit/cargo-deny, and committed
reviewed source with fetched locked dependencies. See the exact CI blocks in
`.github/workflows/ci.yml`; artifact retention includes inventories, SBOMs and
sanitized summaries, not databases, archives, raw browser state or private logs.

```sh
tool_parent=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-sbom-tool.XXXXXX")
report_parent=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-sbom-evidence.XXXXXX")
python3 scripts/prepare_sbom_tool.py --destination "$tool_parent/generator"
python3 scripts/record_supply_chain.py --output "$report_parent/source.json"
python3 scripts/record_supply_chain_sboms.py \
  --tool-directory "$tool_parent/generator" --output "$report_parent/sboms" \
  --image-report default=target/default-container-advisories/auth.json \
  --image-report default-proxy=target/default-container-advisories/proxy.json
```

Image reports must already come from the exact owned builds and unchanged scan
gate. Source-only invocation supplies no image acceptance. The separate image-only
command records opt-in reference images after their assessment. Existing output
directories/files are refused; retain the previous receipts. Inspect declared and
observed profiles, source/image hashes, resolver-only dependencies, missing license
fields and residual advisories before making any release decision.

The generated tooling lock is a reviewed size exception; handwritten modules have
named source/Cargo/SBOM/scanner/bootstrap responsibilities, without an auth crate,
plugin framework, duplicated protocol policy or unrelated structural refactor.
AUTH-47's deferred acceptance, selected production artifacts/targets, current
release risk decisions and independent/operational obligations remain open. No PR,
merge, public deployment or release is authorized by these local reports.
