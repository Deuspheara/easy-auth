# Website search output verification — 2026-10-27

AUTH-60 implementation `fc1aa205678277fb569e847066f860dd530fa21b` replaces the
search writer; `49743f7ec7ff1d04205498b897ab06f399ff8e79` completes public output
permissions and the genuine reopened-query navigation check. Both are on
`feat/auth-60-search-build`, based on validated AUTH-49 sourcea6050d1. No PR,
merge, hosting publication or authentication behavior change is included.

## Observed failure and mechanism

An earlier successful build on a6050d1 emitted zero-length Pagefind runtime/entry
and other asset files. Genuine search timed out. The failed public artifact and
its byte/hash inventory were preserved separately. Disk had about32GiB available.
An unchanged rebuild restored the files, so rebuild success alone did not resolve
an intermittent cause.

A bounded standalone reproduction used normal owned public HTML, requested the
complete expected index through `getFiles()`, called the upstream `writeFiles()`
then immediately `close()`, and compared disk bytes with the in-memory response.
Three of twelve independent runs had incomplete outputs, including zero-byte
`pagefind.js` and index entries. Expected memory buffers remained complete.
A later independent diagnostic observed zero of twelve failures on that upstream
path and zero of twelve on the new path. These observations retain their separate
scope: the first reproduction is real, and the defect is intermittent. Tests do
not require the upstream defect to happen in every run or retry a failed build.

The pinned [Pagefind1.5.2 output code](https://github.com/Pagefind/pagefind/blob/v1.5.2/pagefind/src/output/mod.rs)
awaits Tokio writes but does not flush them before returning. Its installed Node
service close routine kills the backend. [Tokio's file contract](https://docs.rs/tokio/latest/tokio/fs/struct.File.html)
explains that pending operations can outlive file scope unless flushed. This source
and the reproduction support a shutdown race. No power-loss/disk-durability or
independent security assessment follows from that diagnosis.

## Implemented completion boundary

A narrow adapter replaces only the pinned Starlight build writer hook. A test
compares every actual integration hook and preserves all others. Existing search
UI, configuration, source selection, metadata defaults and base-path behavior stay
with Starlight. No node_modules patch, duplicate indexing, disabled search,
unconditional retry, arbitrary sleep or second provider is introduced.

The documented [Pagefind in-memory API](https://pagefind.app/docs/node-api/) supplies
complete index bytes. The backend closes before Node-owned writes begin, so its
termination cannot interrupt those writes. Validate the pinned entry/version,
nonempty language and referenced metadata/WASM, compressed payloads, nonempty
assets and distinct safe paths. Write into newly owned private staging, await each
file close and compare every emitted file byte-for-byte, including nested index/
fragment assets. Refuse stale existing output and unexpected files/symlinks.

After successful validation, normalize files/directories to0644/0755 while keeping
the outer staging directory private until its children are complete. Rename only
complete output into place. Errors fail the build and remove only owned staging;
there is no fallback to stale files. Standard gzip and Node filesystem operations
are reused, not a custom compression or cryptographic implementation.

Pagefind1.5.2 is now an exact direct build dependency, promoting its already locked
transitive version. Every resolved lockfile package record/version/integrity/license
is unchanged. Clean `npm ci --ignore-scripts` in an owned directory succeeded;
installed Pagefind JS and the actual native binary matched that clean installation.
Current npm audit reported zero advisories. Existing npm license/source obligations
remain, including those of other build/native dependencies; the graph is not claimed
solely MIT/Apache. Vendor output bytes/notices are not stripped. Future Starlight/
Pagefind upgrades require review of the deliberate hook and format adaptation.

## Exact validation

On clean49743f7, both Node24.22.1 and Node26.0.0 passed:

```sh
npm run format:check
npm test
npm run check
npm run build
npm run test:browser
```

Each unit run passed22 tests, zero failed/skipped. Each build verified34 HTML files
and49 complete search assets. Each genuine Chromium run passed33 routes/548
anchors, retaining theme/keyboard/mobile/search controls and selecting an actual
indexed result under `/easy-auth/docs/`. Type checks reported zero errors/warnings.
The owned previews stopped and preceding fixed screenshot bytes were restored.
These are macOS arm64 local results, not Linux hosted CI or production qualification.

The Node24 runtime matches the CI workflow's configured major. Its official
`node-v24.22.1-darwin-arm64.tar.xz` archive matched the published SHA256
`654ba79de6155647e22321932b45f2a1ccb705976cc337c9b8e278beb085a628`.
It was extracted only in a new owned temporary directory; system tools were unchanged.

Negative cases reject empty/malformed/wrong-version entries, empty assets, missing
metadata/WASM/index/fragments, truncated gzip, malformed text, duplicates/escaping
paths, missing/altered/unexpected disk files, symlinks, stale existing output and a
real file/directory write conflict. An actual Astro CLI negative build on49743f7
exited1 for an owned preexisting search destination, preserved its sentinel and
removed its private output. An initial diagnostic invocation failed unrelated
config resolution; it was rejected as evidence and corrected to Astro's required
root-relative config path before the intended negative case passed.

Two corrections remain explicit. The initial new navigation assertion assumed a
query survived Escape/reopen. A genuine probe observed17 results before close,
then an empty input/zero results after reopening. Entering the deliberate query
again passed result navigation; existing search assertions stayed intact. A new
restrictive-umask test first failed on private directory0700 versus expected0755
(six other output tests passed), then passed after explicit public permission
normalization. Neither production UI nor a preceding assertion was weakened.

Required backend gates also ran on cleanfc1aa20 and passed: cargo formatting,
strict default/all-feature workspace/all-target Clippy, default workspace167
passes, all-feature1193 reported passes including one isolated logging child
(1192 primary), zero failures/ignored. The real-PG lifecycle target passed676
cases. Audit and all-feature cargo-deny passed with inactive
`rsa0.9.10`/`RUSTSEC-2023-0071` still reported. No Rust/Cargo/schema/root-script/
workflow input changed from that exact backend checkpoint to49743f7; subsequent
changes are website code/tests/docs. The owned PostgreSQL container and exclusive
anonymous volume were removed after exact ownership/shared-volume checks.

## Maintainability and scope

`scripts/search/` separates asset-format policy, file completion/permissions and
integration composition. Shared ordinary HTML setup lives in `tests/support/`;
unit scenarios separate bundle faults, filesystem/output and hook lifecycle. New
modules remain below300 lines and functions below the review triggers. Astro
configuration only composes the adapter. No auth domain policy, generic plugin,
new crate, protocol producer or unrelated refactor was added.

[ADR0033](../architecture/adr/0033-static-project-website.md) and the
[website guide](../../website/README.md#search-output-completion) record the boundary.
Source allowlisting and the retained preview/accounts/passkeys remain unchanged.
AUTH-47/AUTH-48, AUTH-49's actual dependency, deferred real provider/OS/production
verification, SAML waiver limits and outbound OIDC release gate remain separate.
