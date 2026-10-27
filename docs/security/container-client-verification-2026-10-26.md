# Default container and client verification — 2026-10-26

This records AUTH-45 development evidence. It is not production acceptance,
independent security approval, protocol compliance or a full recovery qualification.
The implementation source is `de7c5e2c338ace3c9e31d1e870c0a6deb0c1bb5c`.
No backend crate, workspace dependency, public authentication API or migration changed.

## Reproduction and observed boundaries

Follow [containers](../guides/containers.md), [backups](../guides/backups.md) and
[minimal clients](../guides/minimal-clients.md). The four new CI command blocks in
`.github/workflows/ci.yml` were replayed exactly against the implementation commit:

1. Independent locked Rust example formatting, two URL-policy tests, strict Clippy,
   build, cargo-audit and cargo-deny; locked website install and strict TypeScript.
2. `git archive HEAD` into fresh public source and both named Docker builds.
3. `python3 scripts/smoke_container_examples.py` against those exact images.
4. Existing pinned image scanner with its unchanged high/critical gate.

All four blocks exited zero locally. These results do not claim hosted CI success.
The source workflow SHA-256 is
`5725d2d3f2ab6091b1590081f9c4577518a8f5c209fa64246f5d35d1adba60d2`.
The default context regression separately admitted nine required ordinary markers
and excluded seventeen private/unrelated markers; it read no private source and
executed no copied input. Two private-settings tests verify mode 0600, paired URL/
password, fresh realm, refusal to overwrite and refusal of an in-source destination.

The actual fresh owned Compose stack migrated PostgreSQL, accepted and delivered
one email to the exact owned disposable recipient, and completed the existing
browser-bound confirmation page. The TypeScript example observed the actual user,
then actual logout and anonymous state. The independently executing Rust probe
remained anonymous during browser authentication. Missing Origin, wrong Host and
oversized body were refused with working readiness positive controls. No external
requests or browser errors occurred; the one owned mail message was removed.

The private custom archive restored into a newly created, never-served database.
Private comparisons preserved user IDs and session/revocation/audit/migration counts;
the observed snapshot had one user and 38 successful migrations. The clone/archive
were removed. Exact owned containers, named volume and network were removed and
absence verified. No retained preview, account/passkey or other Docker project was
targeted. This proves this bounded documentation smoke, not disaster recovery,
rolling upgrades, incident reconciliation, encrypted retention or key recovery.

## Exact image assessment

| Image               | Actual image ID                                                           | Remaining findings |
| ------------------- | ------------------------------------------------------------------------- | ------------------ |
| Default application | `sha256:115170d078ed486c927324e19d2a75bcd44d7a13ece7155c3f7e595f46a80088` | 23 medium, 8 low   |
| Local proxy         | `sha256:a31a38c8c4ee49657a49f79106f2fbec904346da1392e062e9e8e705892d8bab` | 23 medium, 10 low  |

Both had zero high/critical findings with zero ignores, no ignore-unfixed option,
no image upload and disabled telemetry. The maintained Trivy 0.76.1 scanner image is
`aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c`.
Database metadata: updated `2026-10-25T19:10:35.479132794Z`, downloaded
`2026-10-26T01:39:11.806924881Z`, metadata SHA-256
`fd9aaaa388d862115e9e4493cf7111299e91e608497d2eaade71eba8b6fcf888`.
Application/proxy report hashes respectively:
`3470a836e7697bd363dd461fe1dbc14ef29877091619e8c83720d06952f47377`,
`567869e9583f38fb471dc6b0d200d67b2517094b69d5d1bdb2fd2ca84429b446`.
Advisory data and package repositories change. Rebuilds need their own exact-image
assessment; remaining findings still require release disposition under AUTH-48.

## Failures retained and corrected

The original bookworm runtime built but failed the unchanged scanner gate with
one critical and 69 high OS-package findings. Reusing the maintained pinned trixie/
distroless base removed those high/critical findings without an ignore. A subsequent
license-copy change produced the final application ID above, which was separately
built, exercised and scanned; earlier image scans are not transferred to it.

The first local startup failed with `development bind must be loopback`. Keeping
the app and SMTP loopback in the shared private namespace plus the constrained
proxy preserved the existing policy. No development or production check was relaxed.

An initial consumer deny invocation placed `--config` after `check` and exited two.
After fixing argument order, offline metadata lacked `web-time 1.1.0`; locked fetch
followed by the corrected command passed. Consumer deny reports unused existing
WebAuthn license exceptions/allowances and duplicate transitive `syn` versions as
warnings, with advisories/bans/licenses/sources passing. No exception was added.

The initial changed-source secret scan flagged a fixed example realm UUID as a
generic key. This was not a database-password finding. Fresh private realm and
paired database settings remove the fixed value; the source/history scans pass
without changing scanner policy or adding an exception.

## Final repository gates

Against the same implementation source, these commands exited zero:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/audit.py
cargo deny --all-features check
```

Tests used an inspected owned disposable PostgreSQL 17 container, loopback-only
port, no host bind and its exclusive anonymous volume. Default tests passed 128;
all-feature tests passed 1,150 primary cases (1,151 result counts including the
isolated logging child), zero failures/ignored, including 651 actual PostgreSQL
cases. The normal four-worker/20-permit budget and real waits remained unchanged.
The local macOS build used debug information off for dev/test and build-override
debug level one, as previously required for the SQLx dylib linker; no assertions,
policies or required cases were disabled. Formatting and both strict Clippy profiles
passed. Audit checks the compiled graph and retains inactive-lockfile findings;
existing deny warnings remain recorded without new exemptions.

Eleven source/qualification-helper tests, maintained source integrity (245 files /
11 patches), reference UI token integrity and both new JavaScript syntax checks
passed. Scoped public-source and new-commit history secret scans passed without
exceptions. The original checkout's 73 protected file hashes/change set and empty
index were independently rechecked; no private file was staged or exported.

Website formatting, seven unit tests, type diagnostics (zero errors/warnings/hints),
production build and genuine Chromium checks passed. The browser checked 29 routes,
484 anchors, search, keyboard interactions, persisted theme and mobile width;
fresh desktop/light/mobile screenshots preserved previous evidence. All 320 local
Markdown targets in the checked README/deployment/ADR/evidence/guides existed.
These are local results; no hosted pass, publication or deployment is inferred.
A documentation-only evidence follow-up does not change the exercised image/client/
fixture/workflow bytes or published guide contents.

## Maintainability and remaining acceptance

The Docker profile, independent consumers, settings, Compose ownership, archive
operation and browser/mail journeys have named separate responsibilities. New
handwritten modules remain below 300 lines and functions below roughly 50 lines.
The generated independent Cargo.lock is a deliberate size exception. The example's
separate workspace is a concrete unpublished consumer, not a production micro-crate
or plugin framework; root manifests/lockfile remain unchanged. No unrelated
structural refactor or deferred cleanup is introduced.

The SAML maintainer waiver retains all its limits and is not independent approval.
Outbound OIDC remains a hard release gate. Real Apple registration/provider/native
OS acceptance, broader protocol qualification and operational recovery remain open.
No PR, merge, public deployment or release was performed for this ticket.
