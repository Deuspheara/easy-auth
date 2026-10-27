# M00 research acceptance review — 2026-10-27

AUTH-1 requires a pinned comparison, an explicit build decision, threat/domain/API/
deployment decisions, a measured build-versus-contribute checkpoint and reviewed
SAML feasibility. This is a review of those deliverables and their limitations,
not production acceptance, independent security approval or protocol compliance.
All four research children are recorded Done; their statuses alone are insufficient
evidence. This review starts from `a6b773937804a9d672aba98ec512bd0441487472`.

## Requirement-to-evidence review

| Requirement | Inspected evidence | Result and limit |
| --- | --- | --- |
| Seven pinned source comparisons; licenses/activity and five build-versus-contribute answers | [Source identities](../research/source-snapshots.json), [comparison](../research/ecosystem.md), [dated advisory inventory](../research/advisory-history-2026-10-27.md) | All seven commit IDs and committer timestamps freshly match primary GitHub observations. Manifest/version and all 52 published repository advisories /74 range rows are recorded. One Better Auth range matches; eleven Kanidm rows require exact-fix review. Empty feeds provide no vulnerability clearance. Full transitive/native review is a separate adoption prerequisite. |
| Explicit build/contribute decision, informed by measurement | [ADR0001](../architecture/adr/0001-build-versus-contribute.md), [native comparison](../research/adoption-comparison.md), [reproduction](../../benchmarks/adoption/README.md) | Retain the requested narrow independent alpha. Smaller compiled graph/executable did not mean lower RSS or simpler setup; all three integrations rejected revoked sessions. No performance/security ranking or novel revocation claim. Maintained alternatives and contribution remain explicit. |
| Trust/domain/API/deployment boundaries and ADRs | [Architecture](../architecture/overview.md), [domain](../architecture/domain-model.md), [flows](../architecture/auth-flows.md), [API](../architecture/api-contract.md), [deployment](../architecture/deployment.md), [initial ADRs](../architecture/adr/0002-sessions-and-postgres.md) | Realm differs from business organization; inbound providers differ from the outbound issuer; users/provider identities/credentials/sessions/tokens remain separate. Core owns policy, PostgreSQL owns transactions and HTTP owns transport. No email linking or application business authorization is introduced. TLS/fail-closed configuration and private storage remain deployment requirements. |
| Threat-to-test mapping | [Threat table](threat-model.md), [fifteen-row source/assertion review](threat-control-review.md), [protocol matrix](protocol-validation-matrix.md) | Concrete source/control/assertion links cover each table row, with bounded execution and residual risks stated. Physical devices, registered providers, OS vault behavior, independent review and production operations are unperformed gates; test counts do not clear them. |
| SAML dependency/signed-content feasibility and explicit selection/blocking decision | [Original assessment](../research/saml-assessment.md), [selected dependency review](../research/saml-dependency-review.md), [maintained source decision](../architecture/adr/0027-maintained-saml-dependency.md), [activation policy](../architecture/adr/0032-saml-maintainer-directed-activation.md) | The original assessment explicitly blocked activation and recorded 93 selected upstream AWS-LC tests plus unavailable native samael execution. Later failed XML controls remain failures at their exact pins. Subsequent maintained-source selection and opt-in activation have their own evidence. ADR0032 waives independent review only; it supplies no independent approval and removes no protocol/trust/lifecycle or dependency checks. |

The initial documents and core entry file first appear together in commit
`e49ad9ee99bb169dda19fa9ccd54a6c1459c7e73` (2026-10-18). Git therefore does not prove
an independently recorded review before the first credential implementation. This
corrects the stronger chronology in the original research acceptance narrative;
the current consistency review cannot retroactively establish that chronology.
No independent reviewer or historical approval is invented.

## Historical measurement provenance and arithmetic

The sustained-load producer is
`34ed2e9e9e2255f6b32b25bf18db99b0cca94565`; its eight recorded harness hashes match
the actual immutable Git objects. The product runtime/lock remained unchanged
from `ffe0b3dc1ae95803a4f93fb40e2450d2e6145f6a` during that experiment. Current
`src/easy.rs` has evolved and does not match that producer; replay instructions now
require the exact historical source in an isolated checkout with owned fixtures.
The initial expectation that current probe bytes still matched was rejected;
the producer checks were retained, rather than replacing their expected hashes.

The verifier needs the producer Git object in the local checkout; it neither checks
out old code nor starts services. Run these read-only checks to inspect the
committed historical evidence:

```sh
python3 benchmarks/adoption/verify_recorded.py
python3 benchmarks/adoption/summarize.py benchmarks/adoption/results/2026-10-19-under-load
```

They check nine process reports, six 512-request trials per process, one/eight
worker distribution, pool 10/eight-session setup, seven sustained other-owner
workers, 64 post-return rejection checks per process, other-owner validity, RSS
samples, throughput arithmetic, dependency identity counts and binary sizes.
The totals match 27,648 timed validations, 576 post-return rejections, 2,532
background validations and nine other-owner controls. Recomputed medians match
the published 144/169/304 compiled packages, 4.68/5.30/8.79MiB executables,
73.48/42.39/30.97MiB RSS and 1337/704/735 versus 4078/2600/2747 validations/s.
No old competitor dependency is newly built or executed. These checks establish
record consistency, not independent reproduction of the original measurements.
The original exact-head [hosted AUTH-5 run](https://github.com/Deuspheara/easy-auth/actions/runs/39223174390)
was freshly observed completed/success at published
`3d644d4b209d1be757825edc2e7068bf6bff8325`; it is historical child evidence,
not a hosted result for this branch.

## Fresh validation

Exact clean source `92a8a2a4ad9d7d2664a2666d1ecf2657bf4a2d32` passed:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` and the same
  command with `--all-features`.
- `cargo test --locked --workspace`: 171 passes; with `--all-features`: 1,197 reported
  passes (1,196 primary plus the isolated logging child), zero failed/ignored.
  The all-feature real-PostgreSQL lifecycle target passed 676 cases.
- The existing benchmark example Rust control and five Python benchmark methods.
- `python3 scripts/audit.py`: compiled advisory gate PASS, retaining the inactive
  RSA 0.9.10 / RUSTSEC-2023-0071 lock entry. All-feature `cargo deny check` passed
  advisories, bans, licenses and sources, retaining existing warnings.
- The new stored-record verifier and existing summarizer. Copies with a mutated
  producer hash or doubled throughput were both rejected. The advisory inventory
  was compared with all collected public records/manifests: 52 identities, 74 ranges,
  unchanged original fields, raw-response hashes and seven version/module IDs.
  All 40 local Markdown links in the changed documents resolved after correcting
  one draft deployment-document path.
- Node 24 website formatting, 22 unit tests, type checking, build and genuine browser
  checks: 36 routes / 581 anchors. The research inventory is repository documentation;
  the website still publishes only its existing explicit public-guide allowlist.
- Unchanged-policy Gitleaks scans of an exported committed source tree and the
  AUTH-1 Git range: zero findings. An initial overbroad working-directory scan and
  its diagnostic rerun exited 1 with 288 findings, all under ignored `target/` build
  output and zero tracked paths. Their redacted reports remain local; no scanner
  exception or policy relaxation was introduced and build artifacts are not pushed.

Backend checks used newly owned disposable PostgreSQL/Mailpit on random loopback
ports, no host mounts and exclusively owned anonymous volumes. Their exact
containers and volumes were removed and absence verified. No historical competitor
probe or retained application database was executed. All 73 protected original-file
hashes, exact original changed-path set and empty original index were verified.
This evidence-only follow-up changes no qualified executable/test/dependency/schema
input. No new hosted result or deployment is inferred from local validation.

## Change scope and remaining gates

The new factual inventory omits raw advisory descriptions, PoCs, authors and private
tracker content. Its JSON is data; the94-line report keeps interpretation and
limits separate from the complete advisory index. The focused benchmark verifier
checks existing data/Git objects only and adds no runtime dependency, policy,
secret handling, database operation or generic abstraction. Existing numeric
results, source pins, migrations, native code and authentication assertions stay
unchanged. No structural or behavior refactor is bundled with this review.

Unresolved candidate applicability is recorded research risk and an adoption
prerequisite, not an unaffected verdict. The original SAML feasibility criterion
allows an explicit block; research completion cannot replace later protocol,
assurance, operational or release acceptance. The SAML waiver retains its exact
limits; outbound OIDC remains a hard release gate. Registered Apple/Google, actual
OS/device and production verification remain deferred and unpassed. This work
creates no PR, merge, release, deployment or upstream contact.
