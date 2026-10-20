# Code organization

AUTH-30 keeps core mapping, opaque proof and sign-in/port in focused
`oidc/identities/` modules; signed profile decoding stays with verification.
PostgreSQL `oauth/identity_policy.rs` owns configuration and exact current-policy
locking. `oauth/identities/completion.rs` owns the visible final transaction;
`ownership.rs` owns scoped subject serialization and existing/new owner branches.
Session source snapshot/composition, provider guard and provider inventory have
separate modules. No new crate, HTTP policy copy or generic identity engine is added.

The owning completion/subject-resolution transactions keep lock order, original
caps, writes and rollback visible; their longer functions are reviewed exceptions.
Likewise, longer ordered signature/registration, fault, migration and lock-wait
cases keep setup/observed wait/release/negative result/valid controls together.
Test setup remains feature-specific; it adds no production proof constructor or
verification bypass. All new source/test modules stay below 300 lines. No unrelated
cleanup is deferred. Adding another test responsibility should use another named
module rather than accumulating it in an entry file.

AUTH-22's optional `oauth/` modules keep core configuration validation, transient
proofs, repository contract and use cases separate. PostgreSQL `oauth/` owns
administrative configuration, committed admission, shared fresh-owner/session
validation and pending transactions. Thin entry modules declare/delegate only;
the existing deadline type exposes a crate-private cap without duplicating session
policy. Integration cases under `tests/lifecycle/oauth/` separate binding, linking,
limits, configuration, concurrency, deterministic ordering, deadlines and upgrade.
Longer save/take functions retain lock ordering, exact bindings, final clock checks
and commit in one visible transaction. Ordered race tests retain setup/observation/
release/assertions together. These are reviewed size exceptions; all new modules
remain below 300 lines. No unrelated structural cleanup is deferred.

Maintainability is part of correctness: authentication code must be easy to locate, understand and review. The mandatory rules live in [AGENTS.md](../../AGENTS.md#maintainability-and-clean-code) and apply to human and agent contributions.

## Responsibility boundaries

Keep the four existing workspace packages. Add modules for implemented behavior inside them; a new feature does not automatically need a new crate.

| Package | Owns | Keep out |
| --- | --- | --- |
| `auth-core` | Domain types, policy, use cases and repository/delivery ports | Axum extractors, cookies, SQL and server configuration |
| `auth-postgres` | Realm-scoped queries, migrations, atomic transactions and locking | HTTP responses and duplicated business policy |
| `auth-axum` | Routing, request/response types, browser boundary and HTTP error mapping | SQL and independent versions of core policy |
| `auth-server` | Configuration, SMTP delivery, worker lifecycle and composition | Duplicated authentication workflows |

Within each package, group related code by the vocabulary used in the domain: email authentication, passwords, recovery, account lifecycle, sessions and notifications. Cross-cutting browser cookie policy can have its own focused module. Keep error conversion at the relevant adapter boundary.

## Growing a feature

Start with a focused module such as `sessions.rs`. If it gains several distinct responsibilities, move it to a folder such as `sessions/mod.rs`, `sessions/types.rs` and `sessions/revocation.rs`. Use names that describe the actual responsibility; do not manufacture that whole tree before the code needs it. The entry file declares modules and exposes the deliberate API; it does not accumulate unrelated implementations.

The same feature may have an HTTP module, a core use-case module and a PostgreSQL transaction module. Those modules follow the existing inward dependency direction. Keep related request types beside their handlers, domain types beside their use cases, and SQL helpers beside the transactions that own them. Expose only what another module or a consumer needs, using private or `pub(super)`/`pub(crate)` visibility where sufficient.

Keep transaction ownership and lock ordering visible in one place. A helper should name a meaningful operation and make its transaction/context dependencies explicit. Avoid layers of tiny forwarding functions that force a reviewer to jump between files to establish an authorization invariant.

## Tests and review

Organize integration suites into feature-named files or modules, with reusable setup in `tests/support/`. Keep feature-specific assertions and fixtures with their tests. Test external behavior and security invariants rather than exposing private implementation solely for tests. When splitting SQLx suites, retain their migration setup and isolated database behavior.

For every change, review:

- Can a contributor find the implementation and its tests from the feature name?
- Does each changed module have one clear responsibility, with a thin crate entry point?
- Are policy, error handling and setup shared only where the meaning is actually the same?
- Are authorization, realm scope, transaction boundaries and secret redaction still easy to inspect?
- Do oversized files/functions need a cohesive split, or is their size justified by keeping an invariant together?

The approximate 300-line file and 50-line function thresholds in AGENTS.md trigger this review. Generated files and published migrations are not extraction targets. A cohesive transaction may be longer; explain that decision rather than splitting it across opaque helpers. Formatting, linting and tests complement this review and cannot replace it.

## Implemented layout

AUTH-52 splits the original accumulating implementation files and test suites into these owning modules:

```text
crates/auth-core/src/
  lib.rs                    # Public facade
  auth/                     # Auth composition and feature use cases
  ports.rs                  # Repository and delivery contracts
  password.rs               # Bounded hashing and password policy
  passkeys/                 # Separate registration/assertion verification, private state, enrollment use cases and port
  email.rs, secret.rs       # Input and secret policies, with unit tests
  audit.rs, error.rs, identity.rs, notifications.rs, sessions.rs
crates/auth-postgres/src/
  lib.rs                    # Adapter construction and startup provisioning
  repository.rs             # Explicit core-port delegation
  locking.rs                # Email lock order and shared locked fresh-session validation
  identity.rs               # Private SQL-row decoding into the core user contract
  audit.rs                  # Typed transactional recording and scoped deidentification
  email.rs, passwords.rs, recovery.rs, notifications.rs
  sessions/                 # Validation, inventory, optional-mailbox ownership locking and revocation
  passkeys/                 # Optional preparation/completion and locked admission/ownership policy
  account/                  # Email-change and deletion transactions
crates/auth-axum/src/
  lib.rs                    # Public facade
  router.rs                 # Routes and state composition
  browser/                  # Validated origin/cookies and request boundary
  handlers/                 # Feature handlers and transport types
  passkeys/                 # Experimental enrollment router, thin handlers and concrete schemas
  contract.rs, error.rs     # Generated OpenAPI and public error mapping
  pages/                    # Optional reference HTML and JavaScript
apps/auth-server/src/
  lib.rs, main.rs           # Public facade and server lifecycle
  configuration.rs          # Validated composition
  smtp.rs, notifications.rs # Delivery adapter and worker
```

The HTTP and PostgreSQL integration entry files declare feature modules under `tests/browser/` and `tests/lifecycle/`, respectively. Their `tests/support/` folders contain reusable setup; account-only proof fixtures stay in the account test module. The single test target per adapter preserves the existing SQLx test setup without duplicated fixture compilation across many integration binaries.

Passkey integration scenarios live under `tests/lifecycle/passkeys/`, separated
into protocol negatives, enrollment binding/admission, concurrency/rollback,
credential limits/deletion and observed lock-wait cases. The software authenticator
is a test-only dependency. Production protocol code does not implement a mock token.

Rust permits one implementation of a trait for a type. PostgreSQL's `repository.rs` therefore delegates directly to crate-private feature methods. It adds no policy, SQL or generic framework. The public adapter and core APIs stay unchanged. OpenAPI's generated path descriptors are imported locally in `contract.rs` so moving a handler does not accidentally publish Rust module names as API tags.

## Reviewed size exceptions

Provider deletion now has a separate core use-case/port and PostgreSQL
`account/provider_deletion/completion.rs` transaction. It reuses the full identity
policy guard and owning active-provider authorization operation; only crate-private
visibility widens for that concrete reuse. The shared erasure tail takes optional
stored verified contact and never acquires authority or commits. Its longer body
retains the ordered cleanup, audit, user deletion and optional notice together.
Feature test setup keeps private snapshots/proof and exact tail gates separate;
completion, denial, claim-time, storage-fault, deadline, concurrency and disable
scenarios have named modules. Longer ordered tests keep observed waits, original
caps, explicit error classes and successful controls visible. All new modules
remain below 300 lines; no generic deletion engine or unrelated cleanup is added.

AUTH-55's `account/provider_deletion/authorization.rs` owns the concrete active
provider-session preparation locks shared by OAuth start/consume/context checks.
It takes no unrelated source-configuration lock and performs no deletion or
authentication-time update. Its longer ordered function keeps policy, optional
email, owner, session, identity and original deadline checks visible. Focused
schema, purpose, invalidation, ordering and wait test modules remain below 300
lines; longer ordered cases retain valid controls and exact failure assertions.

Account deletion delegates its already-authorized destructive tail to
`account/erasure.rs`. This private operation owns account-related proof/admission
cleanup, audit erasure, user deletion and the established deletion notice. It
performs no authorization and does not commit: the caller keeps its owner/session
locks and original deadline, then checks database time after the entire tail.
The longer ordered helper keeps this cleanup boundary visible. Its initial
extraction preserves mailbox behavior and is verified separately from provider
deletion changes.

The PostgreSQL `finish_email`, `enroll_password`, `finish_password_reset`, `confirm_email_change`, `finish_account_deletion`, `list_sessions` and `revoke_all_sessions` functions exceed the approximate 50-line review trigger. Each keeps its lock acquisition, proof revalidation, identity/credential mutation, session invalidation, audit/notice write and commit in a single visible transaction. SQL and bind chains are laid out explicitly. Splitting these functions into arbitrary steps would hide ordering and rollback invariants; add a helper only for a meaningful operation whose dependencies remain clear.

`configured_auth` likewise keeps the ordered, fail-closed startup composition together. Longer integration scenarios keep their arrange/action/assert sequence together to prove complete state transitions, isolation and rollback. They are now grouped by feature rather than collected in one large suite file. These are reasons for the current exceptions, not exemptions from reviewing future growth.

Passkey enrollment `save` and `commit` likewise keep admission, ownership/freshness
revalidation, state mutation, credential insertion, audit and commit visible in
their owning transaction. Their SQL is laid out explicitly. They exceed the
approximate function-size review trigger without adding unrelated responsibilities.

The browser fixture lives under `examples/passkey-browser/`, with separate database
lifecycle, configured fixture and explicitly disabled mail modules. Its Node runner
keeps child/browser ownership and normal-completion cleanup in one visible try/finally;
case bodies live in a separate test module. These longer orchestration/test functions
retain ordered setup/action/assert/cleanup rather than hiding secret handling or
resource ownership in generic helpers.

The assertion verifier keeps trusted ownership/snapshot checks, its explicit
account-bound/discoverable branch, high-level signature verification and backup
policy together in `verify_authentication`. It exceeds the function-size review
trigger to retain that proof boundary in one place. Private ceremony encoding and
stored credential decoding have separate owning modules; no SQL or HTTP behavior
is added to the verifier.

Passkey sign-in use cases and their repository port are separate from assertion
verification. PostgreSQL `passkeys/authentication/` owns admission, preparation and
completion. Its `save` and `commit` exceed the function-size trigger to keep browser
count locking and user/key/ceremony lock order, exact snapshot and post-wait expiry
checks, credential mutation, session/audit insertion and rollback visible. Tests
group binding, concurrency, migration and unchanged-row wait invariants separately.

Experimental HTTP sign-in lives under `passkeys/authentication/`: route composition,
thin handlers, closed modes and concrete wire schemas each have a focused module.
Browser registration and assertion cases use separate modules; signed iframe
context and the fixed counterless storage fixture each own their setup. The longer
fixture/runner functions retain ordered resource ownership, safe output and cleanup;
no test HTTP sign-in/proof bypass is added. The stdin setup changes only one unused
fixture credential's trusted counter metadata and cancels its prior test challenge.

AUTH-53 keeps optional-mailbox row decoding in the PostgreSQL identity module,
user/source admission under account operations and snapshot/lock ownership under
sessions. The ownership helper revalidates nullable email after taking the user
lock; it never acquires email locks afterward. Core user policy and HTTP nullable
fields stay in their owning model/transport modules. Integration cases under
`tests/lifecycle/identity/` separate migration, admission, policy, session and
observed-wait invariants. No generic identity engine or new crate is introduced.

Signup uses focused `passkeys/signup/` modules in core and PostgreSQL. Core owns
the flow, repository contract and unforgeable verified registration transition.
PostgreSQL separates admission, preparation/stage advancement and final completion.
The longer `save` and `commit` functions keep realm capacity serialization, pending
locks, exact proof comparisons, owner/key uniqueness, session/audit inserts and
final post-write expiry/consumption visible in one transaction. They are cohesive
reviewed size exceptions, not a generic workflow abstraction. Signup integration
tests separate protocol, binding, limits, collisions, atomicity, migration and
observed expiry waits. The software residence hint adjustment is test-only and
explicit; production options and verifier policy remain intact.

Experimental signup HTTP lives in `passkeys/signup/` with separate composition,
transport types, handlers and full contract. It reuses the actual enrollment/sign-in
route builders and canonical wire schemas, with only parent-feature visibility for
shared schema types. The anonymous-cookie guard is a transport rule; verification,
limits and persistence remain core/PostgreSQL responsibilities. Browser signup cases
and ceremony helpers live in `tests/browser/passkeys/signup/`; fixture summary
queries have a separate module. No public verification internals or duplicate
business policy were introduced.

Contact attachment uses `auth/email_attachment.rs`, PostgreSQL
`account/email_attachment/` (preparation, locked ownership and completion), and
experimental HTTP `passkeys/email_attachment/`. Its final transaction exceeds the
function-size trigger to keep target-email/user/session/proof lock order, exact
bindings, session rotation, audit and final post-write expiry consumption visible
together. Integration cases separate binding, atomicity, concurrency, observed
waits and migration. Test mail state has named fields in `tests/support/mail.rs`;
no positional tuple or public production delivery internals are added.

Native SMTP contact tests use a server example with separate owned-process,
configuration/composition and aggregate-database modules. It calls the real public
`configured_auth` facade and leaves the private SMTP adapter private. Native cases,
owned Mailpit access and runner/provenance each have a focused JavaScript module.
Longer orchestration retains ordered resource ownership/cleanup and never logs
captured child diagnostics or proof-bearing assertion values. No production fixture
endpoint or generic workflow engine is introduced.

Enrollment final consumption remains in its owning completion transaction, after
key/audit writes, with explicit proof/session deadlines. The longer function is
retained so locks, exact snapshots and rollback stay visible. Enrollment wait tests
separate owner/audit timing from pending-row/uniqueness waits; longer matrix cases
keep observed-lock/action/assert ordering together. AUTH-54 tracks the analogous
mailbox-flow review independently rather than silently expanding this fix.

AUTH-54 separates session validation and ordinary logout into named modules;
`sessions/mod.rs` contains declarations only. This extraction preserves SQL and
public adapter behavior, with existing session/HTTP regressions checked before
any deadline-policy changes.

AUTH-54 keeps the private database deadline cap in `deadlines.rs` and its use at
explicit feature transaction tails. Session validation and inventory share
`sessions/validation.rs`'s locked caller operation. That function exceeds the
50-line review trigger to keep owner-before-session locks, post-wait policy and
expiry validation, original deadline capture and caller-only touch visible together.
No implementation type is public. Tests under `lifecycle/deadlines/` group mailbox,
credentials, lifecycle, session and final-touch waits; only bounded gate/clock setup
is shared there. Published migrations and public APIs are unchanged.

AUTH-20's in-progress management boundary uses focused core `management/flow.rs`,
`repository.rs` and public metadata types, plus PostgreSQL `management/` modules for
admission, authorization/locks, inventory, mutation, notice persistence and explicit
port delegation. Entry files declare/reexport only. The removal transaction exceeds
50 lines to retain owner/session/key lock order, proven-remaining-key guard, session
and ceremony invalidation, typed target audit, notice and final deadline/commit
in one place. It adds no unrelated responsibility or generic credential engine.
Management tests separate boundaries, concurrency, rollback, observed final-write
waits and schema upgrades. Recovery and activation remain unfinished AUTH-20 work. Experimental HTTP management
uses focused routing, handlers, transport DTOs and full-schema modules. It composes
the extracted signup route builder rather than duplicate base routes or policy.
HTTP tests group boundary, contract and lifecycle invariants; native management
steps and owned-mail access stay separate from the existing SMTP case orchestration.

The experimental management constructor retains its explicit aligned service
checks, shared route composition, browser guards and configured full schema in one
function. Its formatted length crosses the approximate 50-line trigger; keeping
this ordered composition visible avoids hiding startup/route ownership in a generic
builder. It contains no SQL or duplicated authentication policy. Native management
likewise keeps the virtual-device selection/action/assert sequence together while
using a separate fixture module from mail access and case orchestration.

Additional enrollment uses a small core method policy and PostgreSQL
`passkeys/enrollment_authority.rs` for locked owner/session and realm-wide key
state. Preparation/completion keep their transactions and final clock checks visible.
Tests under `passkeys/enrollment_authority/` separate stage/realm/provenance
boundaries, the bootstrap race and observed write/owner waits. Positive fixtures
retain their software authenticator and perform real assertions; they do not
fabricate stronger session provenance to continue enrollment.


Genuine fresh passkey-method ownership is shared by management/recovery setup in
`passkeys/authority.rs`; enrollment retains its distinct first-key bootstrap policy.
Saved-code core flow/port and PostgreSQL configuration/delegation have separate
`passkeys/recovery_setup/` modules. Confirmation keeps replacement, pending
consumption, audit/notice and final deadlines in one visible transaction. Its length
is a reviewed cohesive transaction exception. Feature tests separate binding/method
boundaries, isolation/erasure, concurrency/rollback, migration and observed expiry.
The local notice smoke retains create/start/assert/stop/owned cleanup together;
its longer main function makes those resource boundaries explicit.


Saved-code HTTP configuration lives in `auth-axum/passkeys/recovery_setup/`, with
routing, thin handlers, closed transport types and the additive full contract in
separate modules. A private management composition function accepts the selected
OpenAPI document; older public constructors retain their routes/document. HTTP
tests group contract, lifecycle and boundary cases under the owning management
feature fixture. Native contact proof has a shared focused module, while saved-code
cases use separate accounts and preserve earlier management assertions/admission.
The seven-argument explicit constructor and longer test/fixture composition retain
visible service alignment/resource ownership; no generic routing framework or
independent transport policy is introduced.


Claim state uses core `passkeys/recovery_claims/` flow/port/metadata and PostgreSQL
beginning, ownership/projection, cancellation, admission and delegation modules.
Notification leasing/completion and recovery receipt handling now have focused
`notifications/` modules; the entry file contains declarations only. Shared
passkey-sensitive admission selects a bucket from a session snapshot and never
authorizes. Receipt completion and claim creation/cancellation keep their longer
owner/claim/notice transaction and final original deadline checks visible; these
are cohesive size exceptions rather than scattered transaction helpers. Test
modules separate admission, lifecycle/binding, cancellation/rollback, receipt,
concurrency, migration and observed waits. Shared migration setup finishes later
schema before current-adapter flows; historical target assertions remain explicit.


Private replacement flow, repository contract and unforgeable registration
transition live in core `passkeys/recovery_replacement/`. PostgreSQL keeps readiness/
locking, registration, assertion completion, owner-proof invalidation and delegation
under `recovery_claims/replacement/`. Completion's longer transaction deliberately
keeps email-before-owner, exact candidate checks, RP uniqueness, revoke/install,
audit/notice, consumption and final deadline visible; invalidation is a named
transaction-bound operation, not independent policy. Tests separate lifecycle,
boundary/protocol, invalidation, rollback/races, ordered code-rotation contention,
migration and observed row/final-write
waits. Longer scenarios preserve arranged authority and full rollback assertions.


Experimental recovery HTTP lives under `passkeys/recovery/`: named service
composition and body-limited route groups, concrete wire types/full schema, cookie/
anonymous-session boundary, binding, claim metadata, cancellation and replacement
handlers each have a focused module. The setup route builder was extracted and
checked before extension; older constructors keep their schemas. No SQL or duplicate
recovery policy enters handlers. Current-key cancellation shares the existing core/
PostgreSQL authority/transaction path. Integration cases group binding, boundaries,
contract, cancellation, lifecycle/concurrency and rollback/receipt behavior under
the owning feature. Longer fixtures/scenarios retain actual proof and ordered
resource/state assertions; new implementation modules remain below 300 lines.


Recovery reference assets live under `pages/recovery/`, with separate setup and
recovery controllers and scoped HTTP/WebAuthn/lifecycle transport functions. Their
route declaration stays in `passkeys/recovery/pages.rs`; ordinary composition is
unchanged. Native recovery scenarios/setup/cancellation and the owned runner live
under `tests/browser/passkeys/recovery/`. The real-SMTP owned DB/process lifecycle
is shared by the two server examples through `examples/support/smtp_fixture.rs`,
extracted and verified before extension. The new example separates composition,
clock-only trusted fixture control and aggregate DB assertions. No production
clock configuration, mock key/session or generic workflow framework is introduced.
Longer fixture orchestration retains ownership/cleanup ordering; feature modules
and scripts remain below roughly 300 lines.

The recovery example also owns a human signup bootstrap under `manual/`, with
static resource routing in `manual.rs`. It calls real signup through the shared
reference-client transport and contains no alternate registration/session policy.
Its additional native case is separate from the seven recovery scenarios. These
fixture-only resources never enter library or normal server composition.

Reference-client prompt classification stays private in `pages/recovery/shared.js`
next to the scoped native/network/page-lifetime transport. No handler or core policy
is duplicated. Controlled creation/verification rejection and restored-page abort
cases live in `tests/browser/passkeys/recovery/prompt-errors.cjs`, invoked before
the retained-authenticator case's actual successful signatures. The longer ordered
negative scenario keeps its abort/restore/no-request assertions visible together;
both modules remain under 120 lines.

AUTH-28 uses `auth-core/src/oidc/` for public-address/URL policy, metadata, ports,
document caches and feature-specific tests. `auth-server/src/oidc_http/` separates
transport ownership/native DNS, client construction, bounded response handling and
cache headers. Its entry module only declares/reexports. Private component tests
are included from the owning transport module so fixture roots/addresses remain
private without widening production APIs. PostgreSQL delegates to the existing
exact configuration lock/check; no new persistence model or crate is introduced.
Database cases live under `tests/lifecycle/oidc/`.

All new implementation/test modules are below 300 lines. The longer response
download and cache-header functions retain ordered bounds, closed rejection
categories and freshness calculations together. Longer TLS and observed-database
cases retain setup, a valid control, ordered interruption and exact assertions in
one scenario. These are reviewed function-size exceptions with cohesive purposes.
No unrelated structural cleanup is deferred.


AUTH-29 extends the existing key cache slot with one forced-refresh timestamp and
compares opaque snapshot identity in the owning metadata type. No key-ID map, new
crate or parallel cache is introduced. `load_keys` now crosses the 50-line review
trigger: keeping snapshot selection, expiry/URI checks, both miss budgets, fetch,
post-network registry check and cache replacement together makes their ordering
explicit. Refresh regressions live in named core and PostgreSQL feature modules.
The longer core rotation scenario retains exact interval boundaries, coalescing and
request-count controls together. All affected modules remain below 300 lines.

AUTH-29 signature/claim work lives under core `oidc/verification/`: policy, bounded
input/header parsing, typed claims, key selection, orchestration, repository port
and opaque result each have a named module. Entry files only declare/reexport.
PostgreSQL `oauth/verification.rs` reuses existing configuration and original-owner
locking/freshness policy, then takes a single post-wait database clock observation.
No independent account policy, generic crypto plugin or extra crate is introduced.
Tests group validation, signed-header/key boundaries and rotation separately; PG
cases group context/realm/revocation and observed lock-wait deadlines.

All new Rust modules remain below 300 lines. The longer selected-key function keeps
duplicate admission, exact key selection, validated public-component construction
and the fixed established-library verifier choice visible together. Operation-use
authorization is a named method, and claim time/audience/attribute checks are separate
readable methods. Longer security matrices retain valid controls and exact failure
assertions together; ordered PG cases retain arrange/observe/release/assert steps.
These are reviewed function-size exceptions, not reason to widen private APIs.
No unrelated cleanup is deferred.

The native-worker regression uses an owned runtime/queue gate and the actual public
verification API. It tests cancellation, prompt overload and recovered valid work
without production hooks or wider implementation visibility. Its longer ordered
function keeps queue ownership, cleanup and positive controls together.


Code exchange extends `oidc/verification/exchange/` with separate authentication,
authorization URL, protected request, response and orchestration modules. Metadata
policy remains in core documents; `oidc_http/token.rs` owns only concrete HTTPS POST
construction and shared bounded response reading. Private TLS fixtures obtain actual
opaque requests through the public core flow, rather than exposing a constructor
for tests. Core exchange scenarios separate binding, response errors, authority/
concurrency and non-cacheable metadata. Longer ordered tests/fixture setup and form
construction keep exact input/output and redaction invariants together; all new
modules stay below 300 lines. No unrelated structural cleanup is deferred.


Keycloak acceptance has its own owned example: database lifecycle, composition/
command/proof state, and private transport each have a focused module. It includes
existing production TLS/cache/GET/POST/response modules by private source path,
without widening an application API or duplicating protocol/SQL policy. The POST
helper extraction was verified and committed separately before fixture behavior.
Node separates provider provisioning, TLS proxy/faults, browser callback, private
IPC ownership, scenarios and runner/provenance. All new modules remain below300lines.
Longer ordered composition, callbacks and resource try/finally functions keep proof,
cleanup and fixed diagnostic boundaries visible as reviewed size exceptions. No
unrelated structural cleanup, generic test engine or shared plugin is introduced.


First ordinary document admission remains in the owning discovery/key cache module;
leased code-flow orchestration opts into its bounded wait, while standalone and
forced-refresh paths retain prompt admission. No generic retry abstraction or
public timer/configuration hook is added. Exchange admission/expiry/cancellation
scenarios have their own feature test module; actual native/final-authority lease
checks stay with verification worker tests. Cache/preflight guards end before
timers, and final authority/claim validation retains the operation lease. All
changed implementation/test modules remain below300lines; longer ordered scenarios
retain their observation, release and valid controls as reviewed size exceptions.


AUTH-30's owned provider fixture keeps callback/state capture and replay in its
private transactions module, protocol construction in a shared factory, identity
command adaptation under the fixture, and state/evidence in named identity modules.
The original Node verifier cases remain separate from the new identity scenarios.
No production verifier constructor, database internals or HTTP hook is exposed.
New files remain under300lines; longer ordered setup/command/case functions retain
resource ownership, original proof handling, finite diagnostics and cleanup as
reviewed size exceptions. No unrelated structural cleanup is deferred.

## AUTH-55 experimental HTTP boundary

`auth-axum/oidc/deletion/` keeps trusted service alignment/routing, protected cookie
transport, closed DTOs, thin use-case handlers, OpenAPI and fixed reference pages
in named modules. No SQL, alternate authorization policy or network crypto is
implemented in the adapter. Two read-only core configuration getters enable exact
composition checks without exposing secrets or constructing verified proofs.
Feature-owned `tests/browser/oidc_deletion/` separates boundary, binding, completion,
commit ordering, failure cases and actual signed-provider setup. All new modules
remain below 300 lines. Longer fixture construction and ordered commit-wait tests
keep prerequisite verification and the observed invariant together; production
handlers remain under the function-size review trigger. No unrelated cleanup is
deferred. The browser client checks are separate from native Keycloak acceptance.

AUTH-56 moves that adapter under the owning `oidc/` feature tree before adding
browser sign-in. Exact trusted source alignment and the protected cookie codec
live in private sibling modules, with fixed deletion cookie names and unchanged
public deletion constructors, paths and contracts. This structural checkpoint
adds no authentication behavior or persistence policy.


AUTH-55's owned HTTP provider fixture keeps composition/commands, bootstrap,
server/cookie delivery, finite proof observation and a rejecting no-mail tripwire
in named `apps/auth-server/examples/oidc-deletion-http/` modules. Its entry file
only declares/reuses modules and coordinates owned lifetime. The existing bounded
IPC reader/writer was extracted and verified separately before extension; database
ownership and production transport modules are reused without a public bypass.
The browser runner separates owned lifetime/reporting, browser actions and named
acceptance scenarios. All new modules remain below 300 lines. Longer setup and
ordered scenario functions keep prerequisite proof, observed outcome and cleanup
visible together; no application authorization is duplicated in fixture code.


AUTH-56 first extracts existing server configuration without behavior changes:
`configuration.rs` retains environment/public-origin/bind/realm composition and
its existing public `configured_auth` signature. Named `configuration/mail.rs`,
`database.rs` and `passwords.rs` own unchanged SMTP setup, PostgreSQL setup and
password-corpus attachment. Validation order, defaults, bounds, TLS/development
rules and secret-safe errors are preserved. This structural checkpoint is verified
before adding OIDC startup semantics; no generic configuration framework is added.


AUTH-56's stable configuration behavior lives in PostgreSQL
`oauth/identity_startup.rs`. Registry lock/initial-insert primitives stay with
`oauth/configuration.rs`; the existing policy write was extracted and verified in
a separate structural commit before reuse. Policy and configuration rechecks/commit
stay visible in the startup use case; no provider I/O or duplicated policy is added.
Core exposes only a narrow validated policy-metadata restoration method, with the
OAuth field mutator crate-private and no new proof constructor. Feature tests under
`oidc/identities/startup/` separate lifecycle, denial, faults and observed concurrency
from reusable scoped setup. All new/affected modules stay below 300 lines. Longer
ordered concurrency and lifecycle cases retain prerequisites, actual waits, precise
results and cleanup together; no unrelated cleanup is deferred.

AUTH-56's `oidc/web/` separates trusted service/router composition, closed DTOs,
nonmutating callback selection, thin use-case handlers, contract and fixed sign-in
pages. It reuses the existing deletion routes through a private composition boundary,
without duplicating deletion policy or persistence. Cookie namespaces are fixed
constants in the owning codec. The two clients retain explicit purpose-specific
confirmation and status handling rather than hiding destructive behavior behind a
generic client framework. Test modules group boundary, callback, completion, failures
and independently observed commit ordering. The actual-signature provider fixture
now lives once in `tests/support/oidc_provider.rs`, with explicit expected redirect
supplied independently of the request. All affected modules remain under 300 lines;
longer ordered setup/scenarios retain prerequisites, observations and positive
controls together as reviewed size exceptions. No unrelated cleanup is deferred.

AUTH-56 extracts `auth-server/application.rs` as the shared configured application
factory before enabling OIDC startup behavior. Both standalone and embedded entry
points use its typed auth/browser/router/bind result; `configured_auth` is preserved.
The extraction retains default routing, configuration validation and notification
worker ownership, verified through existing workspace and real-SMTP lifecycle cases.

Server OIDC startup extends that factory through `application/oidc.rs` and focused
`configuration/oidc/` modules for the closed environment contract, typed policy and
protected credential-file loading. Base parameter parsing stays with configuration;
database/SMTP/password composition is reused. Core exposes metadata-only document
configuration validation using its existing private egress policy, avoiding a second
URL/IP policy or startup write before validation. Production transport has no fixture
injection. Tests keep pure settings/file cases separate; the named startup script
owns normal-binary mode/restart/refusal cases and disposable resources. New modules
remain below300lines, with no unrelated structural cleanup deferred.

AUTH-56 extracts the embedded example's application-owned private route/state into
`examples/embedded/application.rs` before native public-login acceptance reuses it.
The entrypoint retains configured factory/listener/worker composition. Existing
standalone/embedded actual-SMTP lifecycle checks and strict lint verify unchanged
behavior; no provider policy, credential capability or production hook is introduced.

Native OIDC runners share only bounded private JSON pipes and owned process-group
shutdown in `tests/browser/oidc/owned-process.cjs`. Existing fixture capability,
database-cleanup and exact outcome assertions remain in `fixture.cjs`. Application
and configuration module paths are explicit so the owned acceptance producer can
compile the unchanged configured-factory sources without a production transport
hook. This structural preparation is verified against all existing 6 HTTP and 23
backend provider cases before the new public-login scenarios are introduced.
