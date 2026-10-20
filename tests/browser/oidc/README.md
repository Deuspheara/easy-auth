# Owned Keycloak code-exchange acceptance

This explicit native suite uses the real PostgreSQL OAuth begin/consume/context
ports and core authorization/code/S256/signature verifier against official
Keycloak 26.8.1, pinned to the image digest in `keycloak.cjs`. It is separate from
ordinary Rust tests and is mandatory in CI after browser dependency setup.

Start the documented development PostgreSQL service and export its loopback
`DATABASE_URL`. Use Rust 1.95, Docker, OpenSSL CLI, Node 24 and the existing pinned
browser package; no new npm dependency or production provider account is needed:

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --example oidc-keycloak --features oidc-identities
EASY_AUTH_OIDC_IDENTITIES=1 node tests/browser/oidc/run.cjs
```

The runner owns a random loopback-only Keycloak container, random bootstrap/client/
user credentials, private temporary directory, TLS proxy, isolated Chromium
contexts and random PostgreSQL database. The application runtime has no fixture
endpoint or setting. Do not deploy the example or run its private IPC directly in
a terminal/log. Never capture IPC, browser storage, response bodies, traces,
screenshots, headers, provider assertions, passwords or codes. Ordinary output
contains only finite case outcomes, versions, aggregate counts and cleanup facts.

The example recompiles the same internal production TLS builder, GET/POST and
bounded response readers without widening their API. Only its private transport
maps the core's checked fixture hostname/address to its owned TLS listener and
certificate. Rust still validates hostname/SNI, certificate, peer, time/body/type
limits and redirect/proxy policy. Chromium's disposable context tolerates only the
fixture certificate in practice because all traffic is constrained to the owned
provider and intercepted callback. The host resolver and proxy arguments apply to
that owned browser process only; no hosts file, system security setting, credential
manager or user browser is changed.

Administrative provisioning and the exact captured code/verifier replay use the
owned loopback provider backend; actual application metadata/code requests use
the production HTTPS sources through the owned TLS proxy.

The required cases cover actual code+S256/RS256 identity proof; exact PostgreSQL
consumed-state and original provider-code/verifier replay; actual provider-signed
wrong nonce and untrusted additional audience; wrong PKCE; deliberate proxy
signature corruption and old-token substitution; actual Keycloak signing-key
rotation; a fresh valid control after negatives; and disabled database context
before credential transmission. Missing provider email claims remain valid and
create no local contact/session. The disposable provider user has a complete
profile, while this client requests only openid/profile and has no email scope.

The runner inserts no admission delays between starts or callbacks. The application
keeps its two-operation limit while waiting once before a first ordinary discovery/
key fetch, then uses the unchanged one-second admission checks. It preserves actual
provider discovery/JWKS cache headers. Keycloak's
no-store keys mean the real rotation case does not prove the forced-refresh cache
branch; separate actual-signature/cache tests prove that bound. Controlled signature
corruption and captured-token substitution happen at the owned proxy, never inside
Keycloak; other invalid claims are actually signed by the provider. These facts
must remain distinct in any evidence or interoperability claim.

The first eleven cases retain exact zero local users/sessions/audits/pending work
before identity setup. Identity mode then runs eight additional named cases: an
owned mailbox-proof control; fully verified default-deny; explicit JIT with a
matching provider-verified email and no merge; bound-subject login without optional
profile; a live verified/mapped proof rejected after policy revision; existing
subject login under deny; denial of a different valid subject with usable selected
display; and a live verified proof/session rejected after local disable.

The owned provider uses the [documented client-scope administration
API](https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html): email is optional and asserted verified for the disposable primary user, and
profile becomes optional to produce genuinely signed tokens with no name. A second
owned user proves JIT denial is not missing-profile rejection. These are real
provider-signed claims, without proxy claim rewriting. The mailbox control uses
actual bound repository proof consumption, not SMTP delivery or seeded sessions.
Only finite outcomes/counts/booleans cross the private result pipe; user IDs, local
session secrets, provider tokens and credentials are not report fields.

The private fixture explicitly configures and re-enables its latest local connection
after the original disable case, then applies real administrative policy revisions.
Held proofs remain opaque original mapped values, not reconstructed input. A live
original-cap check prevents expiry from masquerading as the intended revision/disable
denial. The returned optional provider authentication-time value is compared exactly to
stored session provenance. Missing/old-time policy has separate signed-software
PostgreSQL coverage; this native run does not assume the provider omits that claim.

The original nineteen cases require exactly two users (mailbox
and provider), four sessions/audits, zero pending work, one external identity and
provider user, three genuine oidc sessions, and zero provider contacts/weak-method
sessions, before the deletion cases begin. Their proxy totals remain 15 posts/14
successful token responses; original verification-only totals remain 8/7, with
the same one controlled signature mutation and one captured-token replay.

Four further cases restore a current source without reviving old sessions, request
actual provider reauthentication, reject a valid fresh signed wrong subject without
mutation, delete the exact initiating provider owner, and reject a fresh valid JIT
request during cooldown. The wrong-subject and deletion proofs require real signed
authentication time, a live original cap and valid initiating session. Optional
profile is absent; cooldown denial instead requires usable signed display, enabled
current configuration and persisted JIT-Allow, preventing another failure from
masquerading as the intended denial. Callback state replay sends no code.

Only this phase assigns Keycloak's built-in `basic` default scope, which supplies
the genuine authentication-time mapper per the
[pinned upstream migration documentation](https://github.com/keycloak/keycloak/blob/26.8.1/docs/documentation/upgrading/topics/changes/changes-25_0_0.adoc#new-default-client-scope-basic).
The original minimal client explicitly selected profile/email and omitted that
scope. Missing time correctly rejects; it is never replaced by token/local-session
issuance time or a provider profile attribute. Disposable additional provider users
have unique bounded names so their generated mailbox local parts remain valid.

Final completion requires native zero exit, exactly one surviving mailbox user and
session, six audits, zero pending/identity/provider/oidc/weak-provider rows, one
deletion fact, four erased provider audits, one intact mailbox audit and one live
cooldown. Proxy totals are 19/18 with the original single mutation/replay. This is
backend proof through a private fixture, not a public HTTP deletion flow or SMTP
contact-deletion test. Normal owned database, provider and private-file
cleanup is mandatory. Timeout cleanup can remove only the exact generated database
and owner-labeled container; emergency cleanup never converts a failed suite to a
pass. No production-provider credentials, independent security audit, public
callback/ordinary activation or production interoperability is established here.

`EASY_AUTH_OIDC_TEST_BINARY` can select a fixed owned producer copy.
`EASY_AUTH_TEST_REPORT` creates a new immutable sanitized report with versions,
source/binary hashes, case outcomes and cleanup facts; it refuses to overwrite an
existing file. Reports contain no raw token, account IDs, credentials or proof.


The current [fast-callback record](results/2026-10-20/keycloak-fast-callbacks.json)
records `runner_admission_delays: false`. The original paced
[provider record](results/2026-10-20/keycloak-code-rotation.json) stays immutable;
it established those named provider cases with explicit interoperation pauses.
Core tests independently reproduce immediate callback/key admission and final
native-retry lease boundaries; source/binary hashes distinguish the two producers.


The [identity/JIT record](results/2026-10-20/keycloak-identity-jit.json) contains all
**19** cases with `local_identity_cases: true` and no runner admission pacing.
It retains original eleven-case assertions and records exact application/identity
aggregates plus normal cleanup. Source/binary hashes identify its producer. CI
now requires all **23** cases in the
[provider-deletion record](results/2026-10-20/keycloak-provider-deletion.json),
identity mode and both compiled capabilities; it cannot silently run only
the old cases. A separate verification-only example compile and core tests retain
that optional-feature boundary. For explicit legacy compatibility, building with
`oidc-verification` and omitting `EASY_AUTH_OIDC_IDENTITIES` still runs eleven cases
and requires exact zero local authority. Earlier reports remain immutable.
