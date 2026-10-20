# Registered Google native acceptance tool

The optional `google-native-acceptance` example prepares the remaining registered
Google/OS-browser matrix. Its configuration and owned-setup checks do not establish
registered-client acceptance. The actual sign-in mode is deliberately separate;
a [registered native sign-in](results/2026-10-20/registered-native-signin.json)
passed on macOS with the operator-reported Helium browser. A separate
[IPv6 run](results/2026-10-20/registered-native-signin-ipv6.json) passed on the same
platform/browser. These base-profile results do not complete the provider/platform matrix.

## Inputs and local ownership

Use a disposable Google account/application with a client registered as **Desktop
app**. A client ID identifies that app to Google; it does not replace your Google
account or prove application authenticity. Follow Google's
[Desktop setup](https://developers.google.com/identity/protocols/oauth2/native-app).
This tool does not create a Cloud project/client or change provider settings.

Put only the wire client secret in a bounded UTF-8 regular file outside the
repository. Use your editor/secret manager; never put its value in command arguments,
shell history, chat or reports. The exact existing server secret-file reader is
reused privately: Unix requires owner-only permissions, content is bounded and
zeroized, and file/content errors do not echo values or paths. Windows file ACL
protection and actual Windows acceptance require their own review/evidence.

| Environment variable | Meaning |
| --- | --- |
| `AUTH_GOOGLE_TEST_CLIENT_ID` | Complete registered Desktop client ID |
| `AUTH_GOOGLE_TEST_CLIENT_SECRET_FILE` | Absolute protected file path; secret text only, not downloaded credential JSON |
| `AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD` | Explicit `client_secret_post` or `client_secret_basic`, matching registration; no public-method fallback |
| `AUTH_GOOGLE_TEST_LOOPBACK_IP` | Optional literal `127.0.0.1` (default) or `::1` |
| `AUTH_GOOGLE_TEST_CLAIMS_PROFILE` | Optional `base` (default) or explicit `session_age` |
| `DATABASE_URL` | Documented local development PostgreSQL administrative connection, literal loopback with no query/fragment |

The tool creates/migrates only its own randomly named disposable database, using
`tests/support/google/database.rs`; it never migrates the administrative database.
Do not use production credentials or a production database tunnel. Permission to
create/drop the disposable database is required. Source/realm/connection/local
client IDs are generated inside this isolated database; callers cannot select an
ambient account/session. The transient registration uses the existing stable native
profile, exact owned return and subject-only JIT policy. It remains developer test
composition, not an installed-client DB credential model or remote token issuer.

## Build and check before browser interaction

```sh
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --features google-desktop-launch,oidc-identities --example google-native-acceptance
target/debug/examples/google-native-acceptance --check-configuration
target/debug/examples/google-native-acceptance --check-owned-setup
```

First set the variables above yourself. The configuration check reads/validates the
protected local input but performs no network/database/browser operation. The
owned-setup check uses production public-root HTTPS metadata and actual PostgreSQL
policy/native-operation preparation/cancellation, then drops its own database. It
never invokes the opener, visits the authorization URL, submits client credentials
or verifies a token. Both checks report `registered_client_confirmed:false`;
placeholders can pass them. Their output is not a real provider acceptance result.

`session_age` additionally requires Google's published/verified application and
[session-age feature eligibility](https://developers.google.com/identity/siwg/security-bundle).
No setting is changed automatically. Missing signed `auth_time` fails the required
profile; there is no fallback to base. Requesting a claim or receiving a newly
issued token is not freshness. Google documents no Google Account reauthentication
request, so genuine usable freshness/deletion remains a separate lifecycle gate.

## Real manual sign-in

Only after reviewing the setup, explicitly invoke:

```sh
target/debug/examples/google-native-acceptance --run-manual-signin --disposable-account-consent
```

This opens the configured OS browser to Google for fixed `openid email profile`
scopes. Complete account selection/sign-in/consent yourself. Never share your
Google password, challenges, callback URL/code, token or credential data. The flag
is an operator accident guard; authority still requires the library's actual owned
callback, original state/private nonce/S256, issuer/signature/claim verification
and current-source PostgreSQL identity/session/audit commit.

After a verified completion, the tool validates the exact local session, revokes
it and requires subsequent Unauthorized. Scoped observations must show one user,
one provider identity, one revoked session, two audits and zero pending rows.
It then drops the disposable database before emitting finite JSON. Only signed
`auth_time` presence is reported, never a freshness/deletion success. No account ID,
subject/email, private proof, wire credential, token or raw foreign error is emitted.
Denial/provider error, transport failure, source rejection and storage unavailability
remain distinct failing outcomes; they do not become successful sign-in records.

During the owned native operation, Ctrl-C passes cancellation to that operation;
signal-handler failure is an infrastructure error. Opener/callback/exchange limits
stay those of the library. Interruption during initial setup, later local completion
or a forced process termination cannot promise asynchronous cleanup: independently
inspect the exact owned database, rather than deleting unrelated databases. The
same catalog query as the [public preflight](README.md) should find zero
`easy_auth_google_probe_` databases after a completed run.

Local cleanup does not revoke a Google authorization grant that may have been
created during consent. Any provider-grant review/removal belongs to the owner
using that disposable account/app. This tool does not modify existing Google grants.

## Verification scope

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p easy-auth-server --example google-native-acceptance --features google-desktop-launch,oidc-identities
```

The offline suite uses actual RS256/public JWKS, public authorization inputs,
IPv4/IPv6 sockets and PostgreSQL through the same private setup/completion modules.
It covers input/permission guards, explicit profiles and bound cancellation,
actual signed completion/commit/revocation, old signed authentication time without
invented freshness, signed rejection versus provider transport failure, required
claim absence, current source disable and final audit-failure rollback with healthy
controls. Reused independent socket observers retain their own live/refusal controls.
No OS opener is invoked by these tests. Existing library process-actor cases retain
their separate scope. CI runs this offline suite without real provider credentials.

The [tool-validation record](results/2026-10-20/native-tool-validation.json) records
source/producer provenance, public owned-setup and CLI guard checks. It explicitly
records actual manual sign-in as unperformed at preparation time. The separate
[live result](results/2026-10-20/registered-native-signin.json) records the later
registered Desktop/base-profile completion, session validation/revocation and
independently checked database cleanup. Signed `auth_time` was absent; freshness
and deletion remain unaccepted. The later
[IPv6 record](results/2026-10-20/registered-native-signin-ipv6.json) independently
verifies the same outcomes through the literal `::1` callback. Record each real platform/client/
profile/outcome separately using only finite sanitized results; do not turn the
setup checks or offline signatures into registered Google/OS evidence. Broader
native persistence/concurrency, genuine freshness/deletion, ordinary activation
and independent review remain AUTH-23 gates.
