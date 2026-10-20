# Configured public OIDC acceptance

Use the documented loopback PostgreSQL/Mailpit development setup, Node 24, Docker,
OpenSSL CLI and the pinned parent Playwright package. After installing Chromium:

```sh
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --example oidc-web-native --features oidc-web
node tests/browser/oidc/web/run.cjs
```

`EASY_AUTH_OIDC_WEB_TEST_BINARY` can select a fixed owned producer copy.
`EASY_AUTH_TEST_REPORT` writes a fresh immutable JSON report (never an existing file).
No trace, video, storage state, credentials, assertions, callback URLs or codes are
saved/logged. The process-group fixture requires Unix. Never deploy fixture binaries.

The runner owns a pinned Keycloak container, TLS proxy/certificate, private protected
client-secret files, isolated Chromium contexts and a random PostgreSQL database per
mode. Browser requests are restricted to the two owned origins; hostname mapping
and certificate tolerance apply only to that disposable browser process. It alters
no host file, credential manager, user browser or system security setting.

The private producer compiles the unchanged configured-application/settings sources
and the actual embedded example's application-route module. Only its concrete
transport name is replaced with the existing owned certificate/address transport,
which reuses production TLS GET/POST/response sources and retains hostname/SNI/peer/
body/time/redirect/proxy checks. Production has no transport injection, root/address
setting or private trust allowance. Normal-binary configuration/refusal behavior is
verified separately by `scripts/smoke_oidc_startup.py`. This is not a normal-binary
public-root positive TLS test or production-provider interoperability claim.

Both standalone and embedded compositions obtain every session exclusively through
public sign-in/start/callback/finish. No HTTP bootstrap endpoint, seeded local user/
session, invented authentication time or proof constructor exists. Trusted explicit
JIT-Allow is required; the shared configured factory validates the real child-process
environment and protected secret file. Its auth-only compatibility API must refuse
enabled browser settings for the precise documented reason before factory startup.

Each mode runs nine cases: route/anonymous boundary, nonmutating callback and cancel,
controlled token503, public login with an observed final-audit commit wait, ambient
session refusal/logout/actual old-bearer replay, returning owner reuse, genuinely
fresh signed wrong-subject deletion denial, explicit fresh deletion/old proof replay,
and verified public-login cooldown denial. Real private database gates observe
actual final audit and scoped subject-resolution waits with a separate max-one
connection observer, preserving original proof expiry. They change no identity,
credential, session, callback state or clock. Expected401/503 outcomes remain distinct
from observer, TLS, process, transport and cleanup infrastructure failures.

Expected totals are eighteen cases, twelve Basic-authenticated token requests, ten
provider responses and two explicitly injected proxy503s; no signature/token
substitution. Each final database has zero user/session/identity/pending/contact/
notice authority, four deidentified audits and one live cooldown. Both servers and
database owners must exit normally, with exact owned database/container/file cleanup;
emergency cleanup is a failure. Raw private-pipe/proof values never become reports.

This email-free owned-provider evidence does not establish provider-contact SMTP,
manual device/browser matrices, independent audit, protocol certification or release
readiness. Preserve the separate original23 backend/six HTTP cases, controlled
clients, normal-binary startup/SMTP checks and all Rust security regressions.

The current report additionally verifies two real application-process restarts per
mode: an anonymous pending callback retains its original browser/DB binding, and
a committed session remains valid with the same local owner and configuration
revision. The protected secret file is retained unchanged. All six application
instances must stop normally before database cleanup. The earlier eighteen-case
report is preserved as historical evidence; do not add the two reports' case counts.
