# Clean-checkout setup walkthrough

This walkthrough checks the default same-origin email/password application using
local disposable PostgreSQL and Mailpit. It needs Rust 1.95, Docker Compose and a
POSIX shell. No provider account or production credentials are required. Choose
[provider setup](provider-setup.md) only after this baseline works.

## Create an isolated development environment

Use a new checkout and a new Compose project. The example's loopback ports are
PostgreSQL 59473, SMTP 1025, Mailpit 8025 and the application 58417. If any belong
to an existing preview, leave that preview running: use separately provisioned
disposable services and explicitly override `DATABASE_URL`, `SMTP_PORT`,
`AUTH_BIND` and `AUTH_PUBLIC_URL` instead. Keep each listener loopback-only and
keep the browser origin equal to the actual application address.

```sh
git clone https://github.com/Deuspheara/easy-auth.git easy-auth-walkthrough
cd easy-auth-walkthrough
walkthrough_project=easy-auth-walkthrough-$(date +%s)
docker compose -p "$walkthrough_project" up -d --wait
cp .env.example .env
set -a
. ./.env
set +a
cargo build --locked -p easy-auth-server --bin easy-auth
./target/debug/easy-auth --help
./target/debug/easy-auth --version
./target/debug/easy-auth
```

Keep that terminal running. The binary reads exported environment settings; it
does not load `.env` itself. The example credentials and small password corpus
are development-only. Startup runs migrations and provisions the configured
realm, which is why this walkthrough must use disposable storage.

In a second terminal, check `http://127.0.0.1:58417/healthz` and `/readyz`.
Liveness and database readiness do not prove SMTP/provider delivery. Opening
`http://127.0.0.1:58417/` should show email and password access. Compiling the
default binary does not mount experimental passkeys or configure a provider.

## Exercise the actual account journey

1. In a fresh browser context, request a link for a disposable `example.test`
   address through the root page. Expect the generic check-email screen.
2. Open `http://127.0.0.1:8025`, select the message for that exact recipient and
   open its link in the browser context that requested it. The confirmation page
   removes the fragment before the existing completion POST; a GET alone grants
   nothing. Expect the actual account overview after completion.
3. Open Profile and check the same address. Open Sessions and check the current
   session. Do not infer device/location or freshness from presentation metadata.
4. Use the password enrollment view with a unique disposable password satisfying
   the documented [password policy](passwords.md). Never use a personal password
   in a development fixture. Sign out, then sign in through the password view.
5. Sign out again. A subsequent `/v1/session` request from that browser must return
   401. The same-origin page should return to its signed-out presentation.

Keep proof links, cookie jars, passwords and response bodies out of screenshots,
logs and issue reports. The ten-minute email proof still requires its initiating
browser. A different context or replay cannot substitute for it. Do not clear
admission counters or increase limits to make repeated trials succeed.

## Check configuration failures deliberately

Stop only the application process you started. From the same repository and
exported development environment, these commands are expected to fail:

```sh
./target/debug/easy-auth --help extra
AUTH_REALM_ID=invalid ./target/debug/easy-auth
AUTH_DEVELOPMENT=false AUTH_PUBLIC_URL=http://127.0.0.1:58417 ./target/debug/easy-auth
```

The first exits with status 2 and `invalid command line; run easy-auth --help`.
The second identifies `AUTH_REALM_ID must be a UUID`; the third identifies the
HTTPS/allowed-origin requirement. None is evidence of a successful database or
provider check. A missing database, occupied port or unrelated panic must not
count as the expected rejection. See the exact
[diagnostic table](server-cli.md#startup-diagnostics).

The maintained subprocess checks independently exercise malformed values,
non-Unicode settings, secret-safe output, valid controls and preserved TLS/
loopback rules in an empty environment:

```sh
cargo test --locked -p easy-auth-server --test cli --test configuration
```

For the full persistence checks, keep this walkthrough's disposable PostgreSQL
service running and use its `DATABASE_URL`. Run the suites sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
```

These checks do not require real provider credentials. The separate
[genuine reference-browser suite](../../tests/browser/reference-ui/README.md)
owns its database and exact mail recipients; it is broader than this default
startup walkthrough. Do not point tests at retained human-preview storage.

## Finish and record evidence

Stop the exact application process, then remove only the Compose project created
above. This deletes that project's disposable PostgreSQL volume:

```sh
docker compose -p "$walkthrough_project" down --volumes
```

Do not use this cleanup command for an existing project's data. For independently
provisioned services, remove only the resources you created. Record source commit,
build features, runtime versions, fixed outcomes, test counts and verified owned
cleanup; omit raw credentials, proofs and mail bodies. Distinguish an automated
clean-checkout walkthrough from an independent human or real-provider review.

On 2026-10-25, an automated isolated-checkout walkthrough used the default
binary, PostgreSQL 17.11, Mailpit 1.27 and genuine Chromium. The API journey
verified email delivery, wrong-browser/replay rejection, password enrollment,
login and final revocation. The browser journey also verified password reset,
keyboard/focus, session controls, email change and confirmed account deletion,
with zero external requests, page errors or CSP violations. Both removed their
owned database and exact recipient mail. The 13 CLI/configuration subprocess
tests passed. This was automated local evidence, not an independent contributor,
physical-device or real-provider qualification.

Production transport, roles, backup/restore and release qualification remain in
the [deployment guide](../architecture/deployment.md). Local success neither
completes those gates nor turns SAML's review waiver into independent approval.
