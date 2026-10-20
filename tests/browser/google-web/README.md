# Owned Google HTTPS reference-client regression

Use the documented development PostgreSQL and the pinned Node24/Playwright setup
in `../passkeys/`. No Google registration, production credential or human prompt
is required:

```sh
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-axum --features google-web --example google-web-browser
node tests/browser/google-web/run.cjs
```

The runner creates its own temporary certificate/key directory and HTTPS proxy,
an isolated Chromium context and a disposable PostgreSQL database. Only this
context accepts the private certificate. Public app.example traffic is mapped to
the owned loopback proxy. Every external Google authorization navigation is
intercepted within that context and redirected to the fixture-only authorization
endpoint; every other external destination is blocked. No real Google endpoint,
vault, device or system/browser trust setting is touched. Never deploy the example.

The example composes the actual experimental Google router, core authorization,
PostgreSQL policy/transactions and shared RS256 provider fixture. The provider sees
only the actual public client/redirect/nonce/S256 authorization inputs. It never
reads private proof cookies or seeds an account/session/proof. Actual signed
responses drive the normal HTTP callback/finish, mapping and commit. The fixed
controlled authentication times are offline fixture data, not real Google events.
All mailbox delivery is disabled; this is the email-free provider account path.

Thirteen cases cover bound provider denial/failure, duplicate query rejection,
persisted-navigation proof drop, fragment rejection/scrubbing, actual signed nonce
failure, explicit sign-in confirmation before a committed session, ambient-session
switch refusal, deletion cancellation/denial, old/missing signed time and repeated
confirmation before actual fresh-proof deletion. Every callback is scrubbed; script
cookies/storage and reflected foreign details remain absent. Real aggregate facts
end at zero users/identities/sessions/pending, two audit facts, five token POSTs and
five actual signatures. Those counts are checked, not used to fabricate authority.

The parent owns the child and uses bounded graceful shutdown. Emergency database
cleanup accepts only the exact reported owned random name and is a failed acceptance
condition. The normal path verifies child exit0, database removal and temporary TLS
file removal. No screenshots, traces, storage state, codes, tokens or key material
are saved/logged. The optional `EASY_AUTH_GOOGLE_WEB_TEST_BINARY` pins a rebuilt
producer and `EASY_AUTH_GOOGLE_WEB_TEST_REPORT` writes a new immutable report with
source/binary hashes, versions, fixed case outcomes and aggregate cleanup facts.

This proves owned component behavior only. Ordinary standalone activation,
registered Google profile/claim eligibility and genuinely usable fresh lifecycle,
OS system-browser launch/return, broader browser/device evidence and independent
review remain separate gates. It does not resolve the recorded Safari recovery
failure or establish production readiness.
