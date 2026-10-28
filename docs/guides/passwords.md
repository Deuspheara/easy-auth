# Password enrollment and sign-in

Passwords are an opt-in headless API sharing the email/session core. Email proof first establishes a verified account. `Auth::with_passwords(Arc<PasswordService>)` enables the feature for embedded applications; share one service across a process to bound aggregate KDF work. The server enables it when `AUTH_PASSWORD_BLOCKLIST_FILE` names a local UTF-8 file. Otherwise both valid password operations return 503. No remote password lookup or telemetry occurs.

The development `.env.example` selects a tiny demonstration list. **It is not a production compromised-password corpus.** Production mode rejects fewer than 10,000 distinct eligible entries. This minimum is a configuration guard, not evidence of corpus quality or NIST compliance. Operators must supply and maintain an appropriately licensed, representative list of common, expected and compromised passwords, including relevant service-specific values. Evaluate coverage and update frequency for the deployment. Corpus adequacy remains a release-review item.

One complete password per line, no comments, no whitespace trimming or substring matching. Input and corpus use NFC normalization. Entries outside the accepted length are irrelevant and excluded. Maximum file size is 32 MiB. File/read/UTF-8/empty-list errors fail startup; missing configuration disables the feature. The list is reduced to SHA-256 membership keys in memory; these are not credential verifiers. User credentials use salted Argon2id. Do not put real users' passwords into the file.

## API flow

1. Complete `/v1/email/start` and `/v1/email/finish` in the same browser. Keep the session cookie.
2. Within five minutes, POST `/v1/password/enroll` with `{"password":"<new password>"}` and exact Origin. A 204 sets a replacement session cookie and revokes every previous session for that user in the realm. A password may be enrolled once; this endpoint never overwrites it. Stale/expired/revoked/invalid sessions or existing credentials return generic 401. A disallowed new password returns 400. Restart email sign-in for a fresh session when necessary.
3. POST `/v1/password/login` with `{"email":"<verified email>","password":"<password>"}` and exact Origin. A 204 sets a fresh opaque session cookie; then use `/v1/session`, protected embedded routes and `/v1/logout` as with email sign-in. Invalid credentials, unknown users and accounts without passwords have the same 401 body. Login never creates an account or changes its email.

Bodies remain limited to 8 KiB, responses are no-store, cookies are HttpOnly/SameSite=Lax and production uses Secure host cookies. No password or hash is returned. Headless clients should use `autocomplete="current-password"` for login, `autocomplete="new-password"` for enrollment, allow paste/password managers and avoid logging form bodies. The minimal reference page presents email sign-in and reset initiation/completion; password sign-in/enrollment remain headless.

Policy: 15–256 Unicode code points after NFC, at most 1024 UTF-8 bytes before and after normalization. Spaces and long Unicode passwords are allowed, without trimming, arbitrary composition rules or periodic changes. The service does not silently truncate. See [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver) for the baseline; this implementation does not claim conformance certification.

## Resource and persistence policy

RustCrypto Argon2 0.5.3, Argon2id version 19, m=65536 KiB, t=3, p=1, random 16-byte salt and 32-byte output. Raw passwords use a redacted zeroizing type after parsing. Plaintext lifetime reduction is best effort; HTTP/JSON/runtime buffers are not a secure-memory guarantee. Malformed or unexpectedly costly stored hashes fail closed before running the KDF.

Two blocking KDF workers per shared PasswordService limit working memory to approximately 128 MiB plus runtime overhead. Saturation returns 429 without an unbounded queue. Canceling an HTTP future does not free the permit while its blocking hash still runs. PostgreSQL admission is shared across replicas: 10 attempts per normalized email and 40 per source per fixed ten-minute window, counting successes and failures for enrollment and login. No forwarded IP is trusted; an embedded application without ConnectInfo uses one shared source bucket. Fixed windows allow boundary bursts. Rate retention and broader abuse/load hardening remain M09 work.

Enrollment locks the realm/user and revalidates the live session and five-minute freshness with database time after locking. Credential uniqueness, old-session revocation, replacement-session insertion and a bounded audit event commit together. Parallel enrollment has one winner. Login verifies outside a transaction, then locks the user and rechecks the exact credential hash before issuing a session and audit event. Future credential updates must use this same user lock. Changing credentials through direct database writes is unsupported. Unknown accounts run a dummy hash with the same parameters; this mitigates the major timing difference, without promising perfectly equal network latency.

Email magic links remain a supported alternative sign-in method. Password enrollment does not increase assurance or disable mailbox sign-in. [Password recovery](password-recovery.md) and [session-management APIs](sessions.md) are available separately. Authenticated password change and stronger-factor recovery policies remain unfinished. No production readiness is claimed.

## Reproduce

With local services and environment loaded:

```sh
cargo run --locked -p easy-auth-server --bin easy-auth
# In another shell with the server running:
python3 scripts/smoke.py --password
# Or run the embedded example, then:
python3 scripts/smoke.py --embedded --password
cargo run --locked --release -p easy-auth-core --example password_cost
```

The benchmark uses synthetic inputs and prints no passwords/hashes. On the development macOS arm64 host (Rust 1.95.0), five release samples at 64 MiB/three passes: hash 85–91 ms; verify 85–92 ms. The initial 19 MiB/two-pass floor measured 13–14 ms, motivating the stronger profile. These are local observations, not service throughput or deployment guarantees; remeasure under representative concurrency before production.
