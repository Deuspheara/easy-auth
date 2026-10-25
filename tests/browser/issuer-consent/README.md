# Owned HTTPS issuer consent acceptance

Run only with the repository's disposable local PostgreSQL development fixture:

```sh
cargo build --locked -p easy-auth-axum --features issuer-consent-web --example issuer-consent-browser
DATABASE_URL=postgres://… node tests/browser/issuer-consent/run.cjs
```

Uses the existing pinned Playwright dependency/Chromium, private TLS proxy, owned
process lifecycle and restricted disposable database helper. It changes no system
trust or browser settings. External requests are blocked; the registered owned
application callback alone is fulfilled. The private fixture inbox delivers actual
email proofs through normal HTTP completion; no session or verified provider proof
is constructed. Never deploy that example or its inbox.

Eight cases cover query/storage/cookie privacy, explicit preview/allow/deny, reload
recovery, a real old-tab/new-cookie preview mismatch, restoration and duplicate query
refusal. Output is finite counts/cleanup only; no code, cookie, mail token, nonce or
raw response is logged. Database aggregate facts distinguish code/subject creation
from local authority. The database and TLS files are removed on normal/failed exit;
owned emergency cleanup reports separately and is not a successful normal result.

This proves consent delivery only. It exercises no token endpoint, signed issuance,
external application/native interoperability or production deployment. It generates
no XML/signature/adversarial producer and runs no bypass/fuzz/stress experiment.
