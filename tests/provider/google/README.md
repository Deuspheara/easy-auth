# Google public-provider preflight

This explicit external-network check exercises the actual production `OidcHttps`
public roots, DNS/egress and metadata admission, with the real PostgreSQL registry
and native authorization/cancellation path. It opens no browser and accepts no
registered provider client credentials. The default CI suite compiles the example
with its optional features but does not execute this live check.

Start the repository's documented development PostgreSQL and export `DATABASE_URL`
for its administrative connection. The example accepts only a literal loopback
PostgreSQL host with no query/fragment. It creates, migrates and drops its own
random `easy_auth_google_probe_` database; it does not migrate the administrative
or an application database.

```sh
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --features google-desktop --example google-provider-preflight
target/debug/examples/google-provider-preflight --public-metadata
```

Success requires public Google discovery and bounded JWKS-envelope admission,
S256/response-issuer/client-secret-post metadata, an actual native return in the
prepared authorization URL, exactly one pending row, explicit cancellation,
zero user/identity/session/audit facts and rejection after actual source disable.
All GETs use production TLS without extra roots, redirects, proxies or egress
exceptions. The token transport refuses every POST and any attempted POST fails
the preflight. Unregistered placeholders and the private authorization URL never
leave memory. Output contains only fixed outcomes/counts, never provider responses,
proof, tokens, connection strings or foreign error messages.

The failure-cleanup control is separate:

```sh
target/debug/examples/google-provider-preflight --check-cleanup-on-failure
```

It must exit1 with exactly `{"status":"failed","stage":"injected_probe_failure"}`
on stderr, after creating/closing its own database; stdout must be empty. Also
check the PostgreSQL catalog independently for zero matching databases. With the
standard local Docker setup:

```sh
docker compose exec -T postgres psql -U auth -d auth -Atqc "SELECT count(*) FROM pg_database WHERE datname LIKE 'easy_auth_google_probe_%'"
```

Missing mode, a nonlocal host or a URL query/fragment must fail before creation.
The dated record includes missing-mode/nonlocal/host-override negative controls.
Actual provider failures are failing runs, not successful authentication
rejections. Do not add retries, trust exceptions or substitute a local signer to
make a live check pass. A forcibly interrupted process can leave an owned database;
inspect the exact generated database before any operator cleanup.

The [2026-10-20 record](results/2026-10-20/public-provider-preflight.json) captures
finite results, fixed executable SHA256, compiler/platform and a source snapshot:
its base revision plus every changed/new runtime source file. Other runtime source
is verified unchanged from the base. This is source/run provenance, not a
reproducible-binary claim. It contains no raw keys, user data or credential material.

This preflight establishes public metadata/TLS compatibility at its recorded time.
It does **not** establish registered-client acceptance, authorization callback
behavior, token POST/signature/claim validity, actual browser/OS return, genuine
Google freshness, provider-required deletion or ordinary activation. Those remain
AUTH-23 gates. The offline actual-signature/database/browser suites retain their
separate scope and immutable historical reports.
