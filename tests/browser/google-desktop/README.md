# Owned desktop return checks

This suite uses the actual optional server `google-desktop` listener and an owned
Chromium navigation. It does not call Google, launch the OS default browser, use a
registered native client, configure provider settings or issue database identity/
session authority. Full Google native acceptance remains required in AUTH-23.

Use the pinned dependencies/browser installation from `tests/browser/passkeys`:

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
CARGO_INCREMENTAL=0 cargo test --locked -p easy-auth-server --features google-desktop google_desktop
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --features google-desktop --example google-desktop-browser
node tests/browser/google-desktop/run.cjs
```

The example's stdout is private parent/child protocol IPC held only in memory;
never forward it to logs or record the callback URL/state. No traces, storage-state
files, credentials or provider responses are saved. The script emits finite
aggregate output only and terminates its own child on failure/timeout. It checks
actual loopback delivery, query removal by the CSP-allowed inline script, fixed
nonreflective HTML, no cookies/script storage and clean producer exit. The library
returns only an opaque delivery value, without declaring authentication success.

`EASY_AUTH_DESKTOP_TEST_BINARY` can select a fixed owned producer copy to prevent
later Cargo commands replacing the tested executable. `EASY_AUTH_DESKTOP_TEST_REPORT`
writes a new immutable report with code-source hashes and producer hash; an existing
report is never overwritten. These transport checks complement the real PostgreSQL
Google authorization tests rather than substituting for them or for registered
provider/platform/manual evidence. Server-side cleanup cannot remove browser history
outside the current page or prove whole-process secret erasure.

The separate server integration suite needs the documented real PostgreSQL setup
and both explicit transport/identity features. It uses actual listener delivery
and the same shared actual-signed provider fixtures as the PostgreSQL crate:

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p easy-auth-server --features google-desktop,oidc-identities --test google_desktop
```

Those nine cases cover backend commit/rollback/cancellation/URI/revision/race/cap
invariants; the browser fixture above still proves only its named transport case.
