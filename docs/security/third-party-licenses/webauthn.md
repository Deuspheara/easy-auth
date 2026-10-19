# Optional WebAuthn dependency notices

The `easy-auth-core/passkeys` feature uses these unmodified registry packages:
`webauthn-rs`, `webauthn-rs-core`, `webauthn-rs-proto`,
`webauthn-attestation-ca` and `base64urlsafedata`, all version 0.5.5. Their license
is MPL-2.0. Their authors/maintainers are William Brown, Michael Farrell and
James Hodgkinson; preserve the packages' own individual source notices.

Source, including notices, is available in the exact published crate archives:

- [webauthn-rs 0.5.5](https://crates.io/api/v1/crates/webauthn-rs/0.5.5/download)
- [webauthn-rs-core 0.5.5](https://crates.io/api/v1/crates/webauthn-rs-core/0.5.5/download)
- [webauthn-rs-proto 0.5.5](https://crates.io/api/v1/crates/webauthn-rs-proto/0.5.5/download)
- [webauthn-attestation-ca 0.5.5](https://crates.io/api/v1/crates/webauthn-attestation-ca/0.5.5/download)
- [base64urlsafedata 0.5.5](https://crates.io/api/v1/crates/base64urlsafedata/0.5.5/download)

The PostgreSQL development tests additionally use unmodified
[`webauthn-authenticator-rs` 0.5.5](https://crates.io/api/v1/crates/webauthn-authenticator-rs/0.5.5/download),
also MPL-2.0, to generate signed software-authenticator fixtures. That package is
a development dependency, not a runtime dependency. Test builds therefore require
native OpenSSL even when the production passkey feature is disabled.

The root Cargo.lock records archive checksums. The upstream repository is
[kanidm/webauthn-rs](https://github.com/kanidm/webauthn-rs). No upstream source
files were copied or modified for this integration.

Redistributors of an executable containing these packages must include this
notice and the [MPL-2.0 text](MPL-2.0.txt), preserve applicable notices and provide
recipients a reasonable way to obtain the corresponding covered source. Package
the exact source archives with release materials or provide maintained source
availability instructions; a license allowlist result alone does not establish
distribution compliance. Any future modifications to covered files must also be
made available as required by MPL-2.0. Independent easy-auth source files retain
their declared MIT OR Apache-2.0 licenses. See the
[license's distribution provisions](https://www.mozilla.org/en-US/MPL/2.0/#responsibilities)
and [Mozilla's FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

This feature uses system OpenSSL through `openssl`/`openssl-sys`, without enabling
vendoring. Packaged binaries and containers must also carry the notices for the
actual linked OpenSSL distribution and every other included dependency. Default
production builds do not compile this optional WebAuthn stack. Release packaging and source
availability verification remain M09 gates; this project has no supported binary
release yet.

The bundled MPL text is sourced from the
[SPDX license-list-data plain-text copy](https://raw.githubusercontent.com/spdx/license-list-data/main/text/MPL-2.0.txt).
