# Choose an authentication integration

Start with the [clean-checkout walkthrough](setup-walkthrough.md). Choose the
boundary below before registering a provider or adding a button. Cargo features
make code available; trusted application composition, persisted policy and the
current account still decide which operations are usable.

| Need | Current entry point | Setup and limit |
| --- | --- | --- |
| Same-origin email/password app | Default binary or embedded Axum router | [CLI configuration](server-cli.md); passwords need the explicit local corpus |
| Enterprise OIDC login | Server `oidc-web`, `configured_application` | [OIDC browser guide](oidc-web.md); exact HTTPS callback and explicit client authentication |
| SAML organization login | Server `saml-web`, `configured_application` | [SAML guide](saml.md); already-provisioned matching policy and active approved pins |
| Google web/desktop experiment | Explicit library/example composition | [Google guide](google.md); ordinary server startup does not select Google |
| Explicit identity linking | Experimental combined Google/Apple web composition | [Social linking](social-linking.md); fresh owner proof and retained-method local unlink; protected Apple grant capture/revocation requires separate explicit composition and worker configuration |
| Apple login | Experimental backend `apple` and explicit Axum `apple-web` | [Apple guide](apple-setup.md); ordinary activation, OS delivery and registered-provider acceptance remain gated |
| Passkeys and recovery | Explicit experimental constructors | [Passkey guide](passkey-management.md); physical-device and recovery assurance remain separate |
| An independent relying party | Outbound `issuer-web` plus the separate RP client | [Issuer setup](issuer-standalone.md); each RP owns its callback and application session |
| Your own same-origin pages | Existing selected HTTP APIs | [Custom UI guide](custom-ui.md); changing presentation grants no authority |

## Enterprise OIDC

Build the selected server boundary:

```sh
cargo build --locked -p easy-auth-server --bin easy-auth --features oidc-web
```

Follow the complete [startup contract](../architecture/deployment.md#explicit-oidc-browser-startup).
Use stable realm/connection/local-client IDs, the exact provider issuer and an
explicit registered client-authentication method. Register the trusted public
origin plus `/oidc/callback` at the provider. Do not substitute `/google/callback`,
an application callback or a request-supplied origin. Confidential credentials use
the protected file input; missing credentials never select a public fallback.

Discovery and JWKS use the existing public-root, public-address HTTPS transport.
A private-network IdP or private CA is not made supported by setting a URL.
Startup readiness is a database check, not provider availability. An unchanged
OIDC definition preserves its stored revision; a mismatch or operator disable
fails rather than repairing/re-enabling it. JIT defaults to deny. Provider email
does not link an existing local account.

## SAML

Build with `--features saml-web`, then follow the exact
[SAML configuration](../architecture/deployment.md#opt-in-saml-composition).
Keep SP entity ID, IdP entity ID, SSO URL and derived `/saml/acs` distinct. Obtain
certificate material through the operator's trusted process and provision the
matching registration/JIT policy and active leaf pins before startup. An enabled
environment flag cannot create that trust. Check overlap/retirement with the
[provider guide](saml-providers.md).

SAML defaults off and still requires HTTPS, current trust, correlation, replay,
realm and lifecycle checks. [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md)
waives independent review; it does not report a completed review or close the
remaining assurance gaps. Keep outbound OIDC and broader release gates separate.

## Google and native applications

The [registered native example](google.md#registered-native-acceptance-preparation)
separates configuration checks, owned setup and deliberate real-provider sign-in.
Use the registered application type and protected input described there; do not
put provider credentials in arguments, callback URLs or reports. A desktop return
uses an actually owned literal-loopback listener and retains that exact return
through state/S256/code exchange. A registration check alone proves no listener,
identity or session. A shipped desktop credential does not authenticate the app.

Google's [desktop flow](https://developers.google.com/identity/protocols/oauth2/native-app)
uses a system browser and local return. Its
[loopback migration policy](https://developers.google.com/identity/protocols/oauth2/resources/loopback-migration)
keeps that option for Desktop clients; iOS, Android and Chrome app client types
must use their appropriate platform integration. The existing easy-auth desktop
component is not a mobile adapter. Actual OS/provider/fresh-deletion qualification
is separate from owned offline-signature and socket tests.

For your own native application consuming the easy-auth issuer, use the distinct
[native issuer guide](issuer-native.md) and [Rust RP client](oidc-client.md).
An upstream Google identity, a local cookie and an outbound application token
have different owners and cannot substitute for one another.

## Diagnose the selected layer

Use the [fixed CLI diagnostics](server-cli.md#startup-diagnostics) first. Check the
build feature, complete trusted settings, callback registration and current
persisted policy in that order. A visible reference-page button is not a health
or freshness guarantee. Preserve error classes; do not retry an ambiguous code,
passkey or provider completion or choose a weaker method after rejection.

Provider references were checked on 2026-10-25. Documentation research and local
fixtures do not establish real-provider interoperability or production readiness.
