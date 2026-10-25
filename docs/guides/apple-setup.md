# Prepare Sign in with Apple

An **experimental backend Apple component** is implemented behind core/PostgreSQL
`apple` features. It generates client secrets and verifies initiated web/native
code results through existing state, identity and session boundaries. There is no
ordinary Apple router, native OS adapter or `AUTH_APPLE_*` startup contract yet.
Registered Apple web/native acceptance and grant lifecycle remain unverified.
Configuring an account or compiling this feature does not activate Apple login;
do not route Apple results through an unrelated OIDC callback or email login.

## App and website registration

An operator needs access to the appropriate Apple developer team and identifiers.
For a native app, enable Sign in with Apple on its explicit App ID and configure
the matching Xcode capability/provisioning. Apple's
[capability instructions](https://developer.apple.com/help/account/identifiers/enable-app-capabilities/)
describe the account-side change and supported roles. Keep the bundle identifier,
team identifier and App ID association consistent across builds.

For a companion website, Apple's
[web configuration](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/)
requires a Services ID associated with a primary App ID already enabled for Sign
in with Apple. Configure the website domains and exact return URLs on that Services
ID. The Services ID and native bundle identifier serve different client contexts;
do not reuse one blindly as the other's audience. Select actual deployment URLs
only when the future adapter defines its supported callback contract.

Apple's [environment guide](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple)
also describes grouping related apps, email-source registration and account-change
notifications. Private relay email is contact metadata, not permission to merge
local users. Existing easy-auth realm and verified-subject ownership rules remain
mandatory for any future adapter.

## Signing-key custody

Apple's [key instructions](https://developer.apple.com/help/account/capabilities/create-a-sign-in-with-apple-private-key/)
associate a Sign in with Apple private key with the primary app and identify its
key ID. Keep the downloaded private material in an operator-managed secret store;
never commit it, embed it in a browser/mobile bundle, or paste it into a diagnostic.
Plan replacement before revoking an old key. `AppleClientSecretSigner` accepts
operator-supplied PKCS8 P-256 material, exact ten-character team/key identifiers,
the exact registered client ID and explicit UTC whole-second validity bounds.
Trusted composition must load that material through protected input; there is no
Apple startup file loader. It signs only ES256 fixed Apple audience/team/client
claims, with a five-minute lifetime capped by the key window. Select a replacement
by constructing a new signer; an expired or invalid key never selects an old key.
Owned generated-key tests cover signature, window and explicit replacement; actual
Apple-console rotation/revocation is not established by them.

The ES256 client-secret JWT and Apple's RS256 identity token have separate
purposes and verification policies. Both reuse pinned josekit/OpenSSL; do not copy
the outbound issuer's key settings or create cryptographic verification. Native
library copies are not claimed erased; owned raw buffers zeroize and Debug/errors
remain redacted. See [ADR0043](../architecture/adr/0043-apple-code-flow.md).

## Backend web/native integration

Construct `AppleCodeExchange` from the persisted exact `OAuthConnection`, its
authoritative connection/exchange repositories, signer and existing constrained
document/token transports. The source must use `https://appleid.apple.com`, an
exact HTTPS dedicated backend return and matching App/Services ID. Discovery must
retain Apple's exact authorization, token and JWKS endpoints and Post authentication.
The immutable registered kind is `AppleClientType::Web` or
`AppleClientType::Native(AppleNonceEncoding::Plain | AppleNonceEncoding::Sha256Hex)`.
Native redemption omits the web redirect; it never substitutes a desktop loopback
listener or changes client audience based on an incoming token.

Compose matching `OAuthTransactions` and `AppleCodeExchange` with
`AppleAuthorization`. `begin` admits only sign-in and returns private transaction
proof separately from public authorization inputs. Web requests use code-only
form-post with fixed email/name scopes and nonce; native integration must actually
pass the returned state/nonce/client inputs through Authentication Services. Keep
the private original proof in protected transient operation storage. The selected
native nonce convention is exact; there is no raw/hash fallback.

Apple's [metadata](https://appleid.apple.com/.well-known/openid-configuration) and
[token contract](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens)
do not advertise the existing generic S256 exchange contract. This separate Apple
profile sends no invented PKCE parameter and requires the original signed nonce,
one-use state, exact client/issuer/source/return and private browser proof instead.
Generic OIDC/Google still require S256 and their existing issuer policies.

Pass only the bounded actual return form to `AppleAuthorizationResponse::parse`,
then supply the original state/private proof and independently trusted actual
backend return to `finish`. A transport must enforce actual route/method/body and
same-origin final completion; cross-site form-post must not weaken ordinary session
cookies. The component does not implement that HTTP bridge or OS callback delivery.
An unsolicited ID token is rejected as a substitute for backend code exchange.
Bound denial cancels only its operation. Linking and deletion purposes reject.

Success is an opaque `VerifiedOidcIdentity`, not a cookie or local grant. Existing
explicit `OidcIdentityPolicy` mapping and `OidcSignIn` must still enforce current
realm/revision, JIT policy, subject ownership, original deadline and atomic commit.
No email merge or weaker fallback is enabled. Apple's signed boolean/string
email flags are accepted only by this profile; generic OIDC/Google retain boolean
typing. Missing/empty managed-account email creates no contact. Unsigned initial
profile names remain separate presentation, require text rendering, and may be
absent on later consent. Front-channel identity tokens never replace verification.

## Account lifecycle qualification

Apple's [account-deletion and revocation note](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple)
distinguishes deleting application data from revoking provider tokens and reacting
to credential changes. The complete integration needs protected token custody,
revocation/error handling and local-session consequences. easy-auth does not yet
provide this Apple grant lifecycle. A new login, a provider email or a recently
issued token cannot replace the project's genuine authentication/freshness checks.

Before advertising support, record actual registered web/native runs, correct and
wrong audience/nonce/issuer/code controls, account isolation, first/subsequent
consent behavior, key rotation and deletion/revocation outcomes. Keep production
credentials and raw tokens out of evidence. Default CI must remain independent of
external production credentials.

These primary references were checked on 2026-10-25. No Apple account settings,
production credentials, real-provider exchange or device acceptance were created
by this implementation. Owned offline signed responses are component evidence.
See [integration selection](provider-setup.md) for the currently available paths.
