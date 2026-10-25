# Prepare Sign in with Apple

Apple authentication is **not implemented** in easy-auth. There is no Apple
router, client-secret loader, native adapter or `AUTH_APPLE_*` startup contract.
This guide identifies provider-side prerequisites for later implementation and
qualification. Configuring a developer account does not enable an easy-auth flow;
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
Plan replacement before revoking an old key. The project has no Apple key-loading
implementation or tested rotation procedure yet.

A future Apple client-secret JWT and Apple's signed identity token have separate
purposes and verification policies. Do not copy the outbound easy-auth issuer's
RS256 configuration or create custom cryptographic verification. The implementation
must select and review an established dependency and preserve state, nonce,
S256 where applicable, exact audience/issuer, one-use code and realm bindings.
These are implementation obligations, not completed support claims.

## Account lifecycle qualification

Apple's [account-deletion and revocation note](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple)
distinguishes deleting application data from revoking provider tokens and reacting
to credential changes. The eventual integration needs protected token custody,
revocation/error handling and local-session consequences. easy-auth does not yet
provide this Apple grant lifecycle. A new login, a provider email or a recently
issued token cannot replace the project's genuine authentication/freshness checks.

Before advertising support, record actual registered web/native runs, correct and
wrong audience/nonce/issuer/code controls, account isolation, first/subsequent
consent behavior, key rotation and deletion/revocation outcomes. Keep production
credentials and raw tokens out of evidence. Default CI must remain independent of
external production credentials.

These primary references were checked on 2026-10-25. No Apple account settings,
credentials, provider exchange or device acceptance were created by this guide.
See [integration selection](provider-setup.md) for the currently available paths.
