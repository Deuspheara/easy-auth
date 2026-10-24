use serde::Serialize;
use utoipa::openapi::OpenApi;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    passwords: bool,
    passkey_signin: bool,
    passkey_signup: bool,
    passkey_enrollment: bool,
    passkey_management: bool,
    recovery: bool,
    recovery_setup: bool,
    email_attachment: bool,
    oidc: bool,
    google: bool,
    saml: bool,
    oidc_deletion: bool,
    google_deletion: bool,
    saml_deletion: bool,
}

pub(super) fn index(passwords: bool, api: &OpenApi) -> String {
    let has = |path: &str| api.paths.paths.contains_key(path);
    let capabilities = Capabilities {
        passwords,
        passkey_signin: has("/v1/passkeys/authentication/start"),
        passkey_signup: has("/v1/passkeys/signup/start"),
        passkey_enrollment: has("/v1/passkeys/enrollment/start"),
        passkey_management: has("/v1/passkeys"),
        recovery: has("/v1/passkeys/recovery/claims/start"),
        recovery_setup: has("/v1/passkeys/recovery/code/prepare"),
        email_attachment: has("/v1/account/email/attachment/start"),
        oidc: has("/v1/oidc/sign-in/start"),
        google: has("/v1/google/sign-in/start"),
        saml: has("/v1/saml/sign-in/start"),
        oidc_deletion: has("/v1/account/provider-delete/start"),
        google_deletion: has("/v1/account/google-delete/start"),
        saml_deletion: has("/v1/saml/account-delete/start"),
    };
    // Fixed keys and boolean values contain no HTML delimiters or user data.
    // This is presentation metadata; every action still requires its real API.
    include_str!("client.html").replace(
        "__CAPABILITIES__",
        &serde_json::to_string(&capabilities).expect("boolean capabilities serialize"),
    )
}
