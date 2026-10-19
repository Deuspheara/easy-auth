//! Concrete wire schemas; runtime options and assertions remain the library types.
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(in crate::passkeys) struct WebAuthnRequestOptions {
    public_key: AuthenticationOptions,
    /// Only conditional autofill supplies this hint. Omitted for modal/account-bound UI.
    mediation: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AuthenticationOptions {
    challenge: String,
    rp_id: String,
    timeout: Option<u32>,
    allow_credentials: Vec<AuthenticationDescriptor>,
    /// Always required. Client-provided changes cannot weaken server verification.
    user_verification: String,
    #[schema(value_type=Object)]
    extensions: Option<serde_json::Value>,
    hints: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
struct AuthenticationDescriptor {
    #[serde(rename = "type")]
    type_: String,
    id: String,
    transports: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(in crate::passkeys) struct WebAuthnAssertionResponse {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    type_: String,
    response: AssertionResponse,
    #[schema(value_type=Object)]
    client_extension_results: Option<serde_json::Value>,
    authenticator_attachment: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AssertionResponse {
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
    /// Base64url owner UUID. Mandatory for discovery; checked against the stored owner.
    user_handle: Option<String>,
}
