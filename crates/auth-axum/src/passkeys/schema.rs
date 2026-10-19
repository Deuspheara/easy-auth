//! Wire schemas for the pinned library's browser JSON. Runtime serialization and
//! protocol verification still use its actual types, without rewriting options.
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebAuthnCreationOptions {
    public_key: CreationOptions,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct CreationOptions {
    rp: RelyingParty,
    user: CredentialUser,
    /// Cryptographically random base64url-encoded challenge.
    challenge: String,
    pub_key_cred_params: Vec<CredentialAlgorithm>,
    timeout: Option<u32>,
    exclude_credentials: Option<Vec<CredentialDescriptor>>,
    authenticator_selection: Option<AuthenticatorSelection>,
    attestation: Option<String>,
    /// Standard WebAuthn extensions; never accepted as independently trusted identity claims.
    #[schema(value_type=Object)]
    extensions: Option<serde_json::Value>,
    hints: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
struct RelyingParty {
    id: String,
    name: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct CredentialUser {
    /// Base64url-encoded opaque UUID bytes, not an email or caller-selected owner.
    id: String,
    name: String,
    display_name: String,
}

#[derive(Serialize, ToSchema)]
struct CredentialAlgorithm {
    #[serde(rename = "type")]
    type_: String,
    /// COSE algorithm identifier from the high-level verifier's secure algorithm list.
    alg: i64,
}

#[derive(Serialize, ToSchema)]
struct CredentialDescriptor {
    #[serde(rename = "type")]
    type_: String,
    /// Base64url credential ID, used as an exclusion hint only.
    id: String,
    transports: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    authenticator_attachment: Option<String>,
    resident_key: Option<String>,
    require_resident_key: Option<bool>,
    /// Required by this implementation. User presence alone is insufficient.
    user_verification: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebAuthnRegistrationResponse {
    /// Canonical base64url ID matching both rawId and the verified attested credential ID.
    id: String,
    /// Base64url-encoded credential ID bytes.
    raw_id: String,
    #[serde(rename = "type")]
    type_: String,
    response: AttestationResponse,
    #[schema(value_type=Object)]
    client_extension_results: Option<serde_json::Value>,
    authenticator_attachment: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    /// Base64url CBOR attestation object, checked by the high-level verifier.
    attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    /// Base64url exact client-data JSON bytes bound to the challenge, origin and signature.
    client_data_json: String,
    transports: Option<Vec<String>>,
    /// Optional browser convenience fields; identity comes only from verified attestation data.
    authenticator_data: Option<String>,
    public_key: Option<String>,
    public_key_algorithm: Option<i64>,
}
