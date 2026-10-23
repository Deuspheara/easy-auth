use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}
#[derive(ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenFormSchema {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub client_id: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub(super) struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u32,
    pub id_token: String,
    pub scope: &'static str,
}
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicJwkSchema {
    pub kid: String,
    pub kty: String,
    pub n: String,
    pub e: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub key_ops: Vec<String>,
}
#[derive(Serialize, ToSchema)]
pub(super) struct JwksSchema {
    pub keys: Vec<PublicJwkSchema>,
}
#[derive(Serialize, ToSchema)]
pub(super) struct DiscoverySchema {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub claims_parameter_supported: bool,
}

impl TryFrom<auth_core::IssuerJwksDocument> for JwksSchema {
    type Error = auth_core::Error;
    fn try_from(document: auth_core::IssuerJwksDocument) -> Result<Self, Self::Error> {
        let keys = document
            .keys
            .into_iter()
            .map(|value| serde_json::from_value(value).map_err(|_| auth_core::Error::Unavailable))
            .collect::<Result<_, _>>()?;
        Ok(Self { keys })
    }
}
impl From<auth_core::IssuerDiscoveryDocument> for DiscoverySchema {
    fn from(value: auth_core::IssuerDiscoveryDocument) -> Self {
        Self {
            issuer: value.issuer,
            authorization_endpoint: value.authorization_endpoint,
            token_endpoint: value.token_endpoint,
            jwks_uri: value.jwks_uri,
            response_types_supported: strings(value.response_types_supported),
            response_modes_supported: strings(value.response_modes_supported),
            grant_types_supported: strings(value.grant_types_supported),
            subject_types_supported: strings(value.subject_types_supported),
            id_token_signing_alg_values_supported: strings(
                value.id_token_signing_alg_values_supported,
            ),
            token_endpoint_auth_methods_supported: strings(
                value.token_endpoint_auth_methods_supported,
            ),
            scopes_supported: strings(value.scopes_supported),
            claims_supported: strings(value.claims_supported),
            code_challenge_methods_supported: strings(value.code_challenge_methods_supported),
            authorization_response_iss_parameter_supported: value
                .authorization_response_iss_parameter_supported,
            request_parameter_supported: value.request_parameter_supported,
            request_uri_parameter_supported: value.request_uri_parameter_supported,
            claims_parameter_supported: value.claims_parameter_supported,
        }
    }
}
fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}
