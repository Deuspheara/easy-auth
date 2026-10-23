use auth_core::{IssuerAuthorizationInput, IssuerNativeAuthorizationInput};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConsentInput {
    pub client_id: Uuid,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub prompt: String,
}
impl NativeConsentInput {
    pub(super) fn input(&self) -> IssuerNativeAuthorizationInput<'_> {
        IssuerNativeAuthorizationInput {
            authorization: IssuerAuthorizationInput {
                client: self.client_id,
                response_type: &self.response_type,
                redirect_uri: &self.redirect_uri,
                scope: &self.scope,
                state: &self.state,
                nonce: &self.nonce,
                code_challenge: &self.code_challenge,
                code_challenge_method: &self.code_challenge_method,
            },
            prompt: &self.prompt,
        }
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConsentDecision {
    pub authorization: Uuid,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConsentResume {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConsentPreview {
    pub authorization: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub expires_at_us: i64,
    pub grant_expires_at_us: i64,
    pub idle_seconds: u32,
}
impl From<&auth_core::IssuerNativeAuthorizationStart> for NativeConsentPreview {
    fn from(start: &auth_core::IssuerNativeAuthorizationStart) -> Self {
        Self {
            authorization: start.authorization(),
            client_id: start.client(),
            redirect_uri: start.redirect_uri().to_owned(),
            expires_at_us: start.expires_at_us(),
            grant_expires_at_us: start.grant_expires_at_us(),
            idle_seconds: start.idle_seconds(),
        }
    }
}
impl From<auth_core::IssuerNativeAuthorizationPreview> for NativeConsentPreview {
    fn from(p: auth_core::IssuerNativeAuthorizationPreview) -> Self {
        Self {
            authorization: p.authorization,
            client_id: p.client,
            redirect_uri: p.redirect_uri,
            expires_at_us: p.expires_at_us,
            grant_expires_at_us: p.grant_expires_at_us,
            idle_seconds: p.idle_seconds,
        }
    }
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConsentReturn {
    pub redirect_uri: String,
}
