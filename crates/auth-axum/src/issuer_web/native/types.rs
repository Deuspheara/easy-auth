use super::super::types::TokenResponse;
use serde::Serialize;
use utoipa::ToSchema;

pub(super) use super::input::NativeTokenForm;
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeCodeTokens {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u32,
    pub id_token: String,
    pub refresh_token: String,
    pub refresh_expires_in: u32,
    pub scope: &'static str,
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeRefreshTokens {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u32,
    pub refresh_token: String,
    pub refresh_expires_in: u32,
    pub scope: &'static str,
}
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub(super) enum NativeTokenResponse {
    Online(TokenResponse),
    Native(NativeCodeTokens),
    Refresh(NativeRefreshTokens),
}
