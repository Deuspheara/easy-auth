use super::super::{
    error::{TokenHttpError, invalid},
    form,
    types::TokenFormSchema,
};
use axum::http::HeaderMap;
use utoipa::ToSchema;

#[derive(ToSchema)]
#[serde(untagged)]
pub(super) enum NativeTokenForm {
    Code(TokenFormSchema),
    Refresh(RefreshForm),
}
#[derive(ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshForm {
    pub grant_type: String,
    pub refresh_token: String,
    pub client_id: Option<String>,
    pub scope: Option<String>,
}
impl NativeTokenForm {
    pub(super) fn parse(headers: &HeaderMap, body: &[u8]) -> Result<Self, TokenHttpError> {
        let mut fields = form::fields(headers, body)?;
        if fields.keys().any(|k| {
            !matches!(
                k.as_str(),
                "grant_type"
                    | "code"
                    | "redirect_uri"
                    | "code_verifier"
                    | "client_id"
                    | "refresh_token"
                    | "scope"
            )
        }) {
            return Err(invalid());
        }
        match fields
            .get("grant_type")
            .filter(|s| !s.is_empty())
            .ok_or_else(invalid)?
            .as_str()
        {
            "authorization_code" => Ok(Self::Code(TokenFormSchema::from_fields(fields)?)),
            "refresh_token" => {
                if fields.keys().any(|k| {
                    !matches!(
                        k.as_str(),
                        "grant_type" | "refresh_token" | "client_id" | "scope"
                    )
                }) {
                    return Err(invalid());
                }
                let refresh_token = fields
                    .remove("refresh_token")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(invalid)?;
                let scope = fields.remove("scope");
                if scope
                    .as_deref()
                    .is_some_and(|s| s != auth_core::ISSUER_NATIVE_SCOPE)
                {
                    return Err(TokenHttpError::InvalidScope);
                }
                Ok(Self::Refresh(RefreshForm {
                    grant_type: "refresh_token".into(),
                    refresh_token,
                    client_id: fields.remove("client_id"),
                    scope,
                }))
            }
            _ => Err(TokenHttpError::UnsupportedGrant),
        }
    }
}
