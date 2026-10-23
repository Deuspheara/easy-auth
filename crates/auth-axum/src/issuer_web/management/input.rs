use super::super::{
    authentication,
    error::{TokenHttpError, invalid},
    form,
};
use auth_core::{IssuerClientAuthentication, IssuerPresentedToken};
use axum::{
    body::Bytes,
    extract::{
        ConnectInfo, RawQuery,
        rejection::{BytesRejection, ExtensionRejection},
    },
    http::{HeaderMap, StatusCode},
};
use std::net::SocketAddr;
use utoipa::ToSchema;

#[derive(ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenStatusInput {
    pub token: String,
    pub client_id: Option<String>,
    pub token_type_hint: Option<String>,
}
impl TokenStatusInput {
    fn parse(headers: &HeaderMap, body: &[u8]) -> Result<Self, TokenHttpError> {
        let mut fields = form::fields(headers, body)?;
        if fields
            .keys()
            .any(|name| !matches!(name.as_str(), "token" | "client_id" | "token_type_hint"))
        {
            return Err(invalid());
        }
        Ok(Self {
            token: fields
                .remove("token")
                .filter(|s| !s.is_empty())
                .ok_or_else(invalid)?,
            client_id: fields.remove("client_id"),
            token_type_hint: fields.remove("token_type_hint"),
        })
    }
}
pub(super) struct StatusRequest {
    pub authentication: IssuerClientAuthentication,
    pub token: IssuerPresentedToken,
    pub source: String,
}
pub(super) fn request(
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<StatusRequest, TokenHttpError> {
    if query.is_some() {
        return Err(invalid());
    }
    let body = body.map_err(|error| {
        TokenHttpError::InvalidRequest(if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        })
    })?;
    let input = TokenStatusInput::parse(&headers, &body)?;
    let authentication = authentication::parse(&headers, input.client_id.as_deref())?;
    // A hint does not select a namespace or authorize a token operation. This
    // access-only increment always looks up the actual presented credential.
    let _hint = input.token_type_hint;
    let token = IssuerPresentedToken::parse(input.token).map_err(|_| invalid())?;
    let ConnectInfo(peer) =
        peer.map_err(|_| TokenHttpError::Core(auth_core::IssuerTokenError::Unavailable))?;
    Ok(StatusRequest {
        authentication,
        token,
        source: peer.ip().to_string(),
    })
}
