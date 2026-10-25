use super::{error::TokenHttpError, form};
use auth_core::{IssuerClientAuthentication, Secret};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BASIC_HEADER_BYTES: usize = 1024;
pub(super) fn parse(
    headers: &HeaderMap,
    body_client: Option<&str>,
) -> Result<IssuerClientAuthentication, TokenHttpError> {
    let body_client = body_client.map(identifier).transpose()?;
    let count = headers.get_all(header::AUTHORIZATION).iter().count();
    if count == 0 {
        return IssuerClientAuthentication::public(
            body_client.ok_or(TokenHttpError::InvalidClient)?,
        )
        .map_err(|_| TokenHttpError::InvalidClient);
    }
    if count != 1 {
        return Err(TokenHttpError::InvalidClient);
    }
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(TokenHttpError::InvalidClient)?;
    if header.len() > MAX_BASIC_HEADER_BYTES {
        return Err(TokenHttpError::InvalidClient);
    }
    let (scheme, encoded) = header
        .split_once(' ')
        .ok_or(TokenHttpError::InvalidClient)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(TokenHttpError::InvalidClient);
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| TokenHttpError::InvalidClient)?,
    );
    let decoded = std::str::from_utf8(&decoded).map_err(|_| TokenHttpError::InvalidClient)?;
    let (client, secret) = decoded
        .split_once(':')
        .ok_or(TokenHttpError::InvalidClient)?;
    let client = identifier(&form::component(client).map_err(|_| TokenHttpError::InvalidClient)?)?;
    if body_client.is_some_and(|id| id != client) {
        return Err(TokenHttpError::InvalidClient);
    }
    let secret = form::component(secret).map_err(|_| TokenHttpError::InvalidClient)?;
    let secret = Secret::parse(secret).map_err(|_| TokenHttpError::InvalidClient)?;
    IssuerClientAuthentication::basic(client, &secret).map_err(|_| TokenHttpError::InvalidClient)
}
fn identifier(value: &str) -> Result<Uuid, TokenHttpError> {
    let id = Uuid::parse_str(value).map_err(|_| TokenHttpError::InvalidClient)?;
    if id.is_nil() || id.to_string() != value {
        return Err(TokenHttpError::InvalidClient);
    }
    Ok(id)
}
