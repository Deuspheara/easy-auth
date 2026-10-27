use super::types::NoQuery;
use crate::error::ApiError;
use auth_core::AppleAuthorizationResponse;
use axum::{
    extract::{
        Query,
        rejection::{QueryRejection, StringRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::Html,
};

/// No cookies, storage, cancellation or authority; only a bounded escaped handoff.
#[utoipa::path(post,path="/apple/callback",request_body(content=String,content_type="application/x-www-form-urlencoded"),
    responses((status=200,body=String,content_type="text/html",description="Non-authoritative handoff; no state consumption or local session"),(status=400),(status=401),(status=413),(status=415)))]
pub(super) async fn bridge(
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Result<String, StringRejection>,
) -> Result<Html<String>, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || !headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
    {
        return Err(ApiError::Body(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
    let body = body.map_err(|error| {
        ApiError::Body(if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        })
    })?;
    AppleAuthorizationResponse::parse(&body)?;
    Ok(crate::pages::document(&format!(
        include_str!("delivery.html"),
        attribute(&body)
    )))
}
fn attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
