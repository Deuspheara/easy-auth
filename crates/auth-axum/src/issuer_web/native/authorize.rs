use crate::{error::ApiError, issuer_consent::online_authorize};
use axum::{
    extract::RawQuery,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

#[utoipa::path(get,path="/oidc/authorize",operation_id="nativeIssuerAuthorize",responses((status=200,body=String,content_type="text/html"),(status=302),(status=414)))]
pub(super) async fn authorize(RawQuery(query): RawQuery) -> Result<Response, ApiError> {
    if query.as_ref().is_some_and(|q| q.len() > 16 * 1024) {
        return Err(ApiError::Body(StatusCode::URI_TOO_LONG));
    }
    // Fixed local UI selection only, never consent or redirect authority. Keep
    // native mode in its path across query scrubbing/reload. Strict page/core
    // parsing still rejects duplicated/malformed/unconfigured request fields.
    if query.as_ref().is_some_and(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .any(|(k, v)| k == "scope" && v == auth_core::ISSUER_NATIVE_SCOPE)
    }) {
        let location = format!(
            "/oidc/native/authorize?{}",
            query.as_deref().unwrap_or_default()
        );
        let value = location
            .parse::<axum::http::HeaderValue>()
            .map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
        return Ok((StatusCode::FOUND, [(header::LOCATION, value)]).into_response());
    }
    online_authorize(RawQuery(query)).await
}
