use super::types::NoQuery;
use crate::error::ApiError;
use axum::{
    extract::{Query, RawQuery, rejection::QueryRejection},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

#[utoipa::path(get,path="/oidc/authorize",responses((status=200,body=String,content_type="text/html"),(status=414)))]
pub(crate) async fn authorize(RawQuery(query): RawQuery) -> Result<Response, ApiError> {
    if query.as_ref().is_some_and(|q| q.len() > 16 * 1024) {
        return Err(ApiError::Body(StatusCode::URI_TOO_LONG));
    }
    // GET neither parses authority nor persists anything. The fixed page scrubs
    // the query and requires explicit protected POST preparation/confirmation.
    Ok(crate::pages::document(include_str!("authorize.html")).into_response())
}
pub(crate) async fn script(
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("authorize.js"),
    )
        .into_response())
}
