use super::types::{NoQuery, SamlPostDelivery};
use crate::error::ApiError;
use auth_core::{SamlPostResponse, Secret};
use axum::{
    extract::{
        Form, Query,
        rejection::{FormRejection, QueryRejection},
    },
    http::StatusCode,
    response::Html,
};

/// Cross-site delivery establishes no authority and reads no cookies or storage.
/// Reflected fields remain untrusted until same-origin finish verifies everything.
#[utoipa::path(post,path="/saml/acs",request_body(content=SamlPostDelivery,content_type="application/x-www-form-urlencoded"),responses((status=200,body=String,content_type="text/html",description="Non-authoritative same-origin handoff page; no session or request consumption"),(status=400),(status=413),(status=415)))]
pub(super) async fn bridge(
    query: Result<Query<NoQuery>, QueryRejection>,
    body: Result<Form<SamlPostDelivery>, FormRejection>,
) -> Result<Html<String>, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Form(input) = body.map_err(form_error)?;
    // Reuse core input bounds; this parse is explicitly not signature validation.
    SamlPostResponse::parse(input.response.clone())?;
    Secret::parse(input.relay.clone())?;
    Ok(crate::pages::document(&format!(
        include_str!("delivery.html"),
        attribute(&input.response),
        attribute(&input.relay)
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
pub(super) fn form_error(error: FormRejection) -> ApiError {
    let status = match error.status() {
        StatusCode::PAYLOAD_TOO_LARGE => StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        _ => StatusCode::BAD_REQUEST,
    };
    ApiError::Body(status)
}
