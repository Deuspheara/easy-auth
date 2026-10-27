use crate::router::AppState;
use axum::{
    Json,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

pub(crate) async fn boundary(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    serve(
        state,
        request,
        next,
        true,
        json!({"code":"temporarily_unavailable"}),
    )
    .await
}

/// Cross-site POST delivery may render only a non-authoritative handoff page.
/// All authority-changing routes must use the ordinary same-origin boundary.
#[cfg(any(feature = "saml-web", feature = "apple-web"))]
pub(crate) async fn post_delivery_boundary(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    serve(
        state,
        request,
        next,
        false,
        json!({"code":"temporarily_unavailable"}),
    )
    .await
}

/// Independent OAuth client/code/PKCE authentication only. Never attach this
/// Origin exception to a local session-cookie authority route.
#[cfg(feature = "issuer-web")]
pub(crate) async fn client_token_boundary(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = serve(
        state,
        request,
        next,
        false,
        json!({"error":"temporarily_unavailable"}),
    )
    .await;
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

async fn serve(
    state: AppState,
    request: Request,
    next: Next,
    same_origin: bool,
    timeout_body: serde_json::Value,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let mut response = if same_origin
        && request.method() == Method::POST
        && (request.headers().get_all(header::ORIGIN).iter().count() != 1
            || request
                .headers()
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                != Some(state.browser.origin()))
    {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"code":"origin_rejected"})),
        )
            .into_response()
    } else {
        match tokio::time::timeout(Duration::from_secs(15), next.run(request)).await {
            Ok(response) => response,
            Err(_) => (StatusCode::GATEWAY_TIMEOUT, Json(timeout_body)).into_response(),
        }
    };
    super::headers::apply(&mut response, state.browser.secure, &request_id);
    tracing::info!(
        request_id,
        status = response.status().as_u16(),
        "http_request_completed"
    );
    response
}
