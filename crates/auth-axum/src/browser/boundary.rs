use crate::router::AppState;
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

// Only the exact fixed reference stylesheet may supply inline styles.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; style-src 'sha256-mrh6CimstRLBArnA3GtEFuIhGV93ne7xr/K73HnM/uY='; style-src-attr 'none'";

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
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
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
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    if state.browser.secure {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("UUID is header-safe"),
    );
    tracing::info!(
        request_id,
        status = response.status().as_u16(),
        "http_request_completed"
    );
    response
}

#[cfg(test)]
mod reference_style_tests {
    use super::CONTENT_SECURITY_POLICY;
    use base64::Engine;

    #[test]
    fn inline_style_permission_matches_only_the_fixed_reference_stylesheet() {
        let stylesheet = format!(
            "{}{}{}",
            include_str!("../pages/vendor/basecoat.css"),
            include_str!("../pages/tokens.css"),
            include_str!("../pages/reference.css")
        );
        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            stylesheet.as_bytes(),
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        assert!(CONTENT_SECURITY_POLICY.contains(&format!("style-src 'sha256-{encoded}'")));
        assert!(CONTENT_SECURITY_POLICY.contains("style-src-attr 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("default-src 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("style-src 'self'"));
    }
}
