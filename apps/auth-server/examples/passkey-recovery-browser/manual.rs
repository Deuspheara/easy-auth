//! Human-operated bootstrap for the owned development fixture only. All
//! registration/assertion work still goes through the real production services.
use axum::{Router, http::header, response::IntoResponse, routing::get};

pub(super) fn routes() -> Router {
    Router::new()
        .route(
            "/fixture/passkey-signup",
            get(|| async {
                resource(
                    include_str!("manual/signup.html"),
                    "text/html; charset=utf-8",
                )
            }),
        )
        .route(
            "/fixture/passkey-signup.js",
            get(|| async {
                resource(
                    include_str!("manual/signup.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
}

fn resource(body: &'static str, content_type: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
        ],
        body,
    )
}
