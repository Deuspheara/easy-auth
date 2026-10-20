use super::routing::{CALLBACK_PATH, DeletionState};
use axum::{Router, http::header, response::Html, routing::get};

// These GETs serve fixed bytes only. Callback parameters/cookies never enter a
// use case, repository call, response body or diagnostic at this boundary.
pub(super) fn routes() -> Router<DeletionState> {
    Router::new()
        .route(
            "/oidc/account-delete",
            get(|| async { Html(include_str!("pages.html")) }),
        )
        .route(
            CALLBACK_PATH,
            get(|| async { Html(include_str!("pages.html")) }),
        )
        .route(
            "/oidc/account-delete.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("pages.js"),
                )
            }),
        )
}
