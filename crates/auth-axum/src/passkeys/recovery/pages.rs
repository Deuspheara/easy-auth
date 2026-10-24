use super::routing::RecoveryState;
use axum::{Router, http::header, routing::get};

pub(super) fn routes() -> Router<RecoveryState> {
    Router::new()
        .route(
            "/passkey-recovery",
            get(|| async {
                crate::pages::document(include_str!("../../pages/recovery/recover.html"))
            }),
        )
        .route(
            "/passkey-recovery/setup",
            get(|| async {
                crate::pages::document(include_str!("../../pages/recovery/setup.html"))
            }),
        )
        .route(
            "/passkey-recovery/shared.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../pages/browser-operations.js"),
                )
            }),
        )
        .route(
            "/passkey-recovery/recover.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../pages/recovery/recover.js"),
                )
            }),
        )
        .route(
            "/passkey-recovery/setup.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../pages/recovery/setup.js"),
                )
            }),
        )
}
