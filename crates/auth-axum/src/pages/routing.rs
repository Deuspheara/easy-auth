use crate::router::AppState;
use axum::{Router, http::header, response::Html, routing::get};

pub(crate) fn routes() -> Router<AppState> {
    authentication_pages().merge(account_pages())
}

fn authentication_pages() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Html(include_str!("client.html")) }))
        .route(
            "/client.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("client.js"),
                )
            }),
        )
        .route("/reset", get(|| async { Html(include_str!("reset.html")) }))
        .route(
            "/reset.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("reset.js"),
                )
            }),
        )
}

fn account_pages() -> Router<AppState> {
    Router::new()
        .route(
            "/email-change",
            get(|| async { Html(include_str!("email-change.html")) }),
        )
        .route(
            "/account-delete",
            get(|| async { Html(include_str!("account-delete.html")) }),
        )
        .route(
            "/account-action.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("account-action.js"),
                )
            }),
        )
}
