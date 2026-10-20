use super::routing::WebState;
use axum::{Router, http::header, response::Html, routing::get};

#[utoipa::path(get,path="/google/sign-in",responses((status=200,body=String,content_type="text/html",description="Fixed explicit Google sign-in page; no URL proof import outside callback")))]
pub(super) async fn sign_in_page() -> Html<&'static str> {
    Html(include_str!("signin.html"))
}
#[utoipa::path(get,path="/google/account-delete",responses((status=200,body=String,content_type="text/html",description="Fixed deliberate deletion page; signed authentication freshness is required and is never inferred from a prompt")))]
pub(super) async fn deletion_page() -> Html<&'static str> {
    Html(include_str!("deletion.html"))
}

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/google/sign-in", get(sign_in_page))
        .route("/google/account-delete", get(deletion_page))
        .route(
            "/google/client.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("client.js"),
                )
            }),
        )
        .route(
            "/google/callback-error.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("error.js"),
                )
            }),
        )
}
