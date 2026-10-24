use super::routing::WebState;
use axum::{Router, http::header, response::Html, routing::get};

#[utoipa::path(get, path = "/oidc/sign-in", responses((status=200,body=String,content_type="text/html",description="Fixed sign-in page; no URL proof import or automatic sign-in")))]
pub(super) async fn sign_in_page() -> Html<String> {
    crate::pages::document(include_str!("signin.html"))
}
pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/oidc/sign-in", get(sign_in_page))
        .route(
            "/oidc/sign-in.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("signin.js"),
                )
            }),
        )
        .route(
            "/oidc/callback-error.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("error.js"),
                )
            }),
        )
}
