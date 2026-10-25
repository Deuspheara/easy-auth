use axum::{http::header, response::Html};
#[utoipa::path(get,path="/social/accounts",responses((status=200,body=String,content_type="text/html",description="Explicit owner-bound Google/Apple management; no mutation on GET")))]
pub(super) async fn accounts() -> Html<String> {
    crate::pages::document(include_str!("accounts.html"))
}
pub(in crate::oidc) async fn google_return() -> Html<String> {
    crate::pages::document(include_str!("google-return.html"))
}
pub(super) async fn accounts_script() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("accounts.js"),
    )
}
pub(super) async fn return_script() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("google-return.js"),
    )
}
