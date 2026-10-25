use axum::{http::header, response::Html};

#[utoipa::path(get,path="/apple/sign-in",responses((status=200,body=String,content_type="text/html",description="Explicit experimental Apple sign-in; no query proof import")))]
pub(super) async fn sign_in() -> Html<String> {
    crate::pages::document(include_str!("signin.html"))
}
pub(super) async fn script() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("client.js"),
    )
}
