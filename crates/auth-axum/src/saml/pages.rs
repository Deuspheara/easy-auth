use axum::{http::header, response::Html};

#[utoipa::path(get,path="/saml/sign-in",responses((status=200,body=String,content_type="text/html")))]
pub(super) async fn sign_in() -> Html<&'static str> {
    Html(include_str!("signin.html"))
}
pub(super) async fn sign_in_script() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("signin.js"),
    )
}
pub(super) async fn delivery_script() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("delivery.js"),
    )
}
