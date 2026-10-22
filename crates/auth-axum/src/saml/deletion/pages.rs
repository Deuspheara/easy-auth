use axum::{
    http::header,
    response::{Html, IntoResponse},
};

#[utoipa::path(get,path="/saml/account-delete",responses((status=200,body=String,content_type="text/html")))]
pub(in crate::saml) async fn page() -> Html<&'static str> {
    Html(include_str!("page.html"))
}
pub(super) async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("page.js"),
    )
}
