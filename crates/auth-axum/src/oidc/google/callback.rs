use super::pages;
use crate::oidc::cookies::{GOOGLE_DELETION_COOKIES, GOOGLE_SIGN_IN_COOKIES};
use auth_core::GoogleAuthorizationResponse;
use axum::{extract::RawQuery, http::HeaderMap, response::Html};

// State selects fixed UI only. No GET performs provider I/O, consumption or grant.
#[utoipa::path(get,path="/google/callback",
    params(("state"=String,Query),("iss"=String,Query),("code"=Option<String>,Query),("error"=Option<String>,Query),("error_description"=Option<String>,Query),("error_uri"=Option<String>,Query),("scope"=Option<String>,Query),("authuser"=Option<String>,Query),("hd"=Option<String>,Query),("prompt"=Option<String>,Query),("session_state"=Option<String>,Query)),
    responses((status=200,body=String,content_type="text/html",description="Fixed bridge; unique original state cookie selects sign-in/deletion UI, including provider errors. No grant or mutation. Raw callback member set is deliberately closed.")))]
pub(super) async fn bridge(RawQuery(query): RawQuery, headers: HeaderMap) -> Html<String> {
    match select(query.as_deref(), &headers) {
        Some(Bridge::SignIn) => pages::sign_in_page().await,
        Some(Bridge::Deletion) => pages::deletion_page().await,
        None => crate::pages::document(include_str!("error.html")),
    }
}
enum Bridge {
    SignIn,
    Deletion,
}
fn select(query: Option<&str>, headers: &HeaderMap) -> Option<Bridge> {
    let returned = GoogleAuthorizationResponse::parse(query?).ok()?;
    let matches = |cookies: &crate::oidc::cookies::Cookies| {
        cookies
            .state_hint(headers)
            .map(|hint| hint.is_some_and(|state| state.verifier() == returned.state().verifier()))
    };
    match (
        matches(&GOOGLE_SIGN_IN_COOKIES).ok()?,
        matches(&GOOGLE_DELETION_COOKIES).ok()?,
    ) {
        (true, false) => Some(Bridge::SignIn),
        (false, true) => Some(Bridge::Deletion),
        _ => None,
    }
}
