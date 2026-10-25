use super::pages;
use crate::oidc::cookies::{GOOGLE_DELETION_COOKIES, GOOGLE_SIGN_IN_COOKIES};
use auth_core::GoogleAuthorizationResponse;
use axum::{extract::RawQuery, http::HeaderMap, response::Html};

// State selects fixed UI only. No GET performs provider I/O, consumption or grant.
#[utoipa::path(get,path="/google/callback",
    params(("state"=String,Query),("iss"=String,Query),("code"=Option<String>,Query),("error"=Option<String>,Query),("error_description"=Option<String>,Query),("error_uri"=Option<String>,Query),("scope"=Option<String>,Query),("authuser"=Option<String>,Query),("hd"=Option<String>,Query),("prompt"=Option<String>,Query),("session_state"=Option<String>,Query)),
    responses((status=200,body=String,content_type="text/html",description="Fixed bridge; unique original state cookie selects sign-in/deletion UI, including provider errors. No grant or mutation. Raw callback member set is deliberately closed.")))]
pub(super) async fn bridge(
    #[cfg(feature = "social-linking-web")] selected: Option<
        axum::Extension<crate::oidc::social::SocialLinkingSelected>,
    >,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Html<String> {
    #[cfg(feature = "social-linking-web")]
    let selected = selected.is_some();
    #[cfg(not(feature = "social-linking-web"))]
    let selected = false;
    match select(query.as_deref(), &headers, selected) {
        Some(Bridge::SignIn) => pages::sign_in_page().await,
        Some(Bridge::Deletion) => pages::deletion_page().await,
        #[cfg(feature = "social-linking-web")]
        Some(Bridge::Link) => crate::oidc::social::google_return().await,
        None => crate::pages::document(include_str!("error.html")),
    }
}
enum Bridge {
    SignIn,
    Deletion,
    #[cfg(feature = "social-linking-web")]
    Link,
}
fn select(query: Option<&str>, headers: &HeaderMap, _selected: bool) -> Option<Bridge> {
    let returned = GoogleAuthorizationResponse::parse(query?).ok()?;
    let matches = |cookies: &crate::oidc::cookies::Cookies| {
        cookies
            .state_hint(headers)
            .map(|hint| hint.is_some_and(|state| state.verifier() == returned.state().verifier()))
    };
    #[cfg(feature = "social-linking-web")]
    let linking = _selected && matches(&crate::oidc::cookies::GOOGLE_LINK_COOKIES).ok()?;
    #[cfg(not(feature = "social-linking-web"))]
    let linking = false;
    match (
        matches(&GOOGLE_SIGN_IN_COOKIES).ok()?,
        matches(&GOOGLE_DELETION_COOKIES).ok()?,
        linking,
    ) {
        (true, false, false) => Some(Bridge::SignIn),
        (false, true, false) => Some(Bridge::Deletion),
        #[cfg(feature = "social-linking-web")]
        (false, false, true) => Some(Bridge::Link),
        _ => None,
    }
}
