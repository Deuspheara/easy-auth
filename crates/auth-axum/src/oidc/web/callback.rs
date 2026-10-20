use super::pages;
use crate::oidc::{
    cookies::{ACCOUNT_DELETION_COOKIES, SIGN_IN_COOKIES},
    deletion,
};
use auth_core::Secret;
use axum::{extract::RawQuery, http::HeaderMap, response::Html};
use std::collections::HashSet;

const MAX_CALLBACK_BYTES: usize = 8192;
const MAX_VALUE_BYTES: usize = 2048;

// Matching state selects fixed UI only. POST/core/storage still own all proof,
// purpose, source, issuer, original deadline and current authority checks.
#[utoipa::path(get, path = "/oidc/callback",
    params(("state"=String,Query),("code"=String,Query),("iss"=Option<String>,Query),("session_state"=Option<String>,Query)),
    responses((status=200,body=String,content_type="text/html",description="Fixed bridge selected only by unique state cookie match; no consumption, session or deletion. Invalid/provider-error queries receive fixed failure content.")))]
pub(super) async fn bridge(RawQuery(query): RawQuery, headers: HeaderMap) -> Html<&'static str> {
    match select(query.as_deref(), &headers) {
        Some(Bridge::SignIn) => pages::sign_in_page().await,
        Some(Bridge::Deletion) => deletion::callback_page().await,
        None => Html(include_str!("error.html")),
    }
}
enum Bridge {
    SignIn,
    Deletion,
}
fn select(query: Option<&str>, headers: &HeaderMap) -> Option<Bridge> {
    let returned = callback_state(query?)?;
    let sign_in = SIGN_IN_COOKIES.state_hint(headers).ok()?;
    let deletion = ACCOUNT_DELETION_COOKIES.state_hint(headers).ok()?;
    let matches =
        |hint: Option<Secret>| hint.is_some_and(|state| state.verifier() == returned.verifier());
    match (matches(sign_in), matches(deletion)) {
        (true, false) => Some(Bridge::SignIn),
        (false, true) => Some(Bridge::Deletion),
        _ => None,
    }
}
fn callback_state(query: &str) -> Option<Secret> {
    if query.len() > MAX_CALLBACK_BYTES || !valid_encoding(query) {
        return None;
    }
    let mut names = HashSet::new();
    let mut state = None;
    let mut code = false;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !matches!(name.as_ref(), "state" | "code" | "iss" | "session_state")
            || !names.insert(name.to_string())
            || value.len() > MAX_VALUE_BYTES
            || value.contains('\u{fffd}')
            || value.chars().any(char::is_control)
        {
            return None;
        }
        match name.as_ref() {
            "state" => state = Some(Secret::parse(value.into_owned()).ok()?),
            "code" => code = !value.is_empty() && value.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            _ => {}
        }
    }
    if code { state } else { None }
}
fn valid_encoding(query: &str) -> bool {
    let bytes = query.as_bytes();
    bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'%'
            || bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
    })
}
