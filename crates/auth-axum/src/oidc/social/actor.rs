use crate::{
    browser::read_cookie,
    oidc::cookies::{Cookies, Transaction},
    router::AppState,
};
use auth_core::{Error, OAuthPurpose, Result, Secret};
use axum::{Extension, extract::ConnectInfo, http::HeaderMap};
use std::net::SocketAddr;
use uuid::Uuid;

pub(super) type Source = Option<Extension<ConnectInfo<SocketAddr>>>;

pub(super) async fn current(
    base: &AppState,
    headers: &HeaderMap,
    expected: Option<Uuid>,
) -> Result<(Secret, OAuthPurpose)> {
    let session = read_cookie(headers, base.browser.session_name())?;
    let user = base.auth.authenticate(&session).await?;
    if expected.is_some_and(|id| id != user.id) {
        return Err(Error::Unauthorized);
    }
    let purpose = OAuthPurpose::Link {
        user: user.id,
        session: session.verifier(),
    };
    Ok((session, purpose))
}

// An old callback cannot clear private cookies belonging to a newer operation.
// State matching selects presentation/cancellation only; core validates full proof.
pub(super) fn cancel_transaction(
    cookies: &Cookies,
    headers: &HeaderMap,
    hint: Option<String>,
) -> Result<Transaction> {
    let transaction = cookies.read(headers)?;
    if let Some(hint) = hint
        && Secret::parse(hint)?.verifier() != transaction.state.verifier()
    {
        return Err(Error::Unauthorized);
    }
    Ok(transaction)
}
