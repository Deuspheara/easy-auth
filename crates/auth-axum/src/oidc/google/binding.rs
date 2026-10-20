use super::routing::WebState;
use crate::{
    browser::read_cookie,
    oidc::cookies::{Cookies, Transaction},
};
use auth_core::{
    Error, GoogleAuthorizationCompletion, GoogleAuthorizationResponse, OAuthPurpose, Result,
    VerifiedOidcIdentity,
};
use axum::{Extension, extract::ConnectInfo, http::HeaderMap};
use std::net::SocketAddr;

pub(super) type Source = Option<Extension<ConnectInfo<SocketAddr>>>;

// Reject stale/malformed callbacks before clearing a newer operation's cookies.
// These comparisons confer no authority; core/PG still check the full binding.
pub(super) fn callback(
    query: &str,
    cookies: &Cookies,
    headers: &HeaderMap,
) -> Result<(Transaction, GoogleAuthorizationResponse)> {
    let transaction = cookies.read(headers)?;
    let response = GoogleAuthorizationResponse::parse(query)?;
    if response.state().verifier() != transaction.state.verifier() {
        return Err(Error::Unauthorized);
    }
    Ok((transaction, response))
}
pub(super) async fn deletion_purpose(
    state: &WebState,
    headers: &HeaderMap,
) -> Result<OAuthPurpose> {
    let session = read_cookie(headers, state.base.browser.session_name())?;
    let user = state.base.auth.authenticate(&session).await?;
    Ok(OAuthPurpose::DeleteProviderAccount {
        user: user.id,
        session: session.verifier(),
    })
}
pub(super) fn verified(completion: GoogleAuthorizationCompletion) -> Result<VerifiedOidcIdentity> {
    match completion {
        GoogleAuthorizationCompletion::Verified(identity) => Ok(*identity),
        GoogleAuthorizationCompletion::Denied => Err(Error::Unauthorized),
        GoogleAuthorizationCompletion::ProviderFailure => Err(Error::Unavailable),
    }
}
