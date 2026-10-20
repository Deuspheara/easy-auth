use super::super::setup::{Fixture, TokenHttp};
use crate::*;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn fixture(desktop: bool) -> Fixture {
    let redirect = if desktop {
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/callback").unwrap()
    } else {
        OAuthRedirect::https("https://app.example/callback").unwrap()
    };
    let c = OAuthConnection::with_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://accounts.google.com",
        "registered-client.apps.googleusercontent.com",
        redirect,
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    Fixture::configured(
        OidcSigningAlgorithm::RS256,
        &[],
        c,
        &[
            "https://accounts.google.com",
            "https://oauth2.googleapis.com",
            "https://www.googleapis.com",
        ],
        json!({"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs",
            "authorization_response_iss_parameter_supported":true,"code_challenge_methods_supported":["plain","S256"],
            "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]}),
    )
}
pub(super) fn authentication(post: bool) -> OidcClientAuthentication {
    let secret = OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    if post {
        OidcClientAuthentication::ClientSecretPost(secret)
    } else {
        OidcClientAuthentication::ClientSecretBasic(secret)
    }
}
pub(super) fn client(
    f: &Fixture,
    tokens: Arc<TokenHttp>,
    auth: OidcClientAuthentication,
) -> Result<GoogleCodeExchange> {
    GoogleCodeExchange::new(
        f.store.connection.clone(),
        f.store.clone(),
        f.store.clone(),
        auth,
        f.http.clone(),
        tokens,
    )
}
pub(super) fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap()
}
