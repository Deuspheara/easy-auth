use auth_core::*;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn input(realm: Uuid) -> OAuthConnection {
    OAuthConnection::with_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "desktop-client",
        OAuthRedirect::desktop_loopback(
            "127.0.0.1:49153".parse().unwrap(),
            &format!("/owned/{realm}"),
        )
        .unwrap(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap()
    .with_desktop_loopback_returns()
    .unwrap()
}
pub(super) fn flow(
    c: &OAuthConnection,
    store: Arc<easy_auth_postgres::Postgres>,
    port: u16,
) -> OAuthTransactions {
    OAuthTransactions::for_desktop_return(
        c.clone(),
        store,
        OAuthRedirect::desktop_loopback(
            ([127, 0, 0, 1], port).into(),
            url::Url::parse(c.redirect()).unwrap().path(),
        )
        .unwrap(),
    )
    .unwrap()
}
