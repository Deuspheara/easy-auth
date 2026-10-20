use crate::support::realm;
use auth_core::*;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn native_redirect_persistence_keeps_exact_port_and_one_use_context(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let store = Arc::new(store);
    let input = OAuthConnection::with_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "registered-desktop-client",
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/callback").unwrap(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let c = store.configure_oauth_connection(&input).await.unwrap();
    assert_ne!(c.revision(), input.revision());
    assert_eq!(c.redirect(), input.redirect());
    let flow = OAuthTransactions::new(c.clone(), store.clone());
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-native",
        purpose: OAuthPurpose::SignIn,
    };
    let start = flow.begin(&intent).await.unwrap();
    for redirect in [
        "http://127.0.0.1:49154/callback",
        "http://[::1]:49153/callback",
        "https://127.0.0.1:49153/callback",
    ] {
        assert!(matches!(
            flow.consume(
                &intent,
                &start.state,
                super::setup::copy_proof(&start.proof),
                OAuthCallback {
                    redirect,
                    issuer: Some(c.issuer())
                }
            )
            .await,
            Err(Error::Unauthorized)
        ));
    }
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining, 1,
        "bad redirect must not consume the valid bound operation"
    );
    let (first, second) = tokio::join!(
        flow.consume(
            &intent,
            &start.state,
            super::setup::copy_proof(&start.proof),
            OAuthCallback {
                redirect: c.redirect(),
                issuer: Some(c.issuer())
            }
        ),
        flow.consume(
            &intent,
            &start.state,
            super::setup::copy_proof(&start.proof),
            OAuthCallback {
                redirect: c.redirect(),
                issuer: Some(c.issuer())
            }
        )
    );
    match (first, second) {
        (Ok(exchange), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(exchange)) => {
            assert_eq!(exchange.configuration(), &c)
        }
        _ => panic!(
            "one native callback must win; infrastructure errors cannot stand in for replay rejection"
        ),
    }
    let reconfigured = store.configure_oauth_connection(&c).await.unwrap();
    assert_ne!(reconfigured.revision(), c.revision());
    assert_eq!(reconfigured.redirect(), c.redirect());
    assert!(matches!(
        flow.begin(&intent).await,
        Err(Error::Unauthorized)
    ));
    store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    let disabled = store.configure_oauth_connection(&input).await.unwrap();
    let flow = OAuthTransactions::new(disabled.clone(), store.clone());
    assert!(
        matches!(flow.begin(&intent).await, Err(Error::Unauthorized)),
        "reconfiguration must retain disable"
    );
    store.enable_oauth_connection(&disabled).await.unwrap();
    let start = flow.begin(&intent).await.unwrap();
    flow.cancel(&intent, &start.state, &start.proof)
        .await
        .unwrap();
}
