use super::setup::{Fixture, connection};
use auth_core::{
    Error, OAuthConnection, OAuthMixupDefense, OAuthPurpose, OAuthTransactionRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn configuration_revision_cancels_old_state_and_disable_prevents_start(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let new = connection(
        f.connection.realm(),
        f.connection.connection(),
        f.connection.client(),
    );
    let new = f.store.configure_oauth_connection(&new).await.unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.store
            .consume_oauth(&f.request(&start, OAuthPurpose::SignIn))
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::Unauthorized)
    ));
    let flow = auth_core::OAuthTransactions::new(new.clone(), f.store.clone());
    flow.begin(&f.intent(OAuthPurpose::SignIn)).await.unwrap();
    f.store
        .disable_oauth_connection(new.realm(), new.connection(), new.client())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn dedicated_callback_is_unique_across_realms_and_wrong_iss_still_rejected(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    let duplicate = OAuthConnection::new(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://other-issuer.example",
        "other-client",
        f.connection.redirect(),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    assert!(matches!(
        f.store.configure_oauth_connection(&duplicate).await,
        Err(Error::Unavailable)
    ));
    let own = OAuthConnection::new(
        f.connection.realm(),
        f.connection.connection(),
        f.connection.client(),
        f.connection.issuer(),
        f.connection.provider_client(),
        f.connection.redirect(),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    let own = f.store.configure_oauth_connection(&own).await.unwrap();
    let flow = auth_core::OAuthTransactions::new(own.clone(), f.store.clone());
    let start = flow.begin(&f.intent(OAuthPurpose::SignIn)).await.unwrap();
    assert!(matches!(
        flow.consume(
            &f.intent(OAuthPurpose::SignIn),
            &start.state,
            super::setup::copy_proof(&start.proof),
            auth_core::OAuthCallback {
                redirect: own.redirect(),
                issuer: Some("https://attacker.example")
            }
        )
        .await,
        Err(Error::Unauthorized)
    ));
    flow.consume(
        &f.intent(OAuthPurpose::SignIn),
        &start.state,
        start.proof,
        auth_core::OAuthCallback {
            redirect: own.redirect(),
            issuer: None,
        },
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_configuration_cannot_reenable_or_resurrect_a_pre_disable_exchange(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let start = f.start().await;
    let exchange = f
        .flow
        .consume(
            &f.intent(OAuthPurpose::SignIn),
            &start.state,
            start.proof,
            auth_core::OAuthCallback {
                redirect: f.connection.redirect(),
                issuer: Some(f.connection.issuer()),
            },
        )
        .await
        .unwrap();
    let old = exchange.configuration().revision();
    f.store
        .disable_oauth_connection(
            f.connection.realm(),
            f.connection.connection(),
            f.connection.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.store.enable_oauth_connection(&f.connection).await,
        Err(Error::Unauthorized)
    ));
    let current = f
        .store
        .configure_oauth_connection(&f.connection)
        .await
        .unwrap();
    assert_ne!(
        current.revision(),
        old,
        "reapplying old input must allocate a fresh revision"
    );
    let flow = auth_core::OAuthTransactions::new(current.clone(), f.store.clone());
    assert!(
        matches!(
            flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
            Err(Error::Unauthorized)
        ),
        "reconfiguration must preserve disable"
    );
    f.store.enable_oauth_connection(&current).await.unwrap();
    flow.begin(&f.intent(OAuthPurpose::SignIn)).await.unwrap();
    let persisted: uuid::Uuid = sqlx::query_scalar("SELECT revision FROM auth_oauth_connections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(
        persisted, old,
        "a claimed exchange predating disable stays invalid after re-enable"
    );
    assert!(matches!(
        f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::Unauthorized)
    ));
}
