use super::setup::Fixture;
use auth_core::Error;
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn refresh_rechecks_disabled_configuration_even_for_a_cached_observation(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let observed = f.documents.jwks().await.unwrap();
    f.store
        .disable_oauth_connection(
            f.connection.realm(),
            f.connection.connection(),
            f.connection.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.documents.refresh_jwks(&observed).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_commits_during_key_refresh_and_late_keys_are_not_returned(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let observed = f.documents.jwks().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    f.http.hold.store(true, Ordering::SeqCst);
    let action = {
        let documents = f.documents.clone();
        tokio::spawn(async move { documents.refresh_jwks(&observed).await })
    };
    tokio::time::timeout(Duration::from_secs(2), f.http.entered.notified())
        .await
        .expect("test infrastructure: held key fetch entered");
    tokio::time::timeout(
        Duration::from_secs(2),
        f.store.disable_oauth_connection(
            f.connection.realm(),
            f.connection.connection(),
            f.connection.client(),
        ),
    )
    .await
    .expect("key refresh must not hold a database lock across network I/O")
    .unwrap();
    f.http.release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(2), action)
        .await
        .expect("test infrastructure: released key fetch finishes")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure failure cannot stand in for disabled-context rejection"
    );
    assert_eq!(f.gets(), 3);
}
