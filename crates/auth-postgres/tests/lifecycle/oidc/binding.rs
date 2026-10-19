use super::setup::Fixture;
use auth_core::{Error, OAuthConnection, OAuthMixupDefense};
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn cached_documents_recheck_live_revision_and_never_create_authentication_state(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    f.documents.jwks().await.unwrap();
    f.documents.jwks().await.unwrap();
    assert_eq!(f.gets(), 2);
    let current = f
        .store
        .configure_oauth_connection(&f.connection)
        .await
        .unwrap();
    assert!(matches!(f.documents.jwks().await, Err(Error::Unauthorized)));
    assert_eq!(
        f.gets(),
        2,
        "stale configuration must not fetch or reuse cached documents"
    );
    f.documents_for(current).jwks().await.unwrap();
    assert_eq!(f.gets(), 4);
    let facts:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oauth_transactions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn separate_realms_do_not_share_cache_or_configuration_disables(pool: PgPool) {
    let first = Fixture::new(pool.clone()).await;
    let second = Fixture::new(pool).await;
    first.documents.jwks().await.unwrap();
    second.documents.jwks().await.unwrap();
    first
        .store
        .disable_oauth_connection(
            first.connection.realm(),
            first.connection.connection(),
            first.connection.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        first.documents.jwks().await,
        Err(Error::Unauthorized)
    ));
    second.documents.jwks().await.unwrap();
    assert_eq!(first.gets(), 2);
    assert_eq!(second.gets(), 2);
    let original = &second.connection;
    let wrong = OAuthConnection::new(
        Uuid::new_v4(),
        original.connection(),
        original.client(),
        original.issuer(),
        original.provider_client(),
        original.redirect(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    assert!(matches!(
        second.documents_for(wrong).discovery().await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(second.gets(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_commits_during_network_wait_and_late_result_is_rejected(pool: PgPool) {
    let f = Fixture::new(pool).await;
    f.http.hold.store(true, Ordering::SeqCst);
    let action = {
        let documents = f.documents.clone();
        tokio::spawn(async move { documents.discovery().await })
    };
    tokio::time::timeout(Duration::from_secs(2), f.http.entered.notified())
        .await
        .expect("test infrastructure: controlled fetch entered");
    tokio::time::timeout(
        Duration::from_secs(2),
        f.store.disable_oauth_connection(
            f.connection.realm(),
            f.connection.connection(),
            f.connection.client(),
        ),
    )
    .await
    .expect("application must not hold configuration DB locks during network I/O")
    .unwrap();
    f.http.release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(2), action)
        .await
        .expect("test infrastructure: released fetch finishes")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure errors must not prove disabled-context rejection"
    );
    assert_eq!(f.gets(), 1);
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn broken_registry_is_unavailable_not_denial_or_a_cached_success(pool: PgPool) {
    let f = Fixture::new(pool).await;
    f.documents.discovery().await.unwrap();
    sqlx::query("DROP TABLE auth_oauth_connections CASCADE")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.gets(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn another_realm_row_with_identical_revision_cannot_authorize_the_original_context(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    f.documents.discovery().await.unwrap();
    let other = Uuid::new_v4();
    f.store.ensure_realm(other).await.unwrap();
    // Privileged storage fixture preserves every other key/metadata field so
    // random IDs/revisions cannot accidentally mask a missing realm predicate.
    // No pending OAuth/user/session rows exist and no public reparent API is added.
    sqlx::query("UPDATE auth_oauth_connections SET realm_id=$1 WHERE realm_id=$2")
        .bind(other)
        .bind(f.connection.realm())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.gets(),
        1,
        "cached metadata must recheck the exact realm despite an identical row elsewhere"
    );
}
