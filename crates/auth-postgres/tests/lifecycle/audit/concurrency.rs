use crate::support::{realm, signed_in};
use auth_core::Repository;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn logout_waits_for_user_lock_without_holding_the_session_and_cannot_invert_audit_locks(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let mut owner = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(user.id)
        .execute(&mut *owner)
        .await
        .unwrap();
    let logout_store = store.clone();
    let verifier = current.verifier();
    let logout = tokio::spawn(async move { logout_store.revoke(realm, verifier).await });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT u.id FROM auth_users u%FOR UPDATE OF u%')")
                .fetch_one(&pool).await.unwrap();
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    // The user-lock holder must still be able to mutate its sessions before committing.
    sqlx::query("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *owner)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE auth_sessions SET last_seen_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(realm)
    .bind(user.id)
    .execute(&mut *owner)
    .await
    .unwrap();
    let after_wait: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    owner.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), logout)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    store.revoke(realm, current.verifier()).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='session_revoked'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let recorded:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM occurred_at)*1000000)::bigint FROM auth_audit WHERE kind='session_revoked'")
        .fetch_one(&pool).await.unwrap();
    assert!(
        recorded >= after_wait,
        "event time must reflect recording after the lock wait, not transaction start"
    );
}
