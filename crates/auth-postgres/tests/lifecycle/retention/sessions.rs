use super::keeping;
use crate::support::{realm, signed_in};
use auth_core::{
    Error, Repository, RetentionCategory, RetentionHorizon, RetentionPolicy, RetentionRepository,
};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn retained_audit_pins_expired_session_until_explicit_audit_horizon(pool: PgPool) {
    let (store, a) = realm(pool.clone()).await;
    let current = signed_in(&store, a, "owned-audit@example.test").await;
    sqlx::query("UPDATE auth_sessions SET expires_at=statement_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(a).execute(&pool).await.unwrap();
    assert!(matches!(
        store.authenticate(a, current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Sessions, keeping())
            .await
            .unwrap()
            .deleted,
        0
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Audit, keeping())
            .await
            .unwrap()
            .deleted,
        0
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND session_id IS NOT NULL",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1);
    sqlx::query("UPDATE auth_audit SET occurred_at=statement_timestamp()-interval '2 days' WHERE realm_id=$1")
        .bind(a).execute(&pool).await.unwrap();
    let policy = RetentionPolicy::new(
        RetentionHorizon::after(Duration::from_secs(86400)).unwrap(),
        RetentionHorizon::keep(),
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Audit, policy)
            .await
            .unwrap()
            .deleted,
        1
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Sessions, policy)
            .await
            .unwrap()
            .deleted,
        1
    );
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1")
        .bind(a)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1, "retention cannot delete an account");
}
