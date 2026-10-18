use crate::support::*;
use auth_core::Repository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn notification_leases_retry_without_cross_realm_or_stale_ack(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, session.verifier(), "old-hash", [1; 32])
        .await
        .unwrap();
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    store
        .finish_password_reset(realm, token.verifier(), browser.verifier(), "new-hash")
        .await
        .unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    assert!(store.claim_security_notice(other).await.unwrap().is_none());
    let (a, b) = tokio::join!(
        store.claim_security_notice(realm),
        store.claim_security_notice(realm)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let first = a.or(b).unwrap();
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    store
        .complete_security_notice(realm, first.id, first.lease, false)
        .await
        .unwrap();
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp()-interval '1 second'").execute(&pool).await.unwrap();
    let second = store.claim_security_notice(realm).await.unwrap().unwrap();
    assert_ne!(first.lease, second.lease);
    store
        .complete_security_notice(realm, first.id, first.lease, true)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    // Simulate worker cancellation: the lease expires and another worker recovers it.
    sqlx::query(
        "UPDATE auth_security_notifications SET lease_until=clock_timestamp()-interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let third = store.claim_security_notice(realm).await.unwrap().unwrap();
    store
        .complete_security_notice(other, third.id, third.lease, true)
        .await
        .unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1, "another realm cannot acknowledge this notice");
    store
        .complete_security_notice(realm, third.id, third.lease, true)
        .await
        .unwrap();
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    store
        .finish_password_reset(realm, token.verifier(), browser.verifier(), "third-hash")
        .await
        .unwrap();
    sqlx::query("UPDATE auth_security_notifications SET attempts=8")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    let failed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications WHERE attempts=8")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        failed, 1,
        "exhausted notices remain visible for operator redrive"
    );
}
