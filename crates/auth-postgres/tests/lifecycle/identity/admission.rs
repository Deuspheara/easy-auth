use super::Fixture;
use auth_core::{Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn user_admission_is_bounded_by_user_source_and_realm_without_email_keys(pool: PgPool) {
    let f = Fixture::new(pool.clone(), None).await;
    for _ in 0..10 {
        f.store
            .admit_user_action(f.realm, f.user, [1; 32])
            .await
            .unwrap();
    }
    assert!(matches!(
        f.store.admit_user_action(f.realm, f.user, [2; 32]).await,
        Err(Error::RateLimited)
    ));
    // Distinct users share one source budget. Failed admission rolls back both dimensions.
    for _ in 0..3 {
        let user = Uuid::new_v4();
        for _ in 0..10 {
            f.store
                .admit_user_action(f.realm, user, [1; 32])
                .await
                .unwrap();
        }
    }
    assert!(matches!(
        f.store
            .admit_user_action(f.realm, Uuid::new_v4(), [1; 32])
            .await,
        Err(Error::RateLimited)
    ));
    let other_realm = Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    f.store
        .admit_user_action(other_realm, f.user, [1; 32])
        .await
        .unwrap();
    let email_buckets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_rate_buckets WHERE dimension IN ('email','password_email')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(email_buckets, 0);
}
