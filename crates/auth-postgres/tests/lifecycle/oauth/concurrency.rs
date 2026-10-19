use super::setup::Fixture;
use auth_core::{Error, OAuthPurpose, OAuthTransactionRepository, Secret};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = "./migrations")]
async fn simultaneous_callbacks_have_one_winner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let request = f.request(&start, OAuthPurpose::SignIn);
    let (a, b) = tokio::join!(
        f.store.consume_oauth(&request),
        f.store.consume_oauth(&request)
    );
    assert_eq!(
        [a.is_ok(), b.is_ok()].into_iter().filter(|ok| *ok).count(),
        1
    );
    let loser = if a.is_err() { a } else { b };
    assert!(
        matches!(loser, Err(Error::Unauthorized)),
        "infrastructure failure must not count as replay rejection"
    );
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_and_callback_share_single_use_authority(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let request = f.request(&start, OAuthPurpose::SignIn);
    let (cancel, consume) = tokio::join!(
        f.store.cancel_oauth(&request),
        f.store.consume_oauth(&request)
    );
    assert_ne!(cancel.is_ok(), consume.is_ok());
    assert!(matches!(cancel, Ok(()) | Err(Error::Unauthorized)));
    assert!(matches!(consume, Ok(_) | Err(Error::Unauthorized)));
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_start_never_exceeds_three_browser_pending_rows(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool).await);
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let f = f.clone();
        jobs.push(tokio::spawn(async move {
            f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await
        }));
    }
    let mut winners = 0;
    for job in jobs {
        match job.await.expect("test infrastructure: start task") {
            Ok(_) => winners += 1,
            Err(Error::RateLimited) => (),
            Err(_) => panic!("unexpected infrastructure or application error in pending admission"),
        }
    }
    assert_eq!(winners, 3);
    assert_eq!(f.pending().await, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_lookups_spend_budget_and_database_errors_are_not_auth_rejections(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let mut request = f.request(&start, OAuthPurpose::SignIn);
    request.state = Secret::generate().unwrap().verifier();
    let window: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/600)::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    for _ in 0..20 {
        assert!(matches!(
            f.store.consume_oauth(&request).await,
            Err(Error::Unauthorized)
        ));
    }
    let current: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/600)::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        window, current,
        "test infrastructure: admission window crossed"
    );
    assert!(matches!(
        f.store.consume_oauth(&request).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.pending().await, 1);
    sqlx::query("TRUNCATE auth_oauth_admission")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE auth_oauth_transactions")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.consume_oauth(&request).await,
        Err(Error::Unavailable)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_failure_rolls_back_state_and_valid_retry_succeeds(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let request = f.request(&start, OAuthPurpose::SignIn);
    sqlx::raw_sql("CREATE FUNCTION oauth_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixed injected failure'; END $$; CREATE TRIGGER oauth_delete_failure BEFORE DELETE ON auth_oauth_transactions FOR EACH ROW EXECUTE FUNCTION oauth_delete_failure();")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.consume_oauth(&request).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 1);
    sqlx::query("DROP TRIGGER oauth_delete_failure ON auth_oauth_transactions")
        .execute(&f.pool)
        .await
        .unwrap();
    f.store.consume_oauth(&request).await.unwrap();
    assert_eq!(f.pending().await, 0);
}
