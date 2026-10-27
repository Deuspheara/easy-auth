//! Observe actual owned database waits and drained transactions, never blind sleeps.
use sqlx::PgPool;
use std::time::Duration;

pub(super) async fn wait(pool: &PgPool, blocked: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%auth_rate_buckets%')")
                .fetch_one(pool).await.unwrap();
            if found == blocked { return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("expected database wait state was not observed");
}

pub(super) async fn drained(pool: &PgPool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let active: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND xact_start IS NOT NULL")
                .fetch_one(pool).await.unwrap();
            if active == 0 { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("cancelled database transaction did not drain");
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}
