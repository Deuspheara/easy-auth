use super::setup::*;
use axum::http::StatusCode;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

#[sqlx::test]
async fn response_waits_for_final_transaction_commit(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent HTTP commit observer");
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5503)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION hold_http_deletion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5503); RETURN NEW; END $$; CREATE TRIGGER hold_http_deletion BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='account_deleted') EXECUTE FUNCTION hold_http_deletion();").execute(&f.pool).await.unwrap();
    let app = f.app.clone();
    let request = crate::support::post(
        &format!("{ROOT}/finish"),
        &attempt.callback.to_string(),
        Some(&attempt.cookie),
        Some("https://app.example"),
    );
    use tower::ServiceExt;
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO auth_audit%')")
                .fetch_one(&observer).await.expect("test infrastructure: observe HTTP final audit wait");
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: HTTP completion never reached final audit");
    assert!(
        !response.is_finished(),
        "no successful response or clear-cookie headers before commit"
    );
    assert!(
        f.exists().await,
        "uncommitted account erasure is not externally visible"
    );
    gate.commit().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("test infrastructure: HTTP completion failed to resume")
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(cleared(&response) >= 9);
    assert!(!f.exists().await);
    observer.close().await;
}
