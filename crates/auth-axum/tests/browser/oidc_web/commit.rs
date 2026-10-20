use super::setup::*;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use tower::ServiceExt;

// Observe the final audit wait through an independent one-connection pool, rather
// than treating a delayed task or an exhausted shared test pool as proof of commit.
#[sqlx::test]
async fn no_session_cookie_or_success_before_the_final_audit_commits(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent final commit observer");
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5603)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION hold_oidc_http_signin() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5603); RETURN NEW; END $$; CREATE TRIGGER hold_oidc_http_signin BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION hold_oidc_http_signin();")
        .execute(&f.pool).await.expect("test infrastructure: final audit gate");
    let app = f.app.clone();
    let request = crate::support::post(
        &format!("{ROOT}/finish"),
        &a.callback.to_string(),
        Some(&a.cookie),
        Some(ORIGIN),
    );
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO auth_audit%')")
                .fetch_one(&observer).await.expect("test infrastructure: observe actual final audit wait");
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: completion did not reach final audit");
    assert!(
        !response.is_finished(),
        "no response or cookie grant before commit"
    );
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0),
        "uncommitted owner/session remain invisible; consumed state stays consumed"
    );
    gate.commit().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("test infrastructure: completion did not resume")
        .unwrap();
    assert_eq!(response.status(), 204);
    let _ = session(&response);
    cleared(&response);
    assert_eq!(f.facts().await, (1, 1, 1, 0));
    observer.close().await;
}
