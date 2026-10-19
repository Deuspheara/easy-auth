use auth_core::{Error, Result};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

pub(super) async fn write_gate(
    pool: &PgPool,
    table: &'static str,
    kind: &'static str,
) -> Transaction<'static, Postgres> {
    // Callers use fixed internal fixture identifiers/kinds, never request data.
    assert!(matches!(
        table,
        "auth_audit" | "auth_security_notifications"
    ));
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5401)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION deadline_write_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN PERFORM pg_advisory_xact_lock(5401); END IF; RETURN NEW; END $$; DROP TRIGGER IF EXISTS deadline_write_gate ON {table}; CREATE TRIGGER deadline_write_gate BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION deadline_write_gate();"))
        .execute(pool).await.unwrap();
    gate
}

pub(super) async fn arm_proof(pool: &PgPool, table: &'static str, realm: Uuid) -> String {
    assert!(matches!(
        table,
        "auth_email_challenges"
            | "auth_password_resets"
            | "auth_email_changes"
            | "auth_account_deletions"
    ));
    sqlx::query(&format!(
        "UPDATE {table} SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1"
    ))
    .bind(realm)
    .execute(pool)
    .await
    .unwrap();
    format!("SELECT expires_at<=clock_timestamp() FROM {table} WHERE realm_id=$1")
}

pub(super) async fn arm_freshness(pool: &PgPool, realm: Uuid) -> String {
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1")
        .bind(realm).execute(pool).await.unwrap();
    "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL".into()
}

pub(super) async fn wait_and_expire(pool: &PgPool, pattern: &str, query: &str, realm: Uuid) {
    // SQLx's test pools share a 20-connection parent. The gate and worker
    // already own two; observation must not wait for a third parent permit.
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: connect deadline observer");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(pattern).fetch_one(&observer).await.expect("test infrastructure: query lock observer");
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: action did not reach the expected database lock");
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .bind(realm)
            .fetch_one(&observer)
            .await
            .unwrap(),
        "test infrastructure: observed wait must precede deadline"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(query)
            .bind(realm)
            .fetch_one(&observer)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("test infrastructure: database clock did not cross the armed deadline");
    observer.close().await;
}

pub(super) async fn finished<T>(task: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("test infrastructure: action did not finish after releasing its gate")
        .expect("test infrastructure: action task panicked");
    assert!(
        !matches!(result, Err(Error::Unavailable)),
        "repository returned Unavailable instead of Unauthorized; diagnose database/pool errors separately from deadline policy"
    );
    result
}
