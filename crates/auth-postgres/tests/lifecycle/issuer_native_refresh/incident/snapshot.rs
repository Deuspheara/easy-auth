//! Physical snapshot copies of this SQLx-owned database only, never a restore tool.
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::future::Future;
use uuid::Uuid;

pub(super) async fn with_snapshot<F, Fut>(pool: PgPool, exercise: F)
where
    F: FnOnce(PgPool, PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let options = (*pool.connect_options()).clone();
    let source = options.get_database().unwrap().to_owned();
    assert!(source.starts_with("_sqlx_test_"));
    assert!(
        source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().database("postgres"))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT current_database()")
            .fetch_one(&admin)
            .await
            .unwrap(),
        "postgres"
    );
    let clone = format!("owned_auth49_snapshot_{}", Uuid::new_v4().simple());
    // Close every shared fixture connection before PostgreSQL takes its physical
    // consistent copy. No server/worker/listener is ever started against the copy.
    pool.close().await;
    sqlx::query(&format!(
        "CREATE DATABASE \"{clone}\" TEMPLATE \"{source}\""
    ))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&format!(
        "REVOKE CONNECT ON DATABASE \"{clone}\" FROM PUBLIC"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let source_pool = PgPoolOptions::new()
        .max_connections(5)
        .after_release(|_, _| Box::pin(async { Ok(false) }))
        .connect_with(options.clone())
        .await
        .unwrap();
    let snapshot_pool = PgPoolOptions::new()
        .max_connections(5)
        .after_release(|_, _| Box::pin(async { Ok(false) }))
        .connect_with(options.database(&clone))
        .await
        .unwrap();
    let (source_close, snapshot_close) = (source_pool.clone(), snapshot_pool.clone());
    // Observe a scenario panic before cleanup; never leak its owned snapshot DB
    // because an assertion failed. Do not terminate unrelated backend sessions.
    let result = tokio::spawn(exercise(source_pool, snapshot_pool)).await;
    source_close.close().await;
    snapshot_close.close().await;
    // Pool shutdown is a client observation; wait for actual server backends
    // before dropping this exact owned database. Never force other connections.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let remaining: i64 =
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
                    .bind(&clone)
                    .fetch_one(&admin)
                    .await
                    .unwrap();
            if remaining == 0 {
                break;
            }
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&admin)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("owned snapshot backends did not close");
    sqlx::query(&format!("DROP DATABASE \"{clone}\""))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[sqlx::test]
async fn assertion_failure_still_removes_its_exact_owned_snapshot(pool: PgPool) {
    let options = (*pool.connect_options()).clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let result = tokio::spawn(with_snapshot(pool, move |_, snapshot| async move {
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&snapshot)
            .await
            .unwrap();
        sender.send(name).unwrap();
        panic!("owned cleanup negative control");
    }))
    .await;
    assert!(result.unwrap_err().is_panic());
    let name = receiver.await.unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.database("postgres"))
        .await
        .unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(name)
            .fetch_one(&admin)
            .await
            .unwrap()
    );
    admin.close().await;
}
