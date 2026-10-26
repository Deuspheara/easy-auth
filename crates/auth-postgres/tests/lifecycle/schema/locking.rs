use auth_core::Error;
use easy_auth_postgres::Postgres;
use sqlx::{PgPool, migrate::Migrate, postgres::PgPoolOptions};
use std::time::Duration;

const ACTOR: &str = "easy-auth-owned-schema-check";

async fn actor_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            pool.connect_options()
                .as_ref()
                .clone()
                .application_name(ACTOR),
        )
        .await
        .unwrap()
}

async fn waiting_actor(pool: &PgPool) -> i32 {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() \
                 AND application_name=$1 AND wait_event_type='Lock' AND wait_event='advisory'",
            )
            .bind(ACTOR)
            .fetch_optional(pool)
            .await
            .unwrap();
            if let Some(pid) = pid {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("schema actor must actually wait on the migration lock")
}

async fn actor_gone(pool: &PgPool, pid: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid=$1)",
            )
            .bind(pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if !exists {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed schema connection must not remain in the pool or hold a lock")
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_bounds_an_observed_lock_wait_and_releases_its_connection(pool: PgPool) {
    let runtime = actor_pool(&pool).await;
    let store = Postgres::new(runtime.clone());
    let mut owner = pool.acquire().await.unwrap();
    owner.lock().await.unwrap();
    let pending = tokio::spawn(async move { store.verify_schema().await });
    let pid = waiting_actor(&pool).await;
    let result = tokio::time::timeout(Duration::from_secs(7), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(Error::Unavailable)));
    actor_gone(&pool, pid).await;
    owner.unlock().await.unwrap();
    Postgres::new(runtime.clone())
        .verify_schema()
        .await
        .unwrap();
    runtime.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelled_verification_cannot_return_a_waiting_connection_to_the_pool(pool: PgPool) {
    let runtime = actor_pool(&pool).await;
    let store = Postgres::new(runtime.clone());
    let mut owner = pool.acquire().await.unwrap();
    owner.lock().await.unwrap();
    let pending = tokio::spawn(async move { store.verify_schema().await });
    let pid = waiting_actor(&pool).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    actor_gone(&pool, pid).await;
    owner.unlock().await.unwrap();
    Postgres::new(runtime.clone())
        .verify_schema()
        .await
        .unwrap();
    runtime.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_administration_does_not_leave_its_session_lock_in_the_pool(pool: PgPool) {
    let administration = actor_pool(&pool).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&administration)
        .await
        .unwrap();
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=decode('00','hex') WHERE version=1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        Postgres::new(administration.clone()).migrate().await,
        Err(Error::Unavailable)
    ));
    actor_gone(&pool, pid).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=1")
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        Postgres::new(pool.clone()).migrate(),
    )
    .await
    .unwrap()
    .unwrap();
    administration.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelled_administration_does_not_keep_waiting_on_a_migration_lock(pool: PgPool) {
    let administration = actor_pool(&pool).await;
    let store = Postgres::new(administration.clone());
    let mut owner = pool.acquire().await.unwrap();
    owner.lock().await.unwrap();
    let pending = tokio::spawn(async move { store.migrate().await });
    let pid = waiting_actor(&pool).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    actor_gone(&pool, pid).await;
    owner.unlock().await.unwrap();
    Postgres::new(administration.clone())
        .migrate()
        .await
        .unwrap();
    administration.close().await;
}
