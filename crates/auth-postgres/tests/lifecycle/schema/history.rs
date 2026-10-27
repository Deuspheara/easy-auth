use auth_core::Error;
use easy_auth_postgres::Postgres;
use sqlx::PgPool;

async fn history(pool: &PgPool) -> serde_json::Value {
    sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM _sqlx_migrations m")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn refuses_without_repair(pool: &PgPool) {
    let before = history(pool).await;
    assert!(matches!(
        Postgres::new(pool.clone()).verify_schema().await,
        Err(Error::Unavailable)
    ));
    assert!(
        before == history(pool).await,
        "verification must not repair history"
    );
}

#[sqlx::test(migrations = false)]
async fn verification_does_not_bootstrap_an_empty_database(pool: PgPool) {
    let store = Postgres::new(pool.clone());
    assert!(matches!(
        store.verify_schema().await,
        Err(Error::Unavailable)
    ));
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE schemaname='public'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(tables, 0);
    store.migrate().await.unwrap();
    let before = history(&pool).await;
    store.verify_schema().await.unwrap();
    assert!(before == history(&pool).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_requires_the_embedded_checksum_without_mutating_it(pool: PgPool) {
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=decode('00','hex') WHERE version=1")
        .execute(&pool)
        .await
        .unwrap();
    refuses_without_repair(&pool).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=1")
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();
    Postgres::new(pool).verify_schema().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_requires_success_for_every_recorded_migration(pool: PgPool) {
    sqlx::query("UPDATE _sqlx_migrations SET success=false WHERE version=1")
        .execute(&pool)
        .await
        .unwrap();
    refuses_without_repair(&pool).await;
    sqlx::query("UPDATE _sqlx_migrations SET success=true WHERE version=1")
        .execute(&pool)
        .await
        .unwrap();
    Postgres::new(pool).verify_schema().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_rejects_missing_and_future_history_without_guessing_compatibility(
    pool: PgPool,
) {
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET version=$1 WHERE version=$2")
        .bind(version + 1)
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();
    refuses_without_repair(&pool).await;
    sqlx::query("UPDATE _sqlx_migrations SET version=$1 WHERE version=$2")
        .bind(version)
        .bind(version + 1)
        .execute(&pool)
        .await
        .unwrap();
    Postgres::new(pool.clone()).verify_schema().await.unwrap();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=$1")
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();
    refuses_without_repair(&pool).await;
}
