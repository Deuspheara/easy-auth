//! Index-only schema upgrade: preserve existing authority and roll back failed DDL.
use auth_core::{Error, Repository, Secret};
use easy_auth_postgres::Postgres;
use serde_json::Value;
use sqlx::{PgPool, migrate::Migrator};
use std::borrow::Cow;
use uuid::Uuid;

async fn schema38(pool: &PgPool) {
    let migrations = sqlx::migrate!("./migrations")
        .iter()
        .filter(|migration| migration.version <= 38)
        .cloned()
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
    .run(pool)
    .await
    .unwrap();
}

async fn account(store: &Postgres, realm: Uuid, email: &str) -> Secret {
    store.ensure_realm(realm).await.unwrap();
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_email(realm, email, token.verifier(), browser.verifier(), [1; 32])
        .await
        .unwrap();
    let current = Secret::generate().unwrap();
    store
        .finish_email(
            realm,
            token.verifier(),
            browser.verifier(),
            current.verifier(),
        )
        .await
        .unwrap();
    current
}

async fn history(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM _sqlx_migrations m")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn foreign_keys(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_array(conname,pg_get_constraintdef(oid)) ORDER BY conname) FROM pg_constraint WHERE contype='f' AND connamespace='public'::regnamespace")
        .fetch_one(pool).await.unwrap()
}

async fn records(pool: &PgPool) -> Vec<Value> {
    let tables: Vec<String> = sqlx::query_scalar("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'auth_%' ORDER BY tablename")
        .fetch_all(pool).await.unwrap();
    assert_eq!(tables.len(), 47);
    let mut values = Vec::new();
    for table in tables {
        // Identifiers originate only from this disposable database's own catalog.
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"
        );
        values.push(sqlx::query_scalar(&query).fetch_one(pool).await.unwrap());
    }
    values
}

#[sqlx::test(migrations = false)]
async fn retention_indexes_preserve_all_existing_rows_constraints_and_two_realm_sessions(
    pool: PgPool,
) {
    schema38(&pool).await;
    let store = Postgres::new(pool.clone());
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let first = account(&store, a, "owned-index@example.test").await;
    let second = account(&store, b, "owned-index@example.test").await;
    let rows = records(&pool).await;
    let keys = foreign_keys(&pool).await;
    let old_history = history(&pool).await;
    store.migrate().await.unwrap();
    store.verify_schema().await.unwrap();
    assert!(
        rows == records(&pool).await,
        "index upgrade must preserve all stored authority and audit values"
    );
    assert!(
        keys == foreign_keys(&pool).await,
        "index upgrade must preserve every FK definition"
    );
    let new_history: Vec<Value> = history(&pool).await.as_array().unwrap().clone();
    assert_eq!(new_history.len(), 39);
    assert!(
        old_history.as_array().unwrap() == &new_history[..38],
        "immutable historical migration records"
    );
    assert!(store.authenticate(a, first.verifier()).await.is_ok());
    assert!(store.authenticate(b, second.verifier()).await.is_ok());
    assert!(matches!(
        store.authenticate(b, first.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.authenticate(a, second.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = false)]
async fn later_index_conflict_rolls_back_the_whole_new_migration_and_can_be_retried(pool: PgPool) {
    schema38(&pool).await;
    let store = Postgres::new(pool.clone());
    let realm = Uuid::new_v4();
    let current = account(&store, realm, "owned-conflict@example.test").await;
    sqlx::query("CREATE TABLE owned_auth49_retention_probe(id bigint)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE INDEX auth_retention_apple_terminal ON owned_auth49_retention_probe(id)")
        .execute(&pool)
        .await
        .unwrap();
    let rows = records(&pool).await;
    let before = history(&pool).await;
    assert!(matches!(store.migrate().await, Err(Error::Unavailable)));
    assert!(
        before == history(&pool).await,
        "failed DDL must not change applied history"
    );
    assert!(
        rows == records(&pool).await,
        "failed DDL must not change stored authority"
    );
    let earlier: bool =
        sqlx::query_scalar("SELECT to_regclass('public.auth_retention_audit_age') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !earlier,
        "earlier index creation must roll back after later failure"
    );
    let owned: bool = sqlx::query_scalar("SELECT indrelid='owned_auth49_retention_probe'::regclass FROM pg_index WHERE indexrelid='auth_retention_apple_terminal'::regclass")
        .fetch_one(&pool).await.unwrap();
    assert!(owned);
    sqlx::query("DROP INDEX auth_retention_apple_terminal")
        .execute(&pool)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.verify_schema().await.unwrap();
    assert!(
        rows == records(&pool).await,
        "retry must preserve authority"
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_ok());
}
