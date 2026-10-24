use super::*;

#[sqlx::test(migrations = false)]
async fn consumer_migration_preserves_existing_online_and_native_credentials_without_enabling_readers(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 35)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool).await;
    let online = f
        .base
        .service()
        .exchange(
            &f.base.authentication(),
            &f.base.code().await,
            "https://app.example/cb",
            &f.base.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let native = issued(&f).await;
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_issuer_clients",
        "auth_issuer_authorizations",
        "auth_issuer_native_consents",
        "auth_issuer_native_families",
        "auth_issuer_native_refresh_tokens",
        "auth_issuer_access_tokens",
        "auth_audit",
    ];
    let mut before = Vec::new();
    for table in tables {
        before.push(rows(&f.base.pool, table).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0036_issuer_native_consumers.sql"
    ))
    .execute(&f.base.pool)
    .await
    .unwrap();
    for (table, previous) in tables.into_iter().zip(before) {
        assert_eq!(
            rows(&f.base.pool, table).await,
            previous,
            "preserve {table}"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_native_consumers")
            .fetch_one(&f.base.pool)
            .await
            .unwrap(),
        0
    );
    let c = Consumer::new(&f).await;
    assert!(
        c.inspect(&f, native.access_token())
            .await
            .unwrap()
            .is_none()
    );
    c.enable(&f).await;
    assert!(
        c.inspect(&f, native.access_token())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        c.inspect(&f, online.access_token())
            .await
            .unwrap()
            .is_none()
    );
    f.refresher()
        .refresh(
            &f.authentication(),
            &native.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
}
async fn rows(pool: &PgPool, table: &str) -> serde_json::Value {
    sqlx::query_scalar(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t")).fetch_one(pool).await.unwrap()
}
