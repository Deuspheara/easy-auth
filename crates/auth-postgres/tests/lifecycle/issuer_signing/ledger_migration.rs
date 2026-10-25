use super::token_setup::Tokens;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn access_ledger_upgrade_preserves_existing_rows_and_redeems_an_already_approved_code(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 30)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Tokens::new(pool).await;
    let code = f.code().await;
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_audit",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_issuer_authorizations",
        "auth_issuer_key_sets",
        "auth_issuer_keys",
    ];
    let mut original = Vec::new();
    for table in tables {
        original.push(rows(&f.pool, table).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../migrations/0031_issuer_access_tokens.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    for (table, before) in tables.into_iter().zip(original) {
        assert!(
            before == rows(&f.pool, table).await,
            "upgrade must preserve all {table} rows"
        );
    }
    f.service()
        .exchange(
            &f.authentication(),
            &code,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1));
}

async fn rows(pool: &PgPool, table: &str) -> serde_json::Value {
    sqlx::query_scalar(&format!(
        "SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM {table} t"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}
