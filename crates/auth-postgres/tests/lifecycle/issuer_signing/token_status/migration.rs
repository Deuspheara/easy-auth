use super::*;

#[sqlx::test(migrations = false)]
async fn revocation_upgrade_preserves_existing_issued_credentials_and_every_prior_row(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 31)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool, false).await;
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_audit",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_issuer_authorizations",
        "auth_issuer_keys",
        "auth_issuer_key_sets",
        "auth_issuer_access_tokens",
    ];
    let mut original = Vec::new();
    for table in tables {
        original.push(rows(&f.f.pool, table, false).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0032_issuer_access_revocation.sql"
    ))
    .execute(&f.f.pool)
    .await
    .unwrap();
    for (table, before) in tables.into_iter().zip(original) {
        assert!(
            before == rows(&f.f.pool, table, table == "auth_issuer_access_tokens").await,
            "historical {table} values must remain unchanged"
        );
    }
    assert!(f.revoked().await.is_none());
    f.service()
        .revoke_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(f.revoked().await.is_some());
}
async fn rows(pool: &PgPool, table: &str, strip_revocation: bool) -> serde_json::Value {
    let expression = if strip_revocation {
        "to_jsonb(t)-'revoked_at_us'"
    } else {
        "to_jsonb(t)"
    };
    sqlx::query_scalar(&format!(
        "SELECT jsonb_agg({expression} ORDER BY to_jsonb(t)::text) FROM {table} t"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}
