use super::*;
use auth_core::IssuerAuthorization;
use easy_auth_postgres::Postgres;
use std::sync::Arc;

#[sqlx::test(migrations = false)]
async fn family_migration_preserves_online_credentials_and_approved_native_consent_after_restart(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 34)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let mut f = Fixture::new(pool).await;
    let online_code = f.base.code().await;
    let issued = f
        .base
        .service()
        .exchange(
            &f.base.authentication(),
            &online_code,
            "https://app.example/cb",
            &f.base.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let native_code = f.code().await;
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_issuer_authorizations",
        "auth_issuer_native_consents",
        "auth_issuer_native_refresh_policies",
        "auth_issuer_access_tokens",
        "auth_audit",
    ];
    let mut before = Vec::new();
    for table in tables {
        before.push(rows(&f.base.pool, table, false).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0035_issuer_native_token_families.sql"
    ))
    .execute(&f.base.pool)
    .await
    .unwrap();
    // Apply schema before requests, then discard cached pre-DDL SELECT * results.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(f.base.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    f.base.pool = pool.clone();
    f.base.store = Arc::new(Postgres::new(pool));
    f.base.authorization = IssuerAuthorization::new(f.base.authority.clone(), f.base.store.clone());
    f.consent = IssuerNativeAuthorization::new(f.base.authority.clone(), f.base.store.clone());
    f.issuer = IssuerNativeTokenIssuer::new(&f.base.service(), f.base.store.clone());
    for (table, original) in tables.into_iter().zip(before) {
        assert_eq!(
            original,
            rows(&f.base.pool, table, true).await,
            "preserve {table}"
        );
    }
    assert_eq!(f.facts().await, (0, 0, 1, 0, 1));
    assert!(sqlx::query_scalar::<_, bool>("SELECT NOT native_refresh AND native_family_id IS NULL AND native_generation IS NULL FROM auth_issuer_access_tokens")
        .fetch_one(&f.base.pool).await.unwrap());
    auth_core::IssuerTokenManagement::new(f.base.authority.clone(), f.base.store.clone())
        .revoke_access(
            &f.base.authentication(),
            &issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let native = f.exchange(&native_code).await.unwrap();
    let _next = f
        .refresher()
        .refresh(
            &f.authentication(),
            &native.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 2, 3, 1, 2));
}

async fn rows(pool: &PgPool, table: &str, upgraded: bool) -> serde_json::Value {
    let expression = match (upgraded, table) {
        (true, "auth_issuer_access_tokens") => {
            "to_jsonb(t)-'native_refresh'-'native_family_id'-'native_generation'"
        }
        (true, "auth_audit") => {
            "to_jsonb(t)-'issuer_family_id'-'issuer_generation'-'issuer_credential_kind'"
        }
        _ => "to_jsonb(t)",
    };
    sqlx::query_scalar(&format!("SELECT coalesce(jsonb_agg({expression} ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"))
        .fetch_one(pool).await.unwrap()
}
