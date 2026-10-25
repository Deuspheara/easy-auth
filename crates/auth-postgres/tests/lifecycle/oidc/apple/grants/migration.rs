use super::*;
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn grant_custody_upgrade_preserves_actual_existing_identity_session_and_source_without_fabricating_tokens(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|migration| migration.version <= 37)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let web = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    let native = Fixture::new(
        pool.clone(),
        AppleClientType::Native(AppleNonceEncoding::Sha256Hex),
        OidcJitPolicy::Allow,
    )
    .await;
    let a = web.prepare("legacy-owned", serde_json::json!({})).await;
    let (owner, current) = web.signin(&a).await.unwrap();
    let a = native.prepare("legacy-owned", serde_json::json!({})).await;
    let (native_owner, native_current) = native.signin(&a).await.unwrap();
    assert_ne!(owner.id, native_owner.id);
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_audit",
        "auth_oidc_identities",
        "auth_oidc_identity_policies",
        "auth_oauth_connections",
        "auth_oauth_transactions",
    ];
    let mut original = Vec::new();
    for table in tables {
        original.push(rows(&pool, table).await);
    }
    sqlx::raw_sql(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0038_apple_grant_custody.sql"
    )))
    .execute(&pool)
    .await
    .unwrap();
    for (table, before) in tables.into_iter().zip(original) {
        // Do not dump stored verifiers/claims if a migration regression occurs.
        assert!(
            rows(&pool, table).await == before,
            "preserve existing {table}"
        );
    }
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_apple_grants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        grants, 0,
        "historical identities gain no invented credentials"
    );
    assert_eq!(
        web.store
            .authenticate(web.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(
        native
            .store
            .authenticate(native.realm(), native_current.verifier())
            .await
            .unwrap(),
        native_owner
    );
    let (captured_owner, _) = sign_in(&web, "legacy-owned").await;
    assert_eq!(captured_owner, owner);
    let stored = envelopes(&web).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].binding().realm(), web.realm());
    assert!(web.vault.rewrap(&stored[0]).await.is_ok());
    assert!(envelopes(&native).await.is_empty());
    assert_eq!(
        native
            .store
            .authenticate(native.realm(), native_current.verifier())
            .await
            .unwrap(),
        native_owner
    );
}

async fn rows(pool: &PgPool, table: &str) -> Vec<Value> {
    // Every name is from the fixed local table list above; no request value.
    sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {table} t ORDER BY to_jsonb(t)::text"
    ))
    .fetch_all(pool)
    .await
    .unwrap()
}
