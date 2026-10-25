use super::*;
use auth_core::{Repository, Secret};

#[sqlx::test(migrations = false)]
async fn public_registry_upgrade_preserves_all_existing_account_session_client_and_code_rows(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 29)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let current = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let owner = store.authenticate(realm, current.verifier()).await.unwrap();
    let client = store
        .configure_issuer_client(
            &auth_core::IssuerClientRegistration::public(
                realm,
                Uuid::new_v4(),
                &["https://app.example/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    store.issuer_subject(&client, owner.id).await.unwrap();
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let service =
        auth_core::IssuerAuthorization::new(authority.clone(), std::sync::Arc::new(store.clone()));
    let browser = Secret::generate().unwrap();
    let pkce =
        auth_core::IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
            .unwrap();
    service
        .prepare(
            &current,
            &browser,
            &auth_core::IssuerAuthorizationInput {
                client: client.client(),
                response_type: "code",
                redirect_uri: "https://app.example/cb",
                scope: "openid",
                state: "state",
                nonce: "nonce",
                code_challenge: &pkce.challenge(),
                code_challenge_method: "S256",
            },
        )
        .await
        .unwrap();
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_audit",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_issuer_authorizations",
    ];
    let mut original = Vec::new();
    for table in tables {
        let rows: serde_json::Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM {table} t"
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        original.push(rows);
    }
    sqlx::raw_sql(include_str!(
        "../../../migrations/0030_issuer_public_keys.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for (table, before) in tables.into_iter().zip(original) {
        let after: serde_json::Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM {table} t"
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            before == after,
            "historical {table} rows must remain unchanged"
        );
    }
    store
        .publish_issuer_key(&publication(&pool, &authority).await)
        .await
        .unwrap();
}
