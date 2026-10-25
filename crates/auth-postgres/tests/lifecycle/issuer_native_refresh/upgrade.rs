use super::*;
use auth_core::{IssuerAuthorization, IssuerAuthorizationInput, IssuerPkceVerifier, Secret};
use std::sync::Arc;

#[sqlx::test(migrations = false)]
async fn offline_policy_upgrade_preserves_online_consent_client_subject_and_session_rows(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 32)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let current = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_loopback(
                realm,
                Uuid::new_v4(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let store = Arc::new(store);
    let authorization = IssuerAuthorization::new(authority.clone(), store.clone());
    let browser = Secret::generate().unwrap();
    let pkce = IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    let pending = authorization
        .prepare(
            &current,
            &browser,
            &IssuerAuthorizationInput {
                client: client.client(),
                response_type: "code",
                redirect_uri: "http://127.0.0.1:41002/cb",
                scope: "openid",
                state: "owned-state",
                nonce: "owned-nonce",
                code_challenge: &pkce.challenge(),
                code_challenge_method: "S256",
            },
        )
        .await
        .unwrap();
    authorization
        .approve(
            &current,
            &browser,
            pending.handle(),
            pending.authorization(),
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
        "auth_issuer_access_tokens",
    ];
    let mut original = Vec::new();
    for table in tables {
        original.push(rows(&pool, table).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../migrations/0033_issuer_native_refresh_policy.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for (table, before) in tables.into_iter().zip(original) {
        assert_eq!(rows(&pool, table).await, before, "preserve {table}");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_native_refresh_policies")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    store.check_issuer_client(&client).await.unwrap();
    assert!(
        store
            .load_issuer_native_refresh_policy(&authority, client.client())
            .await
            .is_err()
    );
    let next = store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                realm,
                client.client(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let policy = store
        .configure_issuer_native_refresh_policy(
            &IssuerNativeRefreshPolicy::new(authority, next, 3600, 600).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&policy)
            .await
            .is_err()
    );
}

async fn rows(pool: &PgPool, table: &str) -> serde_json::Value {
    sqlx::query_scalar(&format!(
        "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}
