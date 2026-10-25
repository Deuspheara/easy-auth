use super::*;
use auth_core::{IssuerClientAuthentication, IssuerClientRegistration};

#[sqlx::test(migrations = false)]
async fn native_consent_upgrade_preserves_online_grants_and_policy_without_creating_offline_consent(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 33)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let mut f = Fixture::new(pool).await;
    let client = f
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_loopback(
                f.policy.authority().realm(),
                Uuid::new_v4(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = f
        .online()
        .prepare(
            &f.current,
            &f.browser,
            &IssuerAuthorizationInput {
                client: client.client(),
                response_type: "code",
                redirect_uri: "http://127.0.0.1:41002/cb",
                scope: "openid",
                state: "owned-state",
                nonce: "owned-nonce",
                code_challenge: &f.pkce.challenge(),
                code_challenge_method: "S256",
            },
        )
        .await
        .unwrap();
    let returned = f
        .online()
        .approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let code = url::Url::parse(returned.url())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let tables = [
        "auth_users",
        "auth_sessions",
        "auth_audit",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_issuer_native_refresh_policies",
        "auth_issuer_authorizations",
        "auth_issuer_access_tokens",
    ];
    let mut before = Vec::new();
    for table in tables {
        before.push(rows(&f.pool, table, false).await);
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0034_issuer_native_consent.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    // Deployment applies schema before serving requests on fresh connections.
    // Reconnect after DDL so pre-upgrade SELECT * prepared results are not reused.
    let restarted = sqlx::postgres::PgPoolOptions::new()
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    f.pool = restarted.clone();
    f.store = Arc::new(Postgres::new(restarted));
    f.service = Arc::new(IssuerNativeAuthorization::new(
        f.policy.authority().clone(),
        f.store.clone(),
    ));
    for (table, original) in tables.into_iter().zip(before) {
        assert_eq!(
            original,
            rows(&f.pool, table, table == "auth_issuer_authorizations").await,
            "preserve {table}"
        );
    }
    assert_eq!(f.facts().await, (1, 0, 1, 0, 1));
    f.online()
        .redeem(
            &IssuerClientAuthentication::public(client.client()).unwrap(),
            &Secret::parse(code).unwrap(),
            pending.redirect_uri(),
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let native = f.prepare().await;
    let result = f
        .service
        .approve(
            &f.current,
            &f.browser,
            native.handle(),
            native.authorization(),
        )
        .await;
    assert!(
        result.is_ok(),
        "native approval error {:?}; aggregate facts {:?}",
        result.err(),
        f.facts().await
    );
    // The two native client IDs own distinct pairwise sectors for this owner.
    assert_eq!(f.facts().await, (2, 1, 2, 0, 2));
}
async fn rows(pool: &PgPool, table: &str, strip: bool) -> serde_json::Value {
    let expr = if strip {
        "to_jsonb(t)-'native_refresh'"
    } else {
        "to_jsonb(t)"
    };
    sqlx::query_scalar(&format!(
        "SELECT coalesce(jsonb_agg({expr} ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}
