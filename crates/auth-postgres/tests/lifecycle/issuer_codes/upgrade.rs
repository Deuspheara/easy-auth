use super::*;

#[sqlx::test(migrations = false)]
async fn code_schema_upgrade_preserves_legacy_account_session_client_subject_and_audit(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 28)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let historical =
        crate::support::legacy_attribution::seed_session(&pool, realm, "legacy@example.test").await;
    sqlx::query(
        "UPDATE auth_sessions SET authentication_method='legacy_unknown' WHERE realm_id=$1",
    )
    .bind(realm)
    .execute(&pool)
    .await
    .unwrap();
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::public(realm, Uuid::new_v4(), &["https://app.example/cb"])
                .unwrap(),
        )
        .await
        .unwrap();
    store
        .issuer_subject(&client, historical.user_id)
        .await
        .unwrap();
    let mut original = Vec::new();
    for table in [
        "auth_users",
        "auth_sessions",
        "auth_issuer_clients",
        "auth_issuer_subjects",
        "auth_audit",
    ] {
        let data: serde_json::Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM {table} t"
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        original.push((table, data));
    }
    sqlx::raw_sql(include_str!(
        "../../../migrations/0029_issuer_authorization_codes.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for (table, before) in original {
        let projection = if table == "auth_audit" {
            "to_jsonb(t)-'issuer_client_id'-'issuer_authorization_id'"
        } else {
            "to_jsonb(t)"
        };
        let after: serde_json::Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg({projection} ORDER BY to_jsonb(t)::text) FROM {table} t"
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            before == after,
            "historical {table} facts must remain unchanged"
        );
    }
    let loaded = store
        .load_issuer_client(realm, client.client())
        .await
        .unwrap();
    assert_eq!(loaded.revision(), client.revision());
    // Old legacy_unknown sessions are deliberately not fresh consent authority.
    let service = IssuerAuthorization::new(
        IssuerAuthority::new(realm, "https://issuer.example").unwrap(),
        Arc::new(store),
    );
    let browser = Secret::generate().unwrap();
    let pkce = IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    assert!(
        service
            .prepare(
                &historical.secret,
                &browser,
                &IssuerAuthorizationInput {
                    client: client.client(),
                    response_type: "code",
                    redirect_uri: "https://app.example/cb",
                    scope: "openid",
                    state: "state",
                    nonce: "nonce",
                    code_challenge: &pkce.challenge(),
                    code_challenge_method: "S256"
                }
            )
            .await
            .is_err()
    );
}
