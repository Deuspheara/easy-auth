use super::*;
use auth_core::{IssuerClientAuthentication, Secret};

/// Seed only the original published 0027 columns. Today's adapter cannot be used
/// against historical schema; no migration or protocol proof is rewritten.
async fn old_client(pool: &PgPool, registration: &IssuerClientRegistration, secret: &Secret) {
    sqlx::query("INSERT INTO auth_issuer_sectors(realm_id,host) VALUES ($1,$2)")
        .bind(registration.realm())
        .bind(registration.sector())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_issuer_clients(realm_id,id,revision,sector,redirect_uris,authentication,secret_verifier,enabled) VALUES ($1,$2,$3,$4,$5,'client_secret_basic',$6,false)")
        .bind(registration.realm()).bind(registration.client()).bind(registration.revision())
        .bind(registration.sector()).bind(registration.redirects()).bind(secret.verifier().to_vec())
        .execute(pool).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn profile_upgrade_preserves_disabled_web_trust_credentials_subjects_and_sessions(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 27)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm, owner) = setup(&pool).await;
    let secret = Secret::generate().unwrap();
    let client = IssuerClientRegistration::confidential(
        realm,
        Uuid::new_v4(),
        &["https://app.example/cb?fixed=1"],
        &secret,
    )
    .unwrap();
    old_client(&pool, &client, &secret).await;
    let subject = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO auth_issuer_subjects(realm_id,sector,user_id,subject) VALUES ($1,$2,$3,$4)",
    )
    .bind(realm)
    .bind(client.sector())
    .bind(owner)
    .bind(subject)
    .execute(&pool)
    .await
    .unwrap();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(c) FROM auth_issuer_clients c")
            .fetch_one(&pool)
            .await
            .unwrap();
    let sessions: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s")
            .fetch_one(&pool)
            .await
            .unwrap();
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version > 27)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(c)-'redirect_profile' FROM auth_issuer_clients c")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT redirect_profile FROM auth_issuer_clients")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "web_exact"
    );
    let after_sessions: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sessions, after_sessions);
    let authentication = IssuerClientAuthentication::basic(client.client(), &secret).unwrap();
    assert!(
        store
            .validate_issuer_client_authentication(&client, &authentication)
            .await
            .is_err()
    );
    store.enable_issuer_client(&client).await.unwrap();
    store
        .validate_issuer_client_authentication(&client, &authentication)
        .await
        .unwrap();
    assert_eq!(store.issuer_subject(&client, owner).await.unwrap(), subject);
    assert!(!client.permits_redirect("http://127.0.0.1/cb"));
}
