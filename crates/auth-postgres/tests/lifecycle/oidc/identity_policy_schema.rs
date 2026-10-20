use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::{
    OAuthCallback, OAuthConnection, OAuthIntent, OAuthPurpose, OAuthTransactions,
    OidcConnectionRepository, OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy, Repository,
    Secret,
};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn policy_migration_preserves_mailbox_sessions_registry_and_pending_oauth_state(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 16)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool).await;
    let realm = f.connection.realm();
    let session = signed_in(&f.store, realm, "policy-upgrade@example.test").await;
    let user = f
        .store
        .authenticate(realm, session.verifier())
        .await
        .unwrap();
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(f.connection.clone(), f.store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "policy-upgrade",
        purpose: OAuthPurpose::SignIn,
    };
    let start = flow.begin(&intent).await.unwrap();
    let before: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)").fetch_one(&f.pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../migrations/0017_oidc_identity_policies.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    let after: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)").fetch_one(&f.pool).await.unwrap();
    assert_eq!(before, after);
    let policies: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_identity_policies")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(policies, 0, "migration grants no implicit JIT policy");
    assert_eq!(
        f.store
            .authenticate(realm, session.verifier())
            .await
            .unwrap(),
        user
    );
    f.store.check_oidc_connection(&f.connection).await.unwrap();
    flow.consume(
        &intent,
        &start.state,
        start.proof,
        OAuthCallback {
            redirect: f.connection.redirect(),
            issuer: Some(f.connection.issuer()),
        },
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn realm_and_local_client_bindings_keep_independent_policies(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = OidcIdentityPolicy::new(
        f.connection.clone(),
        &[f.connection.issuer()],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap();
    let first = f
        .store
        .configure_oidc_identity_policy(&first)
        .await
        .unwrap();
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    let connection = OAuthConnection::new(
        realm,
        f.connection.connection(),
        f.connection.client(),
        f.connection.issuer(),
        f.connection.provider_client(),
        "https://app.example/other-realm",
        f.connection.defense(),
    )
    .unwrap();
    let second = OidcIdentityPolicy::new(
        connection,
        &[f.connection.issuer()],
        OidcDisplayNameClaim::Name,
    )
    .unwrap()
    .with_jit(OidcJitPolicy::Allow);
    let second = f
        .store
        .configure_oidc_identity_policy(&second)
        .await
        .unwrap();
    let connection = OAuthConnection::new(
        f.connection.realm(),
        f.connection.connection(),
        Uuid::new_v4(),
        f.connection.issuer(),
        f.connection.provider_client(),
        "https://app.example/other-client",
        f.connection.defense(),
    )
    .unwrap();
    let third = OidcIdentityPolicy::new(
        connection,
        &[f.connection.issuer()],
        OidcDisplayNameClaim::PreferredUsername,
    )
    .unwrap();
    let third = f
        .store
        .configure_oidc_identity_policy(&third)
        .await
        .unwrap();
    for (policy, jit) in [(&first, "deny"), (&second, "allow"), (&third, "deny")] {
        let c = policy.configuration();
        f.store.check_oidc_connection(c).await.unwrap();
        let row: (Uuid,String) = sqlx::query_as("SELECT revision,jit FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3").bind(c.realm()).bind(c.connection()).bind(c.client()).fetch_one(&f.pool).await.unwrap();
        assert_eq!(row, (c.revision(), jit.into()));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_identity_policies")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn policy_schema_rejects_unknown_modes_invalid_arrays_and_cross_realm_references(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = &f.connection;
    let valid = vec![Some(c.issuer().to_owned())];
    let cases = [
        ("unknown", "deny", valid.clone()),
        ("sub", "unknown", valid.clone()),
        ("sub", "deny", vec![]),
        ("sub", "deny", vec![None]),
        (
            "sub",
            "deny",
            (0..9)
                .map(|i| Some(format!("https://tenant-{i}.example")))
                .collect(),
        ),
        ("sub", "deny", vec![Some("x".repeat(16385))]),
    ];
    for (display, jit, issuers) in cases {
        let error = sqlx::query("INSERT INTO auth_oidc_identity_policies(realm_id,connection_id,client_id,revision,allowed_issuers,display_claim,jit) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.revision()).bind(issuers).bind(display).bind(jit).execute(&f.pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23514"),
            "only an actual check-constraint violation proves the schema rejection"
        );
    }
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    let error = sqlx::query("INSERT INTO auth_oidc_identity_policies(realm_id,connection_id,client_id,revision,allowed_issuers,display_claim) VALUES($1,$2,$3,$4,$5,'sub')")
        .bind(realm).bind(c.connection()).bind(c.client()).bind(c.revision()).bind(&valid).execute(&f.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23503")
    );
    sqlx::query("INSERT INTO auth_oidc_identity_policies(realm_id,connection_id,client_id,revision,allowed_issuers,display_claim) VALUES($1,$2,$3,$4,$5,'sub')")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.revision()).bind(&valid).execute(&f.pool).await.unwrap();
    let jit: String = sqlx::query_scalar("SELECT jit FROM auth_oidc_identity_policies")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(jit, "deny");
}
