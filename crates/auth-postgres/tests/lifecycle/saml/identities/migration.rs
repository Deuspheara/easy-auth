use super::super::signed_idp;
use auth_core::Error;
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn policy_upgrade_preserves_original_registration_pins_and_request_caps(pool: PgPool) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 22)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = signed_idp::fixture(pool).await;
    let start = f.flow.start().await.unwrap();
    let before: (Value,Value,Value) = sqlx::query_as("SELECT to_jsonb(r),to_jsonb(p),to_jsonb(t) FROM auth_saml_registrations r JOIN auth_saml_certificates p ON p.realm_id=r.realm_id AND p.connection_id=r.id AND p.client_id=r.client_id JOIN auth_saml_requests t ON t.realm_id=r.realm_id AND t.connection_id=r.id AND t.client_id=r.client_id WHERE r.realm_id=$1")
        .bind(f.registration.realm()).fetch_one(&f.pool).await.unwrap();
    crate::support::schema::finish_upgrade_after(&f.pool, 22).await;
    let after: (Value,Value,Value) = sqlx::query_as("SELECT to_jsonb(r),to_jsonb(p),to_jsonb(t) FROM auth_saml_registrations r JOIN auth_saml_certificates p ON p.realm_id=r.realm_id AND p.connection_id=r.id AND p.client_id=r.client_id JOIN auth_saml_requests t ON t.realm_id=r.realm_id AND t.connection_id=r.id AND t.client_id=r.client_id WHERE r.realm_id=$1")
        .bind(f.registration.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(
        before == after,
        "upgrade retains exact original configuration/proofs/deadlines"
    );
    assert!(matches!(
        f.store.saml_identity_policy(&f.registration).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await
            .is_ok()
    );
    let policies: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_saml_identity_policies")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(policies, 0);
}
