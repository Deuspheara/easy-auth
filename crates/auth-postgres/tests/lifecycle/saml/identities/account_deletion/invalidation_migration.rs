use super::setup::Fixture;
use auth_core::Repository;
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn initiator_index_upgrade_preserves_exact_pending_binding_and_current_authority(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 25)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    let before: (Value, Value, Value, Value) = sqlx::query_as("SELECT to_jsonb(u),to_jsonb(s),to_jsonb(i),to_jsonb(r) FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id JOIN auth_saml_identities i ON i.realm_id=s.realm_id AND i.id=s.saml_identity_id JOIN auth_saml_requests r ON r.realm_id=s.realm_id AND r.session_id=s.id WHERE u.realm_id=$1")
        .bind(f.user.realm_id).fetch_one(&f.source.pool).await.unwrap();
    crate::support::schema::finish_upgrade_after(&f.source.pool, 25).await;
    let after: (Value, Value, Value, Value) = sqlx::query_as("SELECT to_jsonb(u),to_jsonb(s),to_jsonb(i),to_jsonb(r) FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id JOIN auth_saml_identities i ON i.realm_id=s.realm_id AND i.id=s.saml_identity_id JOIN auth_saml_requests r ON r.realm_id=s.realm_id AND r.session_id=s.id WHERE u.realm_id=$1")
        .bind(f.user.realm_id).fetch_one(&f.source.pool).await.unwrap();
    assert_eq!(before, after);
    let definition: String = sqlx::query_scalar("SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='auth_saml_requests_initiator'").fetch_one(&f.source.pool).await.unwrap();
    assert!(definition.contains("(realm_id, user_id, session_id)"));
    assert!(
        !definition.contains(" WHERE "),
        "parent FK queries need the unfiltered index too"
    );
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    f.requests
        .cancel(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
}
