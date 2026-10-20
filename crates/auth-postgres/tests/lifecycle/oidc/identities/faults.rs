use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

async fn write_failure(pool: PgPool, table: &str, condition: &str) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    // Fixed test-only table/condition literals, never production request input.
    sqlx::raw_sql(&format!("CREATE FUNCTION reject_oidc_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned OIDC write failure'; END $$; CREATE TRIGGER reject_oidc_write BEFORE INSERT ON {table} FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION reject_oidc_write();")).execute(&f.pool).await.unwrap();
    let result = f.sign_in.finish(f.mapped("subject", json!({})).await).await;
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "injected storage failure must not become an authentication rejection or success"
    );
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 0),
        "user, identity, session and audit all roll back; consumed OAuth state is not resurrected"
    );
    sqlx::query(&format!("DROP TRIGGER reject_oidc_write ON {table}"))
        .execute(&f.pool)
        .await
        .unwrap();
    f.sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
#[sqlx::test(migrations = "./migrations")]
async fn session_write_failure_rolls_back_provisioning_and_requires_a_new_valid_flow(pool: PgPool) {
    write_failure(pool, "auth_sessions", "NEW.authentication_method='oidc'").await;
}
#[sqlx::test(migrations = "./migrations")]
async fn audit_write_failure_rolls_back_identity_session_and_provisioning(pool: PgPool) {
    write_failure(pool, "auth_audit", "NEW.kind='oidc_authenticated'").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_policy_registry_is_unavailable_and_not_counted_as_jit_denial(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let mapped = f.mapped("subject", json!({})).await;
    sqlx::query("DROP TABLE auth_oidc_identity_policies")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.sign_in.finish(mapped).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}
