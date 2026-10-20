use super::super::setup::Fixture;
use auth_core::*;
use serde_json::{Value, json};
use sqlx::PgPool;

pub(super) async fn account(pool: PgPool) -> (Fixture, User, Secret) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, session) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    (f, user, session)
}

pub(super) async fn proof(
    f: &Fixture,
    user: &User,
    current: &Secret,
    attributes: Value,
    cap: Option<i32>,
) -> OidcMappedIdentity {
    f.mapped_for(
        "owned",
        attributes,
        OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        },
        cap,
    )
    .await
}

pub(super) async fn fresh(f: &Fixture, user: &User, current: &Secret) -> OidcMappedIdentity {
    proof(
        f,
        user,
        current,
        json!({"auth_time":f.now_seconds().await}),
        None,
    )
    .await
}

/// Compare privately, without formatting row data or token verifiers on failure.
/// Committed independent source/browser admission is deliberately not account state.
pub(super) async fn snapshot(f: &Fixture) -> Value {
    sqlx::query_scalar(r#"
        SELECT jsonb_build_object(
          'users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_users t),
          'identities',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_oidc_identities t),
          'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_sessions t),
          'audit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM auth_audit t),
          'notices',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_security_notifications t),
          'pending',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,state_hash) FROM auth_oauth_transactions t),
          'cooldown',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,subject_hash) FROM auth_oidc_deleted_subjects t))
    "#).fetch_one(&f.pool).await.expect("test infrastructure: private deletion state snapshot")
}

/// Fixed table/event literals in feature tests, not production request input.
pub(super) async fn tail_gate(
    f: &Fixture,
    table: &str,
    kind: &str,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5502)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("CREATE FUNCTION provider_delete_tail_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5502); RETURN NEW; END $$; CREATE TRIGGER provider_delete_tail_gate BEFORE INSERT ON {table} FOR EACH ROW WHEN (NEW.kind='{kind}') EXECUTE FUNCTION provider_delete_tail_gate();"))
        .execute(&f.pool).await.unwrap();
    gate
}

pub(super) async fn remove_tail_gate(f: &Fixture, table: &str) {
    sqlx::raw_sql(&format!("DROP TRIGGER provider_delete_tail_gate ON {table}; DROP FUNCTION provider_delete_tail_gate();"))
        .execute(&f.pool).await.unwrap();
}
