use super::setup::*;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn additive_link_migration_preserves_real_old_column_jit_local_sessions_and_audit(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 36)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    // The normal first-JIT branch uses only original columns; no linking method
    // is invoked before its migration. Both sessions are genuine committed flows.
    let f = Fixture::with_jit(pool, OidcJitPolicy::Allow).await;
    let (provider, provider_session) = f.login("historical-subject").await.unwrap();
    let (local, local_session) = f.local("owner@example.test").await;
    let before = f.facts().await;
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0037_explicit_oidc_identity_links.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    crate::support::schema::finish_upgrade_after(&f.pool, 37).await;
    assert_eq!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await
            .unwrap(),
        provider
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), local_session.verifier())
            .await
            .unwrap(),
        local
    );
    assert_eq!(f.facts().await, before);
    let linked: bool =
        sqlx::query_scalar("SELECT explicitly_linked FROM auth_oidc_identities WHERE realm_id=$1")
            .bind(f.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!linked);
    f.linked(&local, &local_session, "new-explicit-subject")
        .await;
}

#[sqlx::test(migrations = "./migrations")]
async fn detached_history_cannot_be_unrevoked_and_erasure_removes_new_audit_references(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, provider_session) = f.login("subject").await.unwrap();
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
    let error =
        sqlx::query("UPDATE auth_sessions SET revoked_at=NULL WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm())
            .bind(provider_session.verifier().as_slice())
            .execute(&f.pool)
            .await
            .unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    f.store
        .begin_account_deletion(
            f.realm(),
            current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    f.store
        .finish_account_deletion(
            f.realm(),
            current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    let erased:bool=sqlx::query_scalar("SELECT bool_and(user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL AND oidc_identity_id IS NULL AND subject_erased) FROM auth_audit WHERE realm_id=$1").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(erased);
}

#[sqlx::test(migrations = "./migrations")]
async fn new_link_audit_requires_version_one_and_exact_actor_owner_without_foreign_metadata(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let (_, foreign) = f.local("foreign@example.test").await;
    let foreign_session: Uuid =
        sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm())
            .bind(foreign.verifier().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let error=sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,oidc_identity_id) VALUES($1,$2,'oidc_identity_linked',0,$3)").bind(f.realm()).bind(owner.id).bind(Uuid::new_v4()).execute(&f.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
    let error=sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,actor_session_id,oidc_identity_id) VALUES($1,$2,'oidc_identity_linked',1,$3,$4)").bind(f.realm()).bind(owner.id).bind(foreign_session).bind(Uuid::new_v4()).execute(&f.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23503")
    );
    f.linked(&owner, &current, "subject").await;
}
