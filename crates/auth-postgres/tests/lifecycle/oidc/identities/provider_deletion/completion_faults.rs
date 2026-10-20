use super::completion_setup::{account, fresh, snapshot};
use auth_core::*;
use sqlx::PgPool;

async fn write_failure(pool: PgPool, table: &str, contact: bool) {
    let (f, user, current) = account(pool).await;
    if contact {
        sqlx::query("UPDATE auth_users SET email='notice-control@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
            .bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    }
    let deletion = fresh(&f, &user, &current).await;
    let before = snapshot(&f).await;
    // Table is a fixed feature-test literal, never request input.
    sqlx::raw_sql(&format!("CREATE FUNCTION reject_provider_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned deletion write failure'; END $$; CREATE TRIGGER reject_provider_delete BEFORE INSERT ON {table} FOR EACH ROW WHEN (NEW.kind='account_deleted') EXECUTE FUNCTION reject_provider_delete();"))
        .execute(&f.pool).await.unwrap();
    let result = OidcAccountDeletion::new(f.store.clone())
        .finish(deletion)
        .await;
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "injected storage failure must not become successful deletion or expected Unauthorized"
    );
    assert!(
        snapshot(&f).await == before,
        "all erasure, audit attribution, notice, sessions and cooldown writes must roll back"
    );
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        pending, 0,
        "failed deletion cannot resurrect already consumed OAuth state"
    );
    f.store
        .authenticate(f.realm(), current.verifier())
        .await
        .unwrap();
    sqlx::query(&format!("DROP TRIGGER reject_provider_delete ON {table}"))
        .execute(&f.pool)
        .await
        .unwrap();
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &current).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_audit_failure_restores_account_and_all_attribution_after_destructive_writes(
    pool: PgPool,
) {
    write_failure(pool, "auth_audit", false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_notice_failure_restores_account_audit_sessions_and_cooldown(pool: PgPool) {
    write_failure(pool, "auth_security_notifications", true).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_missing_policy_storage_is_unavailable_and_leaves_account_authority_unchanged(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let deletion = fresh(&f, &user, &current).await;
    sqlx::query("DROP TABLE auth_oidc_identity_policies")
        .execute(&f.pool)
        .await
        .unwrap();
    let before = snapshot(&f).await;
    assert!(matches!(
        f.store.finish_oidc_account_deletion(deletion).await,
        Err(Error::Unavailable)
    ));
    assert!(snapshot(&f).await == before);
}
