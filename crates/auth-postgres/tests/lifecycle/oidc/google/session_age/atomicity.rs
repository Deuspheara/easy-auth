use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn google_session_age_two_genuine_purpose_proofs_delete_once_without_duplicate_fact(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (user, current) = account(&f, "owned").await;
    let first = proof(
        &f,
        &user,
        &current,
        "owned",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    let second = proof(
        &f,
        &user,
        &current,
        "owned",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    let (left, right) = tokio::join!(remove(&f, first), remove(&f, second));
    assert!(matches!(
        (left, right),
        (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    let deletions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='account_deleted'",
    )
    .bind(f.realm())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(deletions, 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 3);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 3);
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn google_session_age_deletion_audit_failure_restores_all_account_state_but_not_consumed_proof(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (user, current) = account(&f, "owned").await;
    let identity = proof(
        &f,
        &user,
        &current,
        "owned",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    let before = snapshot(&f).await;
    sqlx::raw_sql("CREATE FUNCTION owned_google_delete_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Google deletion audit fault'; END $$; CREATE TRIGGER owned_google_delete_fault BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION owned_google_delete_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install actual deletion audit fault");
    assert!(matches!(
        remove(&f, identity).await,
        Err(Error::Unavailable)
    ));
    assert!(
        snapshot(&f).await == before,
        "account/session/identity/audit/notice/cooldown state must privately match after rollback"
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    sqlx::raw_sql("DROP TRIGGER owned_google_delete_fault ON auth_audit; DROP FUNCTION owned_google_delete_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove actual deletion audit fault");
    let identity = proof(
        &f,
        &user,
        &current,
        "owned",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    remove(&f, identity).await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 3);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 3);
}
