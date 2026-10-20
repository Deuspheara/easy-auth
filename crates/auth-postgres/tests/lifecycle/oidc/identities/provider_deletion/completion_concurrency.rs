use super::super::setup::wait_for_lock;
use super::completion_setup::{account, fresh, remove_tail_gate, tail_gate};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_valid_deletion_proofs_have_one_commit_and_no_duplicate_fact(pool: PgPool) {
    let (f, user, current) = account(pool).await;
    let one = fresh(&f, &user, &current).await;
    let two = fresh(&f, &user, &current).await;
    let use_case = OidcAccountDeletion::new(f.store.clone());
    let (one, two) = tokio::join!(
        use_case.finish(one),
        f.store.finish_oidc_account_deletion(two)
    );
    assert!(
        matches!(
            (one, two),
            (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
        ),
        "exactly one valid deletion commits; infrastructure errors are never a losing authorization result"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    let cooldown: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_deleted_subjects")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(cooldown, 1);
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_deletion_winning_owner_lock_rejects_waiting_verified_signin_without_jit_resurrection(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let signin = f.mapped("owned", json!({})).await;
    let cap = signin.identity().expires_us();
    let deletion = fresh(&f, &user, &current).await;
    let gate = tail_gate(&f, "auth_audit", "account_deleted").await;
    let store = f.store.clone();
    let deleting =
        tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    let store = f.store.clone();
    let signing_in = tokio::spawn(async move { OidcSignIn::new(store).finish(signin).await });
    wait_for_lock(&f.pool, "%FROM auth_users%FOR UPDATE%").await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(cap)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(
        live,
        "test infrastructure: waiting callback must retain its original cap"
    );
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), deleting)
        .await
        .expect("test infrastructure: released deletion finishes")
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), signing_in)
        .await
        .expect("test infrastructure: released signin finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    remove_tail_gate(&f, "auth_audit").await;
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn signin_winning_owner_lock_may_commit_before_provider_deletion_erases_both_sessions(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let signin = f.mapped("owned", json!({})).await;
    let deletion = fresh(&f, &user, &current).await;
    let gate = tail_gate(&f, "auth_audit", "oidc_authenticated").await;
    let store = f.store.clone();
    let signing_in = tokio::spawn(async move { OidcSignIn::new(store).finish(signin).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    let store = f.store.clone();
    let deleting =
        tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
    wait_for_lock(
        &f.pool,
        "%authentication_policy='provider_required'%FOR UPDATE%",
    )
    .await;
    gate.commit().await.unwrap();
    let (_, new_session) = tokio::time::timeout(Duration::from_secs(5), signing_in)
        .await
        .expect("test infrastructure: admitted signin finishes")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), deleting)
        .await
        .expect("test infrastructure: waiting deletion finishes")
        .unwrap()
        .unwrap();
    remove_tail_gate(&f, "auth_audit").await;
    for session in [&current, &new_session] {
        assert!(
            matches!(
                f.store.authenticate(f.realm(), session.verifier()).await,
                Err(Error::Unauthorized)
            ),
            "an in-flight success cannot leave authority after deletion commits"
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 3, 0));
}
