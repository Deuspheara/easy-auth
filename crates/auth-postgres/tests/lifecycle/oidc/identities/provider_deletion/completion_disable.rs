use super::super::setup::wait_for_lock;
use super::completion_setup::{account, fresh, remove_tail_gate, snapshot, tail_gate};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn disable_committing_before_final_deletion_rejects_it_and_reenable_cannot_revive_old_proof(
    pool: PgPool,
) {
    let (mut f, user, current) = account(pool).await;
    let deletion = fresh(&f, &user, &current).await;
    let old = fresh(&f, &user, &current).await;
    let c = f.policy.configuration();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_oauth_connections SET enabled=false,revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(Uuid::new_v4()).execute(&mut *gate).await.unwrap();
    let before = snapshot(&f).await;
    let store = f.store.clone();
    let deleting =
        tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
    wait_for_lock(&f.pool, "%FROM auth_oauth_connections WHERE%FOR SHARE%").await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), deleting)
        .await
        .expect("test infrastructure: disabled-source deletion finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert!(snapshot(&f).await == before);
    f.reconfigure(OidcJitPolicy::Allow).await;
    f.store
        .enable_oauth_connection(f.policy.configuration())
        .await
        .unwrap();
    assert!(matches!(
        f.store.finish_oidc_account_deletion(old).await,
        Err(Error::Unauthorized)
    ));
    let (_, valid) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &valid).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn admitted_deletion_can_commit_before_waiting_disable_without_leaving_any_local_authority(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let deletion = fresh(&f, &user, &current).await;
    let gate = tail_gate(&f, "auth_audit", "account_deleted").await;
    let store = f.store.clone();
    let deleting =
        tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    let store = f.store.clone();
    let c = f.policy.configuration().clone();
    let disabling = tokio::spawn(async move {
        store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
    });
    wait_for_lock(&f.pool, "%UPDATE auth_oauth_connections SET enabled=false%").await;
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), deleting)
        .await
        .expect("test infrastructure: admitted deletion finishes")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), disabling)
        .await
        .expect("test infrastructure: waiting disable finishes")
        .unwrap()
        .unwrap();
    remove_tail_gate(&f, "auth_audit").await;
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    let enabled: bool =
        sqlx::query_scalar("SELECT enabled FROM auth_oauth_connections WHERE realm_id=$1")
            .bind(f.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!enabled);
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
}
