use super::*;
use crate::support::lock_observation::{locked, observer};

#[sqlx::test]
async fn policy_disable_committed_during_check_wait_cannot_return_valid_configuration(
    pool: PgPool,
) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM auth_issuer_native_refresh_policies FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let checker = store.clone();
    let snapshot = saved.clone();
    let task =
        tokio::spawn(async move { checker.check_issuer_native_refresh_policy(&snapshot).await });
    locked(
        &view,
        "%FROM auth_issuer_native_refresh_policies%FOR UPDATE%",
    )
    .await;
    sqlx::query("UPDATE auth_issuer_native_refresh_policies SET enabled=false,revision=$1")
        .bind(Uuid::new_v4())
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert!(
        store
            .enable_issuer_native_refresh_policy(&saved)
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn client_disable_committed_during_enable_wait_cannot_enable_offline_policy(pool: PgPool) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let enabler = store.clone();
    let snapshot = saved.clone();
    let task =
        tokio::spawn(async move { enabler.enable_issuer_native_refresh_policy(&snapshot).await });
    locked(&view, "%FROM auth_issuer_clients%FOR UPDATE%").await;
    sqlx::query("UPDATE auth_issuer_clients SET enabled=false,revision=$1")
        .bind(Uuid::new_v4())
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT enabled FROM auth_issuer_native_refresh_policies")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}
