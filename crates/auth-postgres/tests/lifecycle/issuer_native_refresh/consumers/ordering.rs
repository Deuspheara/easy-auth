use super::*;
use crate::support::lock_observation::{locked, observer};
use std::time::Duration;

#[sqlx::test]
async fn actual_family_revoke_committed_before_client_wait_release_cannot_be_inspected_active(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    // Initial signing is complete. Only normal database operations race here.
    let view = observer(&f.base.pool).await;
    let mut blocker = f.base.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_native_families FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let refresh = f.refresher();
    let auth = f.authentication();
    let revoke_token = token.refresh_token().into();
    let revoke =
        tokio::spawn(async move { refresh.revoke(&auth, &revoke_token, "127.0.0.1").await });
    locked(&view, "%FROM auth_issuer_native_families%FOR UPDATE%").await;
    let service = c.service(&f);
    let auth = c.authentication();
    let access = token.access_token().into();
    let read =
        tokio::spawn(async move { service.introspect_access(&auth, &access, "127.0.0.1").await });
    locked(&view, "%FROM auth_issuer_clients%FOR UPDATE%").await;
    blocker.commit().await.unwrap();
    revoke.await.unwrap().unwrap();
    assert!(read.await.unwrap().unwrap().is_none());
}

#[sqlx::test]
async fn actual_consumer_disable_precedes_waiting_inspection_and_cannot_reuse_old_policy(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    let view = observer(&f.base.pool).await;
    let mut blocker = f.base.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM auth_issuer_native_consumers FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let store = f.base.store.clone();
    let authority = f.base.authority.clone();
    let reader = c.policy.consumer().client();
    let audience = c.policy.audience().client();
    let disable = tokio::spawn(async move {
        store
            .disable_issuer_native_consumer(&authority, reader, audience)
            .await
    });
    locked(&view, "%UPDATE auth_issuer_native_consumers%").await;
    let service = c.service(&f);
    let auth = c.authentication();
    let access = token.access_token().into();
    let read =
        tokio::spawn(async move { service.introspect_access(&auth, &access, "127.0.0.1").await });
    locked(&view, "%FROM auth_issuer_clients%FOR UPDATE%").await;
    blocker.commit().await.unwrap();
    disable.await.unwrap().unwrap();
    assert!(read.await.unwrap().unwrap().is_none());
    assert!(
        f.base
            .store
            .enable_issuer_native_consumer(&c.policy)
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn access_expiry_during_observed_family_wait_is_checked_after_every_lock(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    sqlx::query("UPDATE auth_issuer_access_tokens SET expires_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint+2000000 WHERE realm_id=$1").bind(f.base.authority.realm()).execute(&f.base.pool).await.unwrap();
    let view = observer(&f.base.pool).await;
    let mut blocker = f.base.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_native_families FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let service = c.service(&f);
    let auth = c.authentication();
    let access = token.access_token().into();
    let read =
        tokio::spawn(async move { service.introspect_access(&auth, &access, "127.0.0.1").await });
    locked(&view, "%FROM auth_issuer_native_families%FOR UPDATE%").await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    blocker.commit().await.unwrap();
    assert!(read.await.unwrap().unwrap().is_none());
}
