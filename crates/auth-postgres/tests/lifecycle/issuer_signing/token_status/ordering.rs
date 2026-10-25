use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::IssuerTokenManagement;

#[sqlx::test]
async fn completed_issuance_then_database_only_revocations_have_one_permanent_timestamp(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true).await;
    let management = f.service();
    let authentication = f.authentication();
    let token = IssuerPresentedToken::from(f.issued.access_token());
    // The ordinary signature is already complete. Only database revocation
    // operations run concurrently; this is no signing concurrency experiment.
    let (a, b) = tokio::join!(
        management.revoke_access(&authentication, &token, "127.0.0.1"),
        management.revoke_access(&authentication, &token, "127.0.0.1")
    );
    a.unwrap();
    b.unwrap();
    let first = f.revoked().await.unwrap();
    assert!(
        management
            .introspect_access(
                &authentication,
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.revoked().await, Some(first));
}

#[sqlx::test]
async fn revocation_committed_during_access_row_wait_wins_before_active_metadata_can_return(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true).await;
    let view = observer(&f.f.pool).await;
    let mut blocker = f.f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_access_tokens WHERE realm_id=$1 FOR UPDATE")
        .bind(f.f.authority.realm())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let management = f.service();
    let authentication = f.authentication();
    let token = auth_core::IssuerPresentedToken::from(f.issued.access_token());
    let task = tokio::spawn(async move {
        management
            .introspect_access(&authentication, &token, "127.0.0.1")
            .await
    });
    locked(&view, "%FROM auth_issuer_access_tokens%FOR SHARE%").await;
    sqlx::query("UPDATE auth_issuer_access_tokens SET revoked_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE realm_id=$1")
        .bind(f.f.authority.realm()).execute(&mut *blocker).await.unwrap();
    blocker.commit().await.unwrap();
    assert!(task.await.unwrap().unwrap().is_none());
    assert!(f.revoked().await.is_some());
}

#[sqlx::test]
async fn final_clock_rejects_unchanged_access_that_expires_during_a_database_row_wait(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true).await;
    let expiry:i64=sqlx::query_scalar("UPDATE auth_issuer_access_tokens SET expires_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint+5000000 WHERE realm_id=$1 RETURNING expires_at_us")
        .bind(f.f.authority.realm()).fetch_one(&f.f.pool).await.unwrap();
    let view = observer(&f.f.pool).await;
    let mut blocker = f.f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_access_tokens WHERE realm_id=$1 FOR UPDATE")
        .bind(f.f.authority.realm())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let management = IssuerTokenManagement::new(f.f.authority.clone(), f.f.store.clone());
    let authentication = f.authentication();
    let token = auth_core::IssuerPresentedToken::from(f.issued.access_token());
    let task = tokio::spawn(async move {
        management
            .introspect_access(&authentication, &token, "127.0.0.1")
            .await
    });
    locked(&view, "%FROM auth_issuer_access_tokens%FOR SHARE%").await;
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&view)
            .await
            .unwrap();
    tokio::time::sleep(std::time::Duration::from_micros(
        (expiry - now).max(0) as u64 + 50_000,
    ))
    .await;
    blocker.commit().await.unwrap();
    assert!(task.await.unwrap().unwrap().is_none());
    assert!(f.revoked().await.is_none());
}
