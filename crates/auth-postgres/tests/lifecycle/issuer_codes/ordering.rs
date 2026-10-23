use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::{Error, IssuerTokenError};

#[sqlx::test]
async fn two_concurrent_redemptions_commit_exactly_one_grant_and_audit(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let authentication = f.authentication();
    let (a, b) = tokio::join!(
        f.service
            .redeem(&authentication, &code, &f.redirect, &f.pkce, "127.0.0.1"),
        f.service
            .redeem(&authentication, &code, &f.redirect, &f.pkce, "127.0.0.1")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        usize::from(matches!(a, Err(IssuerTokenError::InvalidGrant)))
            + usize::from(matches!(b, Err(IssuerTokenError::InvalidGrant))),
        1
    );
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_code_redeemed'",
    )
    .bind(f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);
}

#[sqlx::test]
async fn approval_and_cancellation_share_one_locked_decision(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let (approved, cancelled) = tokio::join!(
        f.service.approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization()
        ),
        f.service.cancel(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization()
        )
    );
    assert_eq!(
        usize::from(approved.is_ok()) + usize::from(cancelled.is_ok()),
        1
    );
    assert_eq!(
        f.count(&pool, "auth_issuer_subjects").await,
        i64::from(approved.is_ok())
    );
}

#[sqlx::test]
async fn redemption_waiting_for_client_rechecks_committed_disable(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let realm = f.realm;
    let client = f.client.client();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(client)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        f.service
            .redeem(
                &f.authentication(),
                &code,
                &f.redirect,
                &f.pkce,
                "127.0.0.1",
            )
            .await
    });
    locked(&view, "%SELECT enabled FROM auth_issuer_clients%").await;
    sqlx::query(
        "UPDATE auth_issuer_clients SET enabled=false,revision=$3 WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(client)
    .bind(Uuid::new_v4())
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(IssuerTokenError::InvalidClient)
    ));
    let unchanged: bool = sqlx::query_scalar("SELECT status='approved' AND consumed_at_us IS NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert!(unchanged);
    view.close().await;
}

#[sqlx::test]
async fn approval_waiting_for_owner_rejects_committed_revocation(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.realm)
        .bind(f.owner)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let realm = f.realm;
    let task = tokio::spawn(async move {
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
    });
    locked(&view, "%SELECT id FROM auth_users%FOR UPDATE%").await;
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1")
        .bind(realm)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    view.close().await;
}
