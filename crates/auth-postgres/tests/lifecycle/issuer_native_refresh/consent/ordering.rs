use super::*;
use crate::support::lock_observation::{locked, observer};

#[sqlx::test]
async fn native_approve_cancel_race_has_one_decision_and_only_its_committed_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
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
        ),
    );
    assert_eq!(
        usize::from(approved.is_ok()) + usize::from(cancelled.is_ok()),
        1
    );
    let count = i64::from(approved.is_ok());
    assert_eq!(f.facts().await, (count, count, count, 0, count));
}

#[sqlx::test]
async fn native_preparation_rechecks_policy_disabled_during_current_client_wait(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool).await);
    let view = observer(&f.pool).await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.policy.authority().realm())
        .bind(f.policy.client().client())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let worker = f.clone();
    let task = tokio::spawn(async move {
        worker
            .prepare_with("openid offline_access", "consent")
            .await
    });
    locked(
        &view,
        "%SELECT enabled FROM auth_issuer_clients%FOR UPDATE%",
    )
    .await;
    sqlx::query("UPDATE auth_issuer_native_refresh_policies SET enabled=false,revision=$1")
        .bind(Uuid::new_v4())
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test]
async fn native_approval_waiting_for_owner_rechecks_revoked_original_session(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool).await);
    let pending = f.prepare().await;
    let view = observer(&f.pool).await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.policy.authority().realm())
        .bind(f.owner)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let worker = f.clone();
    let task = tokio::spawn(async move {
        worker
            .service
            .approve(
                &worker.current,
                &worker.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
    });
    locked(&view, "%SELECT id FROM auth_users%FOR UPDATE%").await;
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1")
        .bind(f.policy.authority().realm())
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
}

#[sqlx::test]
async fn native_approval_expiring_in_final_audit_wait_rolls_back_code_consent_subject_and_event(
    pool: PgPool,
) {
    let f = Arc::new(Fixture::new(pool).await);
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5480)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION native_audit_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='issuer_authorized' THEN PERFORM pg_advisory_xact_lock(5480); END IF; RETURN NEW; END $$; CREATE TRIGGER native_audit_gate BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION native_audit_gate();").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 57 seconds' WHERE realm_id=$1").bind(f.policy.authority().realm()).execute(&f.pool).await.unwrap();
    let pending = f.prepare().await;
    let cap = pending.expires_at_us();
    let view = observer(&f.pool).await;
    let worker = f.clone();
    let task = tokio::spawn(async move {
        worker
            .service
            .approve(
                &worker.current,
                &worker.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
    });
    locked(&view, "%INSERT INTO auth_audit%").await;
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&view)
            .await
            .unwrap();
    assert!(
        now < cap,
        "must reach the observed write before original expiry"
    );
    tokio::time::sleep(std::time::Duration::from_micros(
        (cap - now) as u64 + 50_000,
    ))
    .await;
    gate.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT approved_at_us IS NULL FROM auth_issuer_native_consents"
        )
        .fetch_one(&f.pool)
        .await
        .unwrap()
    );
}

#[sqlx::test]
async fn native_grant_cap_expiring_during_sidecar_wait_cannot_be_slid_forward(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool).await);
    let short = IssuerNativeRefreshPolicy::new(
        f.policy.authority().clone(),
        f.policy.client().clone(),
        3,
        3,
    )
    .unwrap();
    let _saved = f
        .store
        .configure_issuer_native_refresh_policy(&short)
        .await
        .unwrap();
    let pending = f.prepare().await;
    assert_eq!(pending.expires_at_us(), pending.grant_expires_at_us());
    let cap = pending.grant_expires_at_us();
    let view = observer(&f.pool).await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("SELECT authorization_id FROM auth_issuer_native_consents FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let worker = f.clone();
    let task = tokio::spawn(async move {
        worker
            .service
            .approve(
                &worker.current,
                &worker.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
    });
    locked(&view, "%FROM auth_issuer_native_consents%FOR UPDATE%").await;
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&view)
            .await
            .unwrap();
    assert!(
        now < cap,
        "must observe the wait inside the original grant cap"
    );
    tokio::time::sleep(std::time::Duration::from_micros(
        (cap - now) as u64 + 50_000,
    ))
    .await;
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
}
