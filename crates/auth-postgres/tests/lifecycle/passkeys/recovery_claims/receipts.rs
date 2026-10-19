use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn only_a_current_unexpired_successful_lease_starts_the_notification_delay(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let first = f.start_notice().await;
    f.unnotified().await;
    f.f.store
        .complete_security_notice(f.f.realm, first.id, first.lease, false)
        .await
        .unwrap();
    f.unnotified().await;
    f.due_notices().await;
    let second = f.start_notice().await;
    f.f.store
        .complete_security_notice(f.f.realm, first.id, first.lease, true)
        .await
        .unwrap();
    f.unnotified().await;
    f.f.store
        .complete_security_notice(Uuid::new_v4(), second.id, second.lease, true)
        .await
        .unwrap();
    f.unnotified().await;
    f.due_notices().await;
    f.f.store
        .complete_security_notice(f.f.realm, second.id, second.lease, true)
        .await
        .unwrap();
    f.unnotified().await;
    let third = f.start_notice().await;
    f.f.store
        .complete_security_notice(f.f.realm, third.id, third.lease, true)
        .await
        .unwrap();
    let state = f
        .flow
        .status(f.owner, &f.browser, SOURCE, claim.id)
        .await
        .unwrap();
    assert!(!state.ready && state.not_before_ms.is_some());
    let delay:bool=sqlx::query_scalar("SELECT notified_at>=created_at AND not_before=notified_at+interval '24 hours' FROM auth_passkey_recovery_claims WHERE realm_id=$1")
        .bind(f.f.realm).fetch_one(&pool).await.unwrap();
    assert!(delay);
    let snapshot = f.snapshot().await;
    f.f.store
        .complete_security_notice(f.f.realm, third.id, third.lease, true)
        .await
        .unwrap();
    f.unchanged(snapshot).await;
    sqlx::query("UPDATE auth_passkey_recovery_claims SET created_at=created_at-interval '25 hours',notified_at=notified_at-interval '25 hours',not_before=not_before-interval '25 hours' WHERE realm_id=$1")
        .bind(f.f.realm).execute(&pool).await.unwrap();
    assert!(
        f.flow
            .status(f.owner, &f.browser, SOURCE, claim.id)
            .await
            .unwrap()
            .ready
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelled_rotated_and_expired_claims_cannot_be_revived_by_late_acknowledgements(
    pool: PgPool,
) {
    for mode in ["cancel", "rotate", "expire"] {
        let f = Claims::new(pool.clone(), false).await;
        let claim = f
            .flow
            .begin(f.owner, &f.code, &f.browser, SOURCE)
            .await
            .unwrap();
        let notice = f.start_notice().await;
        match mode {
            "cancel" => f
                .flow
                .cancel(f.owner, &f.browser, SOURCE, claim.id)
                .await
                .unwrap(),
            "rotate" => {
                let next = f.setup.prepare(&f.f.session, SOURCE).await.unwrap();
                // Preparation leaves claim and receipt authority intact until confirmed.
                f.flow
                    .status(f.owner, &f.browser, SOURCE, claim.id)
                    .await
                    .unwrap();
                f.setup
                    .confirm(&f.f.session, SOURCE, next.id, &next.code)
                    .await
                    .unwrap();
            }
            "expire" => {
                sqlx::query("UPDATE auth_passkey_recovery_claims SET created_at=created_at-interval '8 days',expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1")
                .bind(f.f.realm).execute(&pool).await.unwrap();
            }
            _ => unreachable!(),
        }
        f.f.store
            .complete_security_notice(f.f.realm, notice.id, notice.lease, true)
            .await
            .unwrap();
        assert!(matches!(
            f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
            Err(Error::Unauthorized)
        ));
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND notified_at IS NOT NULL")
            .bind(f.f.realm).fetch_one(&pool).await.unwrap();
        assert_eq!(receipts, 0);
    }
}
