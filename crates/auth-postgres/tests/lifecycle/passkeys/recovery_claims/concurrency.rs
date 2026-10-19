use super::*;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn acknowledgement_and_fresh_key_cancellation_serialize_without_restoring_authority(
    pool: PgPool,
) {
    for _ in 0..4 {
        let f = Claims::new(pool.clone(), false).await;
        let claim = f
            .flow
            .begin(f.owner, &f.code, &f.browser, SOURCE)
            .await
            .unwrap();
        let notice = f.start_notice().await;
        let (cancel, ack) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                f.flow.cancel_with_key(&f.f.session, SOURCE, claim.id),
                f.f.store
                    .complete_security_notice(f.f.realm, notice.id, notice.lease, true)
            )
        })
        .await
        .expect("test infrastructure: cancellation/receipt completion");
        cancel.unwrap();
        ack.unwrap();
        assert!(matches!(
            f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
            Err(Error::Unauthorized)
        ));
        let facts:(bool,i64)=sqlx::query_as("SELECT (SELECT cancelled_at IS NOT NULL FROM auth_passkey_recovery_claims WHERE realm_id=$1),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkey_recovery_started')")
            .bind(f.f.realm).fetch_one(&pool).await.unwrap();
        assert_eq!(facts, (true, 0));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn generation_rotation_and_acknowledgement_cannot_keep_an_old_claim_live(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let old = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let notice = f.start_notice().await;
    let next = f.setup.prepare(&f.f.session, SOURCE).await.unwrap();
    let (rotate, ack) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            f.setup.confirm(&f.f.session, SOURCE, next.id, &next.code),
            f.f.store
                .complete_security_notice(f.f.realm, notice.id, notice.lease, true)
        )
    })
    .await
    .expect("test infrastructure: generation/receipt completion");
    rotate.unwrap();
    ack.unwrap();
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, old.id).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    let replacement = f
        .flow
        .begin(f.owner, &next.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert_ne!(replacement.id, old.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn account_deletion_racing_ack_erases_claim_targets_codes_and_owned_admission(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let other = Claims::new(pool.clone(), false).await;
    let before = other.snapshot().await;
    f.flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let notice = f.start_notice().await;
    let (token, browser) =
        crate::account::deletion_proof(&f.f.store, f.f.realm, f.f.session.verifier()).await;
    let (delete, ack) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            f.f.store.finish_account_deletion(
                f.f.realm,
                f.f.session.verifier(),
                token.verifier(),
                browser.verifier()
            ),
            f.f.store
                .complete_security_notice(f.f.realm, notice.id, notice.lease, true)
        )
    })
    .await
    .expect("test infrastructure: deletion/receipt completion");
    delete.unwrap();
    ack.unwrap();
    let erased:bool=sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL AND recovery_claim_id IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_started'")
        .bind(f.f.realm).fetch_one(&pool).await.unwrap();
    assert!(erased);
    let remaining:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkey_recovery_codes WHERE realm_id=$1),(SELECT count(*) FROM auth_passkey_recovery_claims WHERE realm_id=$1),(SELECT count(*) FROM auth_rate_buckets WHERE realm_id=$1 AND dimension='passkey_recovery_user')")
        .bind(f.f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(remaining, (0, 0, 0));
    other.unchanged(before).await;
}
