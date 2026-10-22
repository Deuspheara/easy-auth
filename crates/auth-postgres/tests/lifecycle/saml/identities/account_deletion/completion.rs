use super::setup::{Fixture, counts, proof};
use auth_core::{
    Error, MAX_SAML_DELETION_AUTH_AGE_SECONDS, Repository, SamlAccountDeletion, SamlSignIn, Secret,
    SecurityNoticeKind,
};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn actual_deletion_proof_alone_grants_nothing_then_atomic_erasure_preserves_replay_and_cooldown(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.requests.start(&f.current).await.unwrap();
    let preverified = f
        .policy
        .map(super::super::setup::verify(&f.source, "normal").await)
        .unwrap();
    let deletion = proof(&f, "normal").await;
    assert_eq!(deletion.binding().user, f.user.id);
    assert_eq!(deletion.policy(), &f.policy);
    assert_eq!(
        deletion.fresh_until_us() - deletion.assertion().authenticated_at_us(),
        i64::try_from(MAX_SAML_DELETION_AUTH_AGE_SECONDS).unwrap() * 1_000_000
    );
    assert_eq!(
        format!("{deletion:?}"),
        "SamlVerifiedDeletion([REDACTED; not committed])"
    );
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 1));
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(deletion)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
    let erased: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL),(SELECT count(*) FROM auth_saml_deleted_subjects WHERE realm_id=$1 AND blocked_until>clock_timestamp()),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1)")
        .bind(f.user.realm_id).fetch_one(&f.source.pool).await.unwrap();
    assert_eq!(erased, (2, 1, 0));
    assert!(matches!(
        f.source
            .store
            .authenticate(f.user.realm_id, f.current.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.requests
            .cancel(
                &f.current,
                pending.request_id(),
                pending.relay_state(),
                pending.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        SamlSignIn::new(f.source.store.clone())
            .finish(preverified)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        SamlSignIn::new(f.source.store.clone())
            .finish(
                f.policy
                    .map(super::super::setup::verify(&f.source, "normal").await)
                    .unwrap()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn stored_verified_contact_receives_only_the_existing_notice_without_mailbox_fallback(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::query("UPDATE auth_users SET email='stored-contact@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    assert!(matches!(
        f.source
            .store
            .begin_account_deletion(
                f.user.realm_id,
                f.current.verifier(),
                Secret::generate().unwrap().verifier(),
                Secret::generate().unwrap().verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    let notice = f
        .source
        .store
        .claim_security_notice(f.user.realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(notice.recipient, "stored-contact@example.test");
    assert!(matches!(notice.kind, SecurityNoticeKind::AccountDeleted));
    let subject: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT user_id FROM auth_security_notifications WHERE realm_id=$1")
            .bind(f.user.realm_id)
            .fetch_one(&f.source.pool)
            .await
            .unwrap();
    assert_eq!(subject, None);
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn other_subject_owner_and_another_realm_remain_usable(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = f.another_session("other").await;
    let foreign = Fixture::new(pool).await;
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    let user = f
        .source
        .store
        .authenticate(f.user.realm_id, other.verifier())
        .await
        .unwrap();
    assert_ne!(user.id, f.user.id);
    assert_eq!(
        foreign
            .source
            .store
            .authenticate(foreign.user.realm_id, foreign.current.verifier())
            .await
            .unwrap(),
        foreign.user
    );
    assert_eq!(counts(&foreign).await, (1, 1, 1, 2, 1, 0));
}
