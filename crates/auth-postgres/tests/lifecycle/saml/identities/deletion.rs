use super::setup::{allow_jit, fixture, verify};
use auth_core::{Error, Repository, SamlSignIn};
use sqlx::PgPool;

/// Privileged persistence erasure fixture, not a new SAML self-service deletion
/// ceremony. Follow existing owner locking and audit deidentification contracts.
#[sqlx::test(migrations = "./migrations")]
async fn erased_owner_keeps_replay_and_subject_cooldown_and_cannot_be_revived_by_verified_input(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (owner, bearer) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let pending = policy.map(verify(&f, "normal").await).unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(owner.realm_id)
        .bind(owner.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE auth_audit SET user_id=NULL,actor_session_id=NULL,session_id=NULL,passkey_id=NULL,recovery_claim_id=NULL,subject_erased=true WHERE realm_id=$1 AND user_id=$2")
        .bind(owner.realm_id).bind(owner.id).execute(&mut *tx).await.unwrap();
    sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
        .bind(owner.realm_id)
        .bind(owner.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let maintained = auth_core::run_retention(
        f.store.as_ref(),
        owner.realm_id,
        auth_core::RetentionPolicy::new(
            auth_core::RetentionHorizon::keep(),
            auth_core::RetentionHorizon::keep(),
        ),
    )
    .await
    .unwrap();
    for step in maintained.steps.iter().filter(|step| {
        matches!(
            step.category,
            auth_core::RetentionCategory::SamlReplays | auth_core::RetentionCategory::SamlCooldowns
        )
    }) {
        assert_eq!(step.effects.deleted, 0);
    }
    let retained: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_saml_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_saml_replays),(SELECT count(*) FROM auth_saml_deleted_subjects WHERE blocked_until>clock_timestamp())")
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(retained, (0, 0, 0, 2, 1));
    assert!(matches!(
        service.finish(pending).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        service
            .finish(policy.map(verify(&f, "normal").await).unwrap())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .authenticate(owner.realm_id, bearer.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    // Privileged retention fixture; does not claim five minutes actually elapsed.
    sqlx::query(
        "UPDATE auth_saml_deleted_subjects SET blocked_until=clock_timestamp()-interval '1 second'",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    let (replacement, _) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    assert_ne!(replacement.id, owner.id);
    let retained: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_saml_replays),(SELECT count(*) FROM auth_saml_deleted_subjects)")
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(retained, (4, 0));
}
