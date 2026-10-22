use super::setup::{Fixture, counts, proof};
use auth_core::{Error, Repository, SamlAccountDeletion, SamlDeletionRequests, SamlTransactions};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn ordinary_signed_account_switch_cannot_delete_the_initiating_owner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let deletion = proof(&f, "other").await;
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(deletion)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_after_real_verification_denies_erasure_without_restoring_consumed_request(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let deletion = proof(&f, "normal").await;
    f.source
        .store
        .revoke(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    let revoked_state = counts(&f).await;
    assert_eq!(revoked_state, (1, 1, 1, 2, 2, 0));
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(deletion)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, revoked_state);
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_owner_policy_is_not_a_weaker_deletion_method(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let deletion = proof(&f, "normal").await;
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(deletion)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn operator_disable_after_signature_verification_preserves_the_account(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let deletion = proof(&f, "normal").await;
    let r = &f.source.registration;
    f.source
        .store
        .disable_saml_registration(r.realm(), r.connection(), r.client())
        .await
        .unwrap();
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(deletion)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn replaced_full_policy_rejects_old_proof_and_known_identity_can_delete_under_jit_deny(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool).await;
    let deletion = proof(&f, "normal").await;
    f.policy = f
        .source
        .store
        .configure_saml_identity_policy(
            &f.policy.clone().with_jit(auth_core::SamlJitPolicy::Deny),
            &super::super::super::signed_idp::trust(),
        )
        .await
        .unwrap();
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(deletion)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
    // Source replacement deliberately invalidates the old initiating session.
    // A new real known-subject sign-in under Deny supplies a current session.
    f.source.registration = f.policy.registration().clone();
    f.source.flow = SamlTransactions::new(f.source.registration.clone(), f.source.store.clone());
    f.current = f.another_session("normal").await;
    f.requests = SamlDeletionRequests::new(f.source.registration.clone(), f.source.store.clone());
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 6, 3, 0));
}
