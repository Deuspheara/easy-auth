use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn apple_web_and_native_real_transactions_create_provider_required_sessions_without_email_linking(
    pool: PgPool,
) {
    for kind in [
        AppleClientType::Web,
        AppleClientType::Native(AppleNonceEncoding::Sha256Hex),
    ] {
        let f = Fixture::new(pool.clone(), kind, OidcJitPolicy::Allow).await;
        let local = crate::support::signed_in(&f.store, f.realm(), "matching@example.test").await;
        let local_owner = f
            .store
            .authenticate(f.realm(), local.verifier())
            .await
            .unwrap();
        let a = f.prepare("apple-subject", json!({"email":"matching@example.test","email_verified":"true","is_private_email":"false"})).await;
        let (owner, session) = f.signin(&a).await.unwrap();
        assert_ne!(owner.id, local_owner.id);
        assert!(owner.email.is_none());
        assert_eq!(
            owner.authentication_policy,
            AuthenticationPolicy::ProviderRequired
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            owner
        );
        assert!(matches!(f.signin(&a).await, Err(Error::Unauthorized)));
        let returning = f.prepare("apple-subject", json!({})).await;
        let (same, _) = f.signin(&returning).await.unwrap();
        assert_eq!(same, owner);
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn apple_jit_deny_does_not_create_local_authority_from_a_valid_provider_result(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    let a = f.prepare("subject", json!({})).await;
    assert!(matches!(f.signin(&a).await, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn equal_apple_subjects_are_isolated_by_realm_and_foreign_operations_do_not_consume_owned_state(
    pool: PgPool,
) {
    let a = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    let b = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let one = a.prepare("same-subject", json!({})).await;
    assert!(matches!(b.finish(&one).await, Err(Error::Unauthorized)));
    assert_eq!(a.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(b.provider.posts.load(Ordering::SeqCst), 0);
    let (first, session) = a.signin(&one).await.unwrap();
    let two = b.prepare("same-subject", json!({})).await;
    let (second, _) = b.signin(&two).await.unwrap();
    assert_ne!(first.id, second.id);
    assert!(matches!(
        b.store.authenticate(b.realm(), session.verifier()).await,
        Err(Error::Unauthorized)
    ));
}
