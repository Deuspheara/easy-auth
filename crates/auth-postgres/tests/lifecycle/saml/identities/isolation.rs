use super::super::{setup::registration, signed_idp};
use super::setup::{fixture, verify};
use auth_core::{Error, SamlIdentityPolicy, SamlJitPolicy};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn mapping_policy_and_disable_are_isolated_for_identical_ids_across_realms(pool: PgPool) {
    let (f, policy) = fixture(pool.clone()).await;
    let (other, realm) = crate::support::realm(pool).await;
    let reg = registration(realm, f.registration.connection(), f.registration.client());
    let other_policy = other
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
            &signed_idp::trust(),
        )
        .await
        .unwrap();
    assert!(matches!(
        other_policy.map(verify(&f, "normal").await),
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store.saml_identity_policy(&f.registration).await.unwrap(),
        policy
    );
    assert_eq!(
        other
            .saml_identity_policy(other_policy.registration())
            .await
            .unwrap(),
        other_policy
    );
    f.store
        .disable_saml_registration(
            f.registration.realm(),
            f.registration.connection(),
            f.registration.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.store.saml_identity_policy(&f.registration).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        other
            .saml_identity_policy(other_policy.registration())
            .await
            .unwrap(),
        other_policy
    );
}
