use super::super::signed_idp;
use super::setup::fixture;
use auth_core::{Error, SamlIdentityPolicy, SamlJitPolicy, SamlTransactions};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn policy_replacement_is_explicit_revision_bound_and_preserves_disable(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    assert_eq!(policy.jit(), SamlJitPolicy::Deny);
    assert_eq!(
        f.store.saml_identity_policy(&f.registration).await.unwrap(),
        policy
    );
    let _pending = f.flow.start().await.unwrap();
    let allowed = f
        .store
        .configure_saml_identity_policy(
            &policy.clone().with_jit(SamlJitPolicy::Allow),
            &signed_idp::trust(),
        )
        .await
        .unwrap();
    assert_ne!(
        allowed.registration().revision(),
        policy.registration().revision()
    );
    assert_eq!(allowed.jit(), SamlJitPolicy::Allow);
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.store.saml_identity_policy(policy.registration()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store
            .saml_identity_policy(allowed.registration())
            .await
            .unwrap(),
        allowed
    );
    assert_eq!(
        f.store
            .saml_certificate_trust(allowed.registration())
            .await
            .unwrap()
            .certificates()[0]
            .fingerprint(),
        signed_idp::trust().certificates()[0].fingerprint()
    );
    f.store
        .disable_saml_registration(
            f.registration.realm(),
            f.registration.connection(),
            f.registration.client(),
        )
        .await
        .unwrap();
    let replaced = f
        .store
        .configure_saml_identity_policy(&allowed, &signed_idp::trust())
        .await
        .unwrap();
    assert!(matches!(
        f.store.saml_identity_policy(replaced.registration()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        SamlTransactions::new(replaced.registration().clone(), f.store.clone())
            .start()
            .await,
        Err(Error::Unauthorized)
    ));
    f.store
        .enable_saml_registration(replaced.registration())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .saml_identity_policy(replaced.registration())
            .await
            .unwrap(),
        replaced
    );
    let pins_only = f
        .store
        .configure_saml_pinned_registration(replaced.registration(), &signed_idp::trust())
        .await
        .unwrap();
    assert!(matches!(
        f.store.saml_identity_policy(&pins_only).await,
        Err(Error::Unauthorized)
    ));
    let next = f
        .store
        .configure_saml_identity_policy(&SamlIdentityPolicy::new(pins_only), &signed_idp::trust())
        .await
        .unwrap();
    assert_eq!(next.jit(), SamlJitPolicy::Deny);
}
