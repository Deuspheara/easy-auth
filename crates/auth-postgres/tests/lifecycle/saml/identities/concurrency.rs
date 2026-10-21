use super::super::signed_idp;
use super::setup::fixture;
use auth_core::{Error, SamlJitPolicy};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_policy_writers_leave_one_exact_current_definition(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let _pending = f.flow.start().await.unwrap();
    let allowed = policy.clone().with_jit(SamlJitPolicy::Allow);
    let pins = signed_idp::trust();
    // Database configuration serialization only; no signature verification runs.
    let (a, b) = tokio::join!(
        f.store.configure_saml_identity_policy(&policy, &pins),
        f.store.configure_saml_identity_policy(&allowed, &pins)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.registration().revision(), b.registration().revision());
    let (a_result, b_result) = (
        f.store.saml_identity_policy(a.registration()).await,
        f.store.saml_identity_policy(b.registration()).await,
    );
    assert_eq!(
        usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()),
        1
    );
    if let Ok(current) = a_result {
        assert_eq!(current, a);
        assert!(matches!(b_result, Err(Error::Unauthorized)));
    } else {
        assert!(matches!(a_result, Err(Error::Unauthorized)));
        assert_eq!(b_result.unwrap(), b);
    }
    assert_eq!(f.pending().await, 0);
}
