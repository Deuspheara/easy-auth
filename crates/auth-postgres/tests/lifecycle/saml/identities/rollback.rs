use super::super::signed_idp;
use super::setup::fixture;
use auth_core::{Error, SamlJitPolicy};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn failed_policy_insert_restores_registration_pins_and_pending_state(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let pending = f.flow.start().await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_saml_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned test failure'; END $$; CREATE TRIGGER reject_saml_policy BEFORE INSERT ON auth_saml_identity_policies FOR EACH ROW EXECUTE FUNCTION reject_saml_policy();")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store
            .configure_saml_identity_policy(
                &policy.clone().with_jit(SamlJitPolicy::Allow),
                &signed_idp::trust()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        f.store.saml_identity_policy(&f.registration).await.unwrap(),
        policy
    );
    assert_eq!(
        f.store
            .saml_certificate_trust(&f.registration)
            .await
            .unwrap()
            .certificates()[0]
            .fingerprint(),
        signed_idp::trust().certificates()[0].fingerprint()
    );
    assert_eq!(f.pending().await, 1);
    sqlx::raw_sql("DROP TRIGGER reject_saml_policy ON auth_saml_identity_policies; DROP FUNCTION reject_saml_policy();").execute(&f.pool).await.unwrap();
    assert!(
        f.flow
            .prepare_response(
                pending.request_id(),
                pending.relay_state(),
                pending.browser_proof()
            )
            .await
            .is_ok()
    );
    assert!(
        f.store
            .configure_saml_identity_policy(
                &policy.with_jit(SamlJitPolicy::Allow),
                &signed_idp::trust()
            )
            .await
            .is_ok()
    );
}
