use super::{super::signed_idp, setup::fixture};
use auth_core::{Error, SamlIdentityPolicy, SamlJitPolicy, SamlRegistration};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn startup_load_preserves_revision_pending_work_and_trusted_policy(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let _pending = f.flow.start().await.unwrap();
    let input = SamlIdentityPolicy::new(f.registration.reconfigured());
    let (first, second) = tokio::join!(
        f.store.load_saml_identity_policy(&input),
        f.store.load_saml_identity_policy(&input)
    );
    assert_eq!(first.unwrap(), policy);
    assert_eq!(second.unwrap(), policy);
    assert_eq!(f.pending().await, 1);
    assert!(matches!(
        f.store
            .load_saml_identity_policy(&input.with_jit(SamlJitPolicy::Allow))
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn startup_never_provisions_changes_or_reenables_a_source(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let reg = policy.registration();
    for (realm, connection, idp) in [
        (Uuid::new_v4(), reg.connection(), reg.idp_entity()),
        (reg.realm(), Uuid::new_v4(), reg.idp_entity()),
        (reg.realm(), reg.connection(), "urn:wrong:idp"),
    ] {
        let other = SamlIdentityPolicy::new(
            SamlRegistration::unsigned_redirect(
                realm,
                connection,
                reg.client(),
                reg.sp_entity(),
                idp,
                reg.sso(),
                reg.acs(),
            )
            .unwrap(),
        );
        assert!(matches!(
            f.store.load_saml_identity_policy(&other).await,
            Err(Error::Unauthorized)
        ));
    }
    f.store
        .disable_saml_registration(reg.realm(), reg.connection(), reg.client())
        .await
        .unwrap();
    assert!(matches!(
        f.store.load_saml_identity_policy(&policy).await,
        Err(Error::Unauthorized)
    ));
    let enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM auth_saml_registrations WHERE realm_id=$1 AND id=$2 AND client_id=$3",
    )
    .bind(reg.realm())
    .bind(reg.connection())
    .bind(reg.client())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!enabled);
}

#[sqlx::test(migrations = "./migrations")]
async fn startup_rejects_generic_registration_and_pins_without_identity_policy(pool: PgPool) {
    let f = super::super::setup::Fixture::new(pool).await;
    let input = SamlIdentityPolicy::new(f.registration.clone());
    assert!(matches!(
        f.store.load_saml_identity_policy(&input).await,
        Err(Error::Unauthorized)
    ));
    let registration = f
        .store
        .configure_saml_pinned_registration(&f.registration, &signed_idp::trust())
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .load_saml_identity_policy(&SamlIdentityPolicy::new(registration))
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn startup_requires_active_approved_pins_without_repairing_them(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    sqlx::query("UPDATE auth_saml_certificates SET approved_until=approved_from+1 WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
        .bind(f.registration.realm()).bind(f.registration.connection()).bind(f.registration.client())
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.load_saml_identity_policy(&policy).await,
        Err(Error::Unauthorized)
    ));
    let width: i64 = sqlx::query_scalar("SELECT approved_until-approved_from FROM auth_saml_certificates WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
        .bind(f.registration.realm()).bind(f.registration.connection()).bind(f.registration.client())
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(width, 1);
}
