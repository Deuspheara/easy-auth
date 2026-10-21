use super::setup::{Fixture, registration};
use auth_core::{Error, SamlCertificateTrust, SamlPinnedCertificate, SamlTransactions};
use sqlx::PgPool;

fn trust() -> SamlCertificateTrust {
    trust_from(include_bytes!(
        "../../../../../tests/support/saml/certificates/idp.cer"
    ))
}

fn trust_from(pem: &[u8]) -> SamlCertificateTrust {
    let der = openssl::x509::X509::from_pem(pem)
        .unwrap()
        .to_der()
        .unwrap();
    SamlCertificateTrust::pinned_leaf(vec![
        SamlPinnedCertificate::from_der(&der, 1_483_228_800, 1_514_764_800).unwrap(),
    ])
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn certificate_rotation_cancels_pending_state_and_requires_current_exact_registration(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let _pending = f.flow.start().await.unwrap();
    let trusted = trust();
    let next = f
        .store
        .configure_saml_pinned_registration(&f.registration, &trusted)
        .await
        .unwrap();
    assert_ne!(next.revision(), f.registration.revision());
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.store.saml_certificate_trust(&f.registration).await,
        Err(Error::Unauthorized)
    ));
    let stored = f.store.saml_certificate_trust(&next).await.unwrap();
    assert_eq!(
        stored.certificates()[0].fingerprint(),
        trusted.certificates()[0].fingerprint()
    );
    assert!(stored.active_at(1_792_540_800).is_err());
    let cleared = f.store.configure_saml_registration(&next).await.unwrap();
    assert!(matches!(
        f.store.saml_certificate_trust(&cleared).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_certificate_rotation_rolls_back_configuration_pins_and_pending_state(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let original = f
        .store
        .configure_saml_pinned_registration(&f.registration, &trust())
        .await
        .unwrap();
    let flow = SamlTransactions::new(original.clone(), f.store.clone());
    let _pending = flow.start().await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_saml_certificate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'storage fixture'; END $$; CREATE TRIGGER reject_saml_certificate BEFORE INSERT ON auth_saml_certificates FOR EACH ROW EXECUTE FUNCTION reject_saml_certificate()")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store
            .configure_saml_pinned_registration(&original, &trust())
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 1);
    assert!(f.store.saml_certificate_trust(&original).await.is_ok());
    sqlx::query("DROP TRIGGER reject_saml_certificate ON auth_saml_certificates")
        .execute(&f.pool)
        .await
        .unwrap();
    let next = f
        .store
        .configure_saml_pinned_registration(&original, &trust())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(f.store.saml_certificate_trust(&next).await.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn certificates_are_realm_scoped_disabled_and_revalidated_when_loaded(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::new(pool).await;
    let trusted = f
        .store
        .configure_saml_pinned_registration(&f.registration, &trust())
        .await
        .unwrap();
    assert!(matches!(
        other
            .store
            .saml_certificate_trust(&other.registration)
            .await,
        Err(Error::Unauthorized)
    ));
    let other_registration = registration(
        other.registration.realm(),
        trusted.connection(),
        trusted.client(),
    );
    let other_trust = trust_from(include_bytes!(
        "../../../../../tests/support/saml/certificates/rotation.cer"
    ));
    let other_registration = other
        .store
        .configure_saml_pinned_registration(&other_registration, &other_trust)
        .await
        .unwrap();
    let other_pins = other
        .store
        .saml_certificate_trust(&other_registration)
        .await
        .unwrap();
    assert_ne!(
        other_pins.certificates()[0].fingerprint(),
        trust().certificates()[0].fingerprint()
    );
    assert_eq!(
        f.store
            .saml_certificate_trust(&trusted)
            .await
            .unwrap()
            .certificates()[0]
            .fingerprint(),
        trust().certificates()[0].fingerprint()
    );
    // A stored malformed public certificate is an infrastructure failure, never an accepted pin.
    sqlx::query("UPDATE auth_saml_certificates SET certificate_der=$2 WHERE realm_id=$1")
        .bind(trusted.realm())
        .bind([0u8].as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.saml_certificate_trust(&trusted).await,
        Err(Error::Unavailable)
    ));
    let original = trust();
    sqlx::query(
        "UPDATE auth_saml_certificates SET certificate_der=$2,fingerprint=$3 WHERE realm_id=$1",
    )
    .bind(trusted.realm())
    .bind(original.certificates()[0].der())
    .bind([0u8; 32].as_slice())
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(matches!(
        f.store.saml_certificate_trust(&trusted).await,
        Err(Error::Unavailable)
    ));
    f.store
        .disable_saml_registration(trusted.realm(), trusted.connection(), trusted.client())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_saml_certificates WHERE realm_id=$1")
            .bind(trusted.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    assert!(
        other
            .store
            .saml_certificate_trust(&other_registration)
            .await
            .is_ok()
    );
    assert!(matches!(
        f.store.saml_certificate_trust(&trusted).await,
        Err(Error::Unauthorized)
    ));
}
