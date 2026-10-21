use super::super::setup::registration;
use super::setup::{fixture, response, trust};
use auth_core::{Error, SamlResponseVerifier, SamlTransactions, SamlVerificationRepository};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn identical_connection_and_client_identifiers_cannot_cross_realms(pool: PgPool) {
    let f = fixture(pool.clone()).await;
    let (other, realm) = crate::support::realm(pool).await;
    let other = Arc::new(other);
    let input = registration(realm, f.registration.connection(), f.registration.client());
    let reg = other
        .configure_saml_pinned_registration(&input, &trust())
        .await
        .unwrap();
    let other_flow = SamlTransactions::new(reg.clone(), other.clone());
    let other_start = other_flow.start().await.unwrap();
    let start = f.flow.start().await.unwrap();
    let response = response(&f, &start, "normal", Duration::from_secs(180));
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let wrong = SamlResponseVerifier::new(reg.clone(), other.clone()).unwrap();
    assert!(matches!(
        wrong.verify(prepared, response).await,
        Err(Error::Unauthorized)
    ));
    f.store
        .disable_saml_registration(
            f.registration.realm(),
            f.registration.connection(),
            f.registration.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .load_saml_verification_material(&f.registration)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(other.load_saml_verification_material(&reg).await.is_ok());
    assert!(
        other_flow
            .prepare_response(
                other_start.request_id(),
                other_start.relay_state(),
                other_start.browser_proof()
            )
            .await
            .is_ok()
    );
}
