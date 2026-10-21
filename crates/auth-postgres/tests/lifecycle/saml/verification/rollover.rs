use super::super::signed_idp::{alternate_pin, fixture, response, trust};
use auth_core::{Error, SamlCertificateTrust, SamlResponseVerifier, SamlTransactions};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn only_approved_active_signing_pin_can_verify_with_explicit_overlap(pool: PgPool) {
    let mut f = fixture(pool).await;
    let wrong = SamlCertificateTrust::pinned_leaf(vec![alternate_pin()]).unwrap();
    f.registration = f
        .store
        .configure_saml_pinned_registration(&f.registration, &wrong)
        .await
        .unwrap();
    f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
    let start = f.flow.start().await.unwrap();
    let input = response(&f, &start, "normal", Duration::from_secs(180));
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    assert!(matches!(
        verifier.verify(prepared, input).await,
        Err(Error::Unauthorized)
    ));
    // The same ordinary IdP response path succeeds with one explicit overlap.
    // Attempts are sequential; there is no concurrent signature experiment.
    let overlap =
        SamlCertificateTrust::pinned_leaf(vec![alternate_pin(), trust().certificates()[0].clone()])
            .unwrap();
    f.registration = f
        .store
        .configure_saml_pinned_registration(&f.registration, &overlap)
        .await
        .unwrap();
    f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
    let start = f.flow.start().await.unwrap();
    let input = response(&f, &start, "normal", Duration::from_secs(180));
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    let proof = verifier.verify(prepared, input).await.unwrap();
    assert_eq!(
        proof.certificate_fingerprint(),
        trust().certificates()[0].fingerprint()
    );
}
