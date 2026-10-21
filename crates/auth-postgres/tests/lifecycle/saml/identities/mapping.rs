use super::super::signed_idp;
use super::setup::{fixture, verify};
use auth_core::{Error, SamlIdentityPolicy};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn only_actual_proof_of_exact_registration_maps_without_granting_authority(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let proof = verify(&f, "Opaque-Subject").await;
    let stale = SamlIdentityPolicy::new(f.registration.reconfigured());
    assert!(matches!(stale.map(proof), Err(Error::Unauthorized)));
    let proof = verify(&f, "Opaque-Subject").await;
    let deadline = proof.expires_at_us();
    let certificate = *proof.certificate_fingerprint();
    let replay_hash = *proof.replay_reservations()[0].hash();
    let mapped = policy.map(proof).unwrap();
    assert_eq!(mapped.policy(), &policy);
    assert_eq!(mapped.assertion().registration(), policy.registration());
    assert_eq!(mapped.assertion().subject(), "Opaque-Subject");
    assert_eq!(mapped.display_name(), Some("Opaque-Subject"));
    assert_eq!(mapped.assertion().replay_reservations().len(), 2);
    assert_eq!(mapped.assertion().expires_at_us(), deadline);
    assert_eq!(mapped.assertion().certificate_fingerprint(), &certificate);
    assert_eq!(
        mapped.assertion().replay_reservations()[0].hash(),
        &replay_hash
    );
    assert_eq!(
        format!("{mapped:?}"),
        "SamlMappedIdentity([REDACTED; not committed])"
    );
    let long = policy.map(verify(&f, &"s".repeat(300)).await).unwrap();
    assert!(long.display_name().is_none());
    assert_eq!(long.assertion().subject().len(), 300);
    let proof = verify(&f, "Opaque-Subject").await;
    let next = f
        .store
        .configure_saml_identity_policy(&policy, &signed_idp::trust())
        .await
        .unwrap();
    assert!(matches!(next.map(proof), Err(Error::Unauthorized)));
    let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(counts, (0, 0, 0));
}
