use super::setup;
use super::setup::{fixture, response};
use auth_core::{
    Error, SamlPostResponse, SamlReplayKind, SamlResponseVerifier, SamlTransactions,
    SamlVerificationRepository,
};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn actual_signed_post_extracts_bound_facts_without_creating_local_authority(pool: PgPool) {
    let f = fixture(pool).await;
    let start = f.flow.start().await.unwrap();
    let input = response(
        &f,
        &start,
        "opaque-persistent-subject",
        Duration::from_secs(180),
    );
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let original_cap = prepared.expires_at_us();
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    let proof = verifier.verify(prepared, input).await.unwrap();
    assert_eq!(proof.registration(), &f.registration);
    assert_eq!(proof.subject(), "opaque-persistent-subject");
    assert!(proof.authenticated_at_us() > 0 && proof.authenticated_at_us() < proof.expires_at_us());
    assert!(proof.expires_at_us() <= original_cap);
    assert_eq!(
        proof.certificate_fingerprint(),
        setup::trust().certificates()[0].fingerprint()
    );
    let replay = proof.replay_reservations();
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].kind(), SamlReplayKind::Response);
    assert_eq!(replay[1].kind(), SamlReplayKind::Assertion);
    assert_ne!(replay[0].hash(), replay[1].hash());
    assert!(
        replay
            .iter()
            .all(|r| r.retain_until_us() >= proof.expires_at_us())
    );
    assert_eq!(
        format!("{proof:?}"),
        "VerifiedSamlAssertion([REDACTED; not committed])"
    );
    assert_eq!(f.pending().await, 0);
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions)",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn configured_profile_rejects_invalid_subject_and_excessive_validity(pool: PgPool) {
    let f = fixture(pool).await;
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    for (subject, lifetime) in [("", 180), (" padded ", 180), ("normal", 600)] {
        let start = f.flow.start().await.unwrap();
        let input = response(&f, &start, subject, Duration::from_secs(lifetime));
        let prepared = f
            .flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof(),
            )
            .await
            .unwrap();
        assert!(matches!(
            verifier.verify(prepared, input).await,
            Err(Error::Unauthorized)
        ));
    }
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
    assert!(verifier.verify(prepared, input).await.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_material_requires_current_namespace_and_storage_health(pool: PgPool) {
    let f = fixture(pool).await;
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
    let old = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    let next = f
        .store
        .configure_saml_pinned_registration(&f.registration, &setup::trust())
        .await
        .unwrap();
    assert!(matches!(
        old.verify(prepared, input).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .load_saml_verification_material(&f.registration)
            .await,
        Err(Error::Unauthorized)
    ));
    let next_flow = SamlTransactions::new(next.clone(), f.store.clone());
    let start = next_flow.start().await.unwrap();
    let prepared = next_flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    // Mismatched configuration fails before XML/crypto, even for bounded junk.
    assert!(matches!(
        old.verify(
            prepared,
            SamlPostResponse::parse("invalid-base64".into()).unwrap()
        )
        .await,
        Err(Error::Unauthorized)
    ));
    f.pool.close().await;
    assert!(matches!(
        f.store.load_saml_verification_material(&next).await,
        Err(Error::Unavailable)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_response_requires_its_original_in_response_to(pool: PgPool) {
    let f = fixture(pool).await;
    let a = f.flow.start().await.unwrap();
    let b = f.flow.start().await.unwrap();
    let input = response(&f, &b, "normal", Duration::from_secs(180));
    let prepared_a = f
        .flow
        .prepare_response(a.request_id(), a.relay_state(), a.browser_proof())
        .await
        .unwrap();
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    assert!(matches!(
        verifier.verify(prepared_a, input).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    let input = response(&f, &b, "normal", Duration::from_secs(180));
    let prepared_b = f
        .flow
        .prepare_response(b.request_id(), b.relay_state(), b.browser_proof())
        .await
        .unwrap();
    assert!(verifier.verify(prepared_b, input).await.is_ok());
}
