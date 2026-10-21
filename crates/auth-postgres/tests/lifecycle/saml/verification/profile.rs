use super::setup::{fixture, response_from};
use auth_core::{Error, SamlResponseVerifier};
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn ordinary_idp_nameid_formats_must_match_the_persistent_profile(pool: PgPool) {
    let f = fixture(pool).await;
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    for format in [
        None,
        Some(NameIdFormat::EmailAddress),
        Some(NameIdFormat::Transient),
        Some(NameIdFormat::Unspecified),
    ] {
        let start = f.flow.start().await.unwrap();
        let input = response_from(
            &f,
            &start,
            NameId::new("normal", format),
            f.registration.idp_entity(),
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
        assert!(matches!(
            verifier.verify(prepared, input).await,
            Err(Error::Unauthorized)
        ));
    }
    let start = f.flow.start().await.unwrap();
    let input = response_from(
        &f,
        &start,
        NameId::new("normal", Some(NameIdFormat::Persistent)),
        f.registration.idp_entity(),
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
    assert_eq!(
        verifier.verify(prepared, input).await.unwrap().subject(),
        "normal"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_validly_signed_response_from_another_configured_issuer_is_rejected(pool: PgPool) {
    let f = fixture(pool).await;
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    for (issuer, accepted) in [
        ("urn:example:other-idp", false),
        (f.registration.idp_entity(), true),
    ] {
        let start = f.flow.start().await.unwrap();
        let input = response_from(
            &f,
            &start,
            NameId::new("normal", Some(NameIdFormat::Persistent)),
            issuer,
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
        let result = verifier.verify(prepared, input).await;
        if accepted {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
    }
}
