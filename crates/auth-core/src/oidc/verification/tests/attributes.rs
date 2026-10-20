use super::setup::Fixture;
use crate::OidcSigningAlgorithm;
use serde_json::json;

#[cfg(not(feature = "oidc-identities"))]
#[tokio::test]
async fn verification_without_mapping_ignores_unrecognized_profile_attributes() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let (exchange, mut claims) = f.exchange().await;
    claims["name"] = json!({"unrecognized": "presentation"});
    claims["preferred_username"] = json!([true]);
    let identity = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    assert_eq!(identity.subject(), "subject");
}

#[tokio::test]
async fn omitted_email_is_not_an_identity_failure_or_a_verified_contact() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for flag in [true, false] {
        let (exchange, mut claims) = f.exchange().await;
        claims["email_verified"] = json!(flag);
        let identity = f
            .verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap();
        assert_eq!(identity.subject(), "subject");
        assert_eq!(identity.email(), None);
        assert!(
            !identity.email_verified(),
            "no email value means no verified email attribute, regardless of a standalone flag"
        );
    }
    let (exchange, mut claims) = f.exchange().await;
    claims["email"] = json!("attribute@example.test");
    claims["email_verified"] = json!(true);
    let identity = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    assert_eq!(identity.email(), Some("attribute@example.test"));
    assert!(identity.email_verified());
    assert_eq!(f.gets(), 2);
}
