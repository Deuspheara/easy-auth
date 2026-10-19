use super::setup::{Fixture, Signing};
use crate::{Error, OidcSigningAlgorithm};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn rotated_key_is_verified_after_one_refresh_and_repeated_unknown_ids_are_bounded() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.documents.jwks().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let rotated = Signing::new(OidcSigningAlgorithm::ES256, "rotated");
    *f.http.keys.lock().unwrap() =
        serde_json::to_vec(&json!({"keys":[rotated.public.clone()]})).unwrap();
    let (exchange, claims) = f.exchange().await;
    assert_eq!(
        f.verifier
            .verify(exchange, rotated.token(&claims))
            .await
            .unwrap()
            .subject(),
        "subject"
    );
    assert_eq!(f.gets(), 3);
    let unknown = Signing::new(OidcSigningAlgorithm::ES256, "unknown");
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, unknown.token(&claims)).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.gets(), 3);
    let (exchange, claims) = f.exchange().await;
    assert_eq!(
        f.verifier
            .verify(exchange, rotated.token(&claims))
            .await
            .unwrap()
            .subject(),
        "subject"
    );
    assert_eq!(f.gets(), 3);
}

#[tokio::test]
async fn unknown_after_one_refresh_rejects_and_ambiguous_key_ids_are_not_signature_negatives() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.documents.jwks().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let unknown = Signing::new(OidcSigningAlgorithm::ES256, "absent");
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, unknown.token(&claims)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 3, "only one refresh per verification attempt");
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    *f.http.keys.lock().unwrap() =
        serde_json::to_vec(&json!({"keys":[f.key.public.clone(),f.key.public.clone()]})).unwrap();
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, f.key.token(&claims)).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        f.gets(),
        2,
        "ambiguous provider document is not an unknown key and must not refresh"
    );
}
