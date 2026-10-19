use super::setup::{Fixture, valid_metadata};
use crate::{Error, MAX_OIDC_DOCUMENT_BYTES};
use serde_json::Value;
use std::sync::atomic::Ordering;

#[tokio::test(start_paused = true)]
async fn issuer_and_every_endpoint_are_validated_with_unchanged_positive_controls() {
    for (field, value) in [
        ("issuer", "https://issuer.example/tenant"),
        ("jwks_uri", "https://attacker.example/keys"),
        ("jwks_uri", "http://issuer.example/keys"),
        ("jwks_uri", "https://issuer.example:8443/keys"),
        ("token_endpoint", "https://user:secret@issuer.example/token"),
        (
            "authorization_endpoint",
            "https://issuer.example/authorize#fragment",
        ),
    ] {
        let f = Fixture::new();
        let mut value_json: Value = serde_json::from_slice(&valid_metadata()).unwrap();
        value_json[field] = value.into();
        *f.http.metadata.lock().unwrap() = serde_json::to_vec(&value_json).unwrap();
        assert!(matches!(
            f.documents.discovery().await,
            Err(Error::Unavailable)
        ));
        assert_eq!(f.gets(), 1);
        assert!(matches!(
            f.documents.discovery().await,
            Err(Error::RateLimited)
        ));
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        *f.http.metadata.lock().unwrap() = valid_metadata();
        let valid = f.documents.discovery().await.unwrap();
        assert!(valid.supports_s256() && valid.supports_response_issuer());
        assert_eq!(f.gets(), 2, "invalid response must not populate cache");
    }
}

#[tokio::test(start_paused = true)]
async fn duplicate_fields_bad_json_oversize_status_and_missing_issuer_support_are_not_cached() {
    let mut unsupported: Value = serde_json::from_slice(&valid_metadata()).unwrap();
    unsupported["authorization_response_iss_parameter_supported"] = false.into();
    for body in [
        b"not-json".to_vec(),
        vec![b' '; MAX_OIDC_DOCUMENT_BYTES + 1],
        br#"{"issuer":"https://issuer.example/tenant/","issuer":"https://attacker.example"}"#
            .to_vec(),
        serde_json::to_vec(&unsupported).unwrap(),
    ] {
        let f = Fixture::new();
        *f.http.metadata.lock().unwrap() = body;
        assert!(matches!(
            f.documents.discovery().await,
            Err(Error::Unavailable)
        ));
        assert_eq!(f.gets(), 1);
    }
    let f = Fixture::new();
    f.http.status.store(302, Ordering::SeqCst);
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::Unavailable)
    ));
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    f.http.status.store(200, Ordering::SeqCst);
    f.http.age.store(0, Ordering::SeqCst);
    f.documents.discovery().await.unwrap();
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::RateLimited)
    ));
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    f.documents.discovery().await.unwrap();
    assert_eq!(
        f.gets(),
        3,
        "non-cacheable successful responses are fetched again"
    );
}

#[tokio::test(start_paused = true)]
async fn jwks_validates_only_a_bounded_envelope_and_preserves_original_bytes() {
    for body in [
        br#"{"keys":[]}"#.to_vec(),
        br#"{"keys":[{}]}"#.to_vec(),
        br#"{"keys":[1]}"#.to_vec(),
        br#"{"keys":[{"kid":"a"}],"keys":[{"kid":"b"}]}"#.to_vec(),
        serde_json::to_vec(&serde_json::json!({"keys":vec![serde_json::json!({"kid":"test"});65]}))
            .unwrap(),
    ] {
        let f = Fixture::new();
        *f.http.keys.lock().unwrap() = body;
        assert!(matches!(f.documents.jwks().await, Err(Error::Unavailable)));
        assert_eq!(f.gets(), 2);
    }
    let f = Fixture::new();
    let original = f.http.keys.lock().unwrap().clone();
    let bytes = f.documents.jwks().await.unwrap();
    assert!(bytes.as_bytes() == original);
}

#[tokio::test(start_paused = true)]
async fn public_jwks_rejects_private_parameters_and_diagnostics_redact_the_document() {
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let f = Fixture::new();
        let mut key = serde_json::Map::new();
        key.insert("kid".into(), "envelope-fixture".into());
        key.insert(field.into(), "private-fixture-marker".into());
        *f.http.keys.lock().unwrap() =
            serde_json::to_vec(&serde_json::json!({"keys":[key]})).unwrap();
        assert!(matches!(f.documents.jwks().await, Err(Error::Unavailable)));
        assert_eq!(f.gets(), 2);
        *f.http.keys.lock().unwrap() = br#"{"keys":[{"kid":"envelope-fixture"}]}"#.to_vec();
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        let document = f.documents.jwks().await.unwrap();
        assert_eq!(
            f.gets(),
            3,
            "rejected private parameters must not populate the cache"
        );
        assert_eq!(format!("{document:?}"), "OidcJwksDocument([REDACTED])");
        assert!(document.as_bytes() == f.http.keys.lock().unwrap().as_slice());
    }
}
