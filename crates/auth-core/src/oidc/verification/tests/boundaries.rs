use super::setup::{Fixture, Signing};
use crate::{Error, OidcIdToken, OidcSigningAlgorithm, OidcVerificationPolicy};
use serde_json::json;

#[tokio::test]
async fn signed_unsupported_or_ambiguous_headers_reject_before_document_fetch() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let (_, claims) = f.exchange().await;
    for header in [
        r#"{"alg":"none","kid":"current"}"#,
        r#"{"alg":"HS256","kid":"current"}"#,
        r#"{"alg":"ES256","alg":"ES256","kid":"current"}"#,
        r#"{"alg":"ES256","kid":"current","kid":"current"}"#,
        r#"{"alg":"ES256","kid":"current","jku":"https://attacker.example/keys"}"#,
        r#"{"alg":"ES256","kid":"current","x5u":"https://attacker.example/cert"}"#,
        r#"{"alg":"ES256","kid":"current","jwk":{"kty":"oct","k":"AA"}}"#,
        r#"{"alg":"ES256","kid":"current","crit":["extension"]}"#,
        r#"{"alg":"ES256","kid":"current","b64":false}"#,
        r#"{"alg":"ES256","kid":"current","typ":null}"#,
        r#"{"alg":"ES256","kid":"current","typ":"at+jwt"}"#,
    ] {
        assert!(matches!(
            OidcIdToken::parse(f.key.with_header(header.as_bytes(), &claims)),
            Err(Error::Unauthorized)
        ));
    }
    for malformed in [
        "".to_owned(),
        "x.y".into(),
        "x.y.z.w".into(),
        "x".repeat(16 * 1024 + 1),
    ] {
        assert!(matches!(
            OidcIdToken::parse(malformed),
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.gets(), 0);
    let disallowed = Signing::new(OidcSigningAlgorithm::RS256, "current");
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, disallowed.token(&claims)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.gets(),
        0,
        "configured algorithms must be checked before any metadata fetch"
    );
    let (exchange, claims) = f.exchange().await;
    assert_eq!(
        f.verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap()
            .subject(),
        "subject"
    );
}

#[tokio::test]
async fn key_restrictions_reject_tokens_while_malformed_documents_remain_unavailable() {
    for (member, value, malformed_document) in [
        ("alg", json!("RS256"), false),
        ("use", json!("enc"), false),
        ("key_ops", json!(["sign"]), false),
        ("key_ops", json!(["verify", "verify"]), true),
        ("crv", json!("P-384"), false),
        ("x", json!("AA"), true),
        ("kty", json!("RSA"), false),
        ("kid", serde_json::Value::Null, true),
    ] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        let mut public = f.key.public.clone();
        public[member] = value;
        *f.http.keys.lock().unwrap() = serde_json::to_vec(&json!({"keys":[public]})).unwrap();
        let (exchange, claims) = f.exchange().await;
        let result = f.verifier.verify(exchange, f.key.token(&claims)).await;
        if malformed_document {
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "malformed provider {member}"
            );
        } else {
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "incompatible key use {member}"
            );
        }
        assert_eq!(
            f.gets(),
            2,
            "malformed known key must not trigger an unknown-key retry"
        );
    }
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let mixed = crate::OidcTokenVerifier::new(
        f.documents.clone(),
        f.store.clone(),
        OidcVerificationPolicy::new(
            &[OidcSigningAlgorithm::ES256, OidcSigningAlgorithm::RS256],
            &[],
        )
        .unwrap(),
    );
    let rsa = Signing::new(OidcSigningAlgorithm::RS256, "current");
    let (exchange, claims) = f.exchange().await;
    assert!(
        matches!(
            mixed.verify(exchange, rsa.token(&claims)).await,
            Err(Error::Unauthorized)
        ),
        "a token pairing the wrong algorithm with a valid provider key must not blame infrastructure"
    );
    let (exchange, claims) = f.exchange().await;
    assert_eq!(
        f.verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap()
            .subject(),
        "subject"
    );
}

#[tokio::test]
async fn duplicate_key_material_is_rejected_before_lossy_map_conversion() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let public = serde_json::to_string(&f.key.public).unwrap();
    let duplicate = format!("{{\"keys\":[{{\"kty\":\"EC\",{}]}}", &public[1..]);
    *f.http.keys.lock().unwrap() = duplicate.into_bytes();
    f.documents
        .jwks()
        .await
        .expect("test infrastructure: duplicate-member envelope is otherwise valid JSON");
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, f.key.token(&claims)).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.gets(), 2);
}

#[test]
fn configured_algorithm_and_audience_policy_rejects_ambiguity() {
    assert!(matches!(
        OidcVerificationPolicy::new(&[], &[]),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        OidcVerificationPolicy::new(
            &[OidcSigningAlgorithm::RS256, OidcSigningAlgorithm::RS256],
            &[]
        ),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::RS256], &["other", "other"]),
        Err(Error::InvalidInput)
    ));
}
