use super::setup::{Fixture, NOW_US, Signing};
use crate::{Error, OidcIdToken, OidcSigningAlgorithm, Secret};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn explicit_algorithms_verify_real_signatures_without_inventing_freshness_or_contact_authority()
 {
    for algorithm in [
        OidcSigningAlgorithm::RS256,
        OidcSigningAlgorithm::PS256,
        OidcSigningAlgorithm::ES256,
    ] {
        let f = Fixture::new(algorithm, &[]);
        let (exchange, mut claims) = f.exchange().await;
        claims["email"] = json!("attribute@example.test");
        claims["email_verified"] = json!(true);
        let token = f.key.token(&claims);
        assert_eq!(format!("{token:?}"), "OidcIdToken([REDACTED])");
        let result = f.verifier.verify(exchange, token).await.unwrap();
        assert_eq!(result.configuration(), &f.store.connection);
        assert_eq!(
            result.expires_us(),
            NOW_US + 60_000_000,
            "provider token expiry also caps future commit authority"
        );
        assert_eq!(result.subject(), "subject");
        assert_eq!(result.issued_at(), (NOW_US / 1_000_000) as u64);
        assert_eq!(
            result.authenticated_at(),
            None,
            "token issuance does not prove provider authentication time"
        );
        assert_eq!(result.email(), Some("attribute@example.test"));
        assert!(result.email_verified());
        assert_eq!(format!("{result:?}"), "VerifiedOidcIdentity([REDACTED])");
        assert_eq!(f.gets(), 2);
    }
}

#[tokio::test]
async fn required_claims_and_exact_binding_time_and_type_negatives_reject_then_valid_control_succeeds()
 {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for field in ["iss", "sub", "aud", "iat", "exp", "nonce"] {
        let (exchange, mut claims) = f.exchange().await;
        claims.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(
                f.verifier.verify(exchange, f.key.token(&claims)).await,
                Err(Error::Unauthorized)
            ),
            "missing {field}"
        );
    }
    let invalids: Vec<(&str, Value)> = vec![
        ("iss", json!("https://issuer.example/")),
        ("sub", json!("")),
        ("sub", json!("a".repeat(256))),
        ("aud", json!("other")),
        ("aud", json!([])),
        ("aud", json!(["client", "client"])),
        ("aud", json!(["client", "untrusted"])),
        ("nonce", json!(Secret::generate().unwrap().expose())),
        ("nonce", Value::Null),
        ("azp", json!("other")),
        ("azp", Value::Null),
        ("iat", json!(NOW_US / 1_000_000 + 1)),
        ("iat", json!(NOW_US / 1_000_000 - 301)),
        ("iat", json!(NOW_US / 1_000_000 - 300)),
        ("iat", json!("1700000000")),
        ("exp", json!(NOW_US / 1_000_000)),
        ("exp", Value::Null),
        ("nbf", json!(NOW_US / 1_000_000 + 1)),
        ("nbf", Value::Null),
        ("auth_time", json!(NOW_US / 1_000_000 + 1)),
        ("email_verified", json!("true")),
        ("email_verified", Value::Null),
    ];
    for (field, value) in invalids {
        let (exchange, mut claims) = f.exchange().await;
        claims[field] = value;
        assert!(
            matches!(
                f.verifier.verify(exchange, f.key.token(&claims)).await,
                Err(Error::Unauthorized)
            ),
            "invalid {field}"
        );
    }
    let (exchange, claims) = f.exchange().await;
    assert_eq!(
        f.verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap()
            .subject(),
        "subject"
    );
    assert_eq!(f.gets(), 2, "claim rejection never forces a key refresh");
}

#[tokio::test]
async fn multiple_audiences_require_explicit_trust_and_matching_authorized_party() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &["trusted"]);
    for azp in [None, Some("other")] {
        let (exchange, mut claims) = f.exchange().await;
        claims["aud"] = json!(["client", "trusted"]);
        if let Some(value) = azp {
            claims["azp"] = json!(value);
        }
        assert!(matches!(
            f.verifier.verify(exchange, f.key.token(&claims)).await,
            Err(Error::Unauthorized)
        ));
    }
    let (exchange, mut claims) = f.exchange().await;
    claims["aud"] = json!(["client", "trusted"]);
    claims["azp"] = json!("client");
    claims["auth_time"] = json!(NOW_US / 1_000_000 - 1000);
    let result = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    assert_eq!(
        result.authenticated_at(),
        Some((NOW_US / 1_000_000 - 1000) as u64)
    );
}

#[tokio::test]
async fn bad_signature_never_refreshes_and_a_fresh_valid_signature_is_a_control() {
    for algorithm in [
        OidcSigningAlgorithm::RS256,
        OidcSigningAlgorithm::PS256,
        OidcSigningAlgorithm::ES256,
    ] {
        let f = Fixture::new(algorithm, &[]);
        let other = Signing::new(algorithm, "current");
        let (exchange, claims) = f.exchange().await;
        assert!(matches!(
            f.verifier.verify(exchange, other.token(&claims)).await,
            Err(Error::Unauthorized)
        ));
        let (exchange, claims) = f.exchange().await;
        assert_eq!(
            f.verifier
                .verify(exchange, f.key.token(&claims))
                .await
                .unwrap()
                .subject(),
            "subject"
        );
        assert_eq!(f.gets(), 2);
    }
}

#[tokio::test]
async fn duplicate_security_claims_are_rejected_from_original_signed_bytes() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for field in ["iss", "aud", "nonce", "iat", "exp", "sub"] {
        let (exchange, claims) = f.exchange().await;
        let original = serde_json::to_string(&claims).unwrap();
        let duplicate = format!(
            "{{\"{field}\":{},{}",
            serde_json::to_string(&claims[field]).unwrap(),
            &original[1..]
        );
        let token = OidcIdToken::parse(f.key.raw(duplicate.as_bytes())).unwrap();
        assert!(
            matches!(
                f.verifier.verify(exchange, token).await,
                Err(Error::Unauthorized)
            ),
            "duplicate {field}"
        );
    }
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
async fn foreign_expired_disabled_and_broken_contexts_have_distinct_errors_and_no_grants() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let other = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let (exchange, claims) = other.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, other.key.token(&claims)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 0);
    f.store.available.store(false, Ordering::SeqCst);
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, f.key.token(&claims)).await,
        Err(Error::Unavailable)
    ));
    f.store.available.store(true, Ordering::SeqCst);
    f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst);
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, f.key.token(&claims)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 0);
    f.store.now.store(NOW_US, Ordering::SeqCst);
    f.store.checks.store(0, Ordering::SeqCst);
    f.store.disable_at.store(2, Ordering::SeqCst);
    let (exchange, claims) = f.exchange().await;
    assert!(matches!(
        f.verifier.verify(exchange, f.key.token(&claims)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.gets(),
        2,
        "late context rejection follows actual signature verification"
    );
}

#[tokio::test]
async fn verified_result_retains_original_token_age_and_transaction_deadline_caps() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let (exchange, mut claims) = f.exchange().await;
    claims["iat"] = json!(NOW_US / 1_000_000 - 299);
    claims["exp"] = json!(NOW_US / 1_000_000 + 3600);
    let result = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    assert_eq!(
        result.expires_us(),
        NOW_US + 1_000_000,
        "checking age cannot restart the token's original acceptance window"
    );
    let (exchange, mut claims) = f.exchange().await;
    let original = exchange.expires_us();
    claims["exp"] = json!(NOW_US / 1_000_000 + 3600);
    let result = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    assert_eq!(result.expires_us(), original);
}
