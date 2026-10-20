use super::super::setup::{NOW_US, Signing, TokenHttp};
use super::setup::*;
use crate::*;
use serde_json::json;

#[tokio::test]
async fn actual_rs256_wrong_security_claims_cannot_become_google_identity() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    for (field, value) in [
        ("iss", json!("accounts.google.com")),
        ("iss", json!("https://attacker.example")),
        ("aud", json!("another-client")),
        ("azp", json!("another-client")),
        (
            "aud",
            json!([
                "registered-client.apps.googleusercontent.com",
                "another-client"
            ]),
        ),
        ("nonce", json!(Secret::generate().unwrap().expose())),
        ("nonce", json!(null)),
        ("sub", json!("")),
        ("sub", json!("x".repeat(256))),
        ("exp", json!(NOW_US / 1_000_000)),
        ("iat", json!(NOW_US / 1_000_000 + 1)),
        ("email_verified", json!("true")),
        ("email_verified", json!(null)),
    ] {
        let (exchange, mut claims) = f.exchange().await;
        claims[field] = value;
        tokens.success(&f, &claims);
        assert!(
            matches!(
                client.exchange(exchange, code()).await,
                Err(Error::Unauthorized)
            ),
            "signed malformed/wrong claim must fail authorization"
        );
    }
    let (exchange, mut claims) = f.exchange().await;
    claims["azp"] = json!(f.store.connection.provider_client());
    tokens.success(&f, &claims);
    assert_eq!(
        client.exchange(exchange, code()).await.unwrap().subject(),
        "subject"
    );
}

#[tokio::test]
async fn email_verification_is_a_signed_attribute_not_required_local_contact_authority() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    for (email, flag) in [
        (true, Some(true)),
        (true, Some(false)),
        (true, None),
        (false, Some(true)),
    ] {
        let (exchange, mut claims) = f.exchange().await;
        if email {
            claims["email"] = json!("attribute@example.test");
        }
        if let Some(flag) = flag {
            claims["email_verified"] = json!(flag);
        }
        tokens.success(&f, &claims);
        let identity = client.exchange(exchange, code()).await.unwrap();
        assert_eq!(identity.subject(), "subject");
        assert_eq!(identity.email(), email.then_some("attribute@example.test"));
        assert_eq!(identity.email_verified(), email && flag == Some(true));
    }
}

#[tokio::test]
async fn foreign_signature_other_algorithm_and_duplicate_email_flag_fail_closed() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    for algorithm in [OidcSigningAlgorithm::RS256, OidcSigningAlgorithm::ES256] {
        let (exchange, claims) = f.exchange().await;
        let foreign = Signing::new(algorithm, "current");
        *tokens.body.lock().unwrap()=serde_json::to_vec(&json!({"id_token":foreign.raw(&serde_json::to_vec(&claims).unwrap()),"access_token":"unused","token_type":"Bearer"})).unwrap();
        assert!(matches!(
            client.exchange(exchange, code()).await,
            Err(Error::Unauthorized)
        ));
    }
    let (exchange, mut claims) = f.exchange().await;
    claims["email_verified"] = json!(true);
    let raw = serde_json::to_string(&claims).unwrap().replace(
        "\"email_verified\":true",
        "\"email_verified\":false,\"email_verified\":true",
    );
    assert_eq!(
        raw.matches("\"email_verified\"").count(),
        2,
        "the fixture must preserve both original signed flag members"
    );
    *tokens.body.lock().unwrap()=serde_json::to_vec(&json!({"id_token":f.key.raw(raw.as_bytes()),"access_token":"unused","token_type":"Bearer"})).unwrap();
    assert!(matches!(
        client.exchange(exchange, code()).await,
        Err(Error::Unauthorized)
    ));
}
