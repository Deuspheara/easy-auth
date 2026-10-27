use super::setup::*;

#[tokio::test]
async fn foreign_signature_and_non_rs256_tokens_reject_without_algorithm_fallback() {
    use super::super::setup::Signing;
    for algorithm in [OidcSigningAlgorithm::RS256, OidcSigningAlgorithm::ES256] {
        let f = fixture();
        let (exchange, claims) = f.exchange().await;
        let foreign = Signing::new(algorithm, "current");
        if algorithm == OidcSigningAlgorithm::ES256 {
            *f.http.keys.lock().unwrap() =
                serde_json::to_vec(&json!({"keys":[foreign.public]})).unwrap();
        }
        let tokens = TokenHttp::new();
        *tokens.body.lock().unwrap() = serde_json::to_vec(&json!({"id_token":foreign.raw(&serde_json::to_vec(&claims).unwrap()),"access_token":"unused","token_type":"Bearer"})).unwrap();
        assert!(matches!(
            client(&f, tokens.clone(), AppleClientType::Web)
                .exchange(exchange, code())
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(tokens.posts(), 1);
    }
}

#[tokio::test]
async fn non_signin_exchange_contexts_reject_before_code_or_credentials_are_sent() {
    let f = fixture();
    let tokens = TokenHttp::new();
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-test",
        purpose: OAuthPurpose::Link {
            user: uuid::Uuid::new_v4(),
            session: Secret::generate().unwrap().verifier(),
        },
    };
    let transactions = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let start = transactions.begin(&intent).await.unwrap();
    let exchange = transactions
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.store.connection.redirect(),
                issuer: None,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        client(&f, tokens.clone(), AppleClientType::Web)
            .exchange(exchange, code())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(tokens.posts(), 0);
    assert_eq!(f.gets(), 0);
}

#[tokio::test]
async fn apple_signed_claim_negatives_never_become_verified_identities() {
    for (field, value) in [
        ("iss", json!("https://accounts.google.com")),
        ("aud", json!("com.other.client")),
        ("aud", json!(["com.example.auth", "com.other.client"])),
        ("azp", json!("com.other.client")),
        ("nonce", json!(Secret::generate().unwrap().expose())),
        ("sub", json!("")),
        ("iat", json!(NOW_US / 1_000_000 + 1)),
        ("exp", json!(NOW_US / 1_000_000)),
        ("email_verified", json!("TRUE")),
        ("email_verified", json!(1)),
        ("email_verified", json!(null)),
    ] {
        let f = fixture();
        let (exchange, mut claims) = f.exchange().await;
        claims[field] = value;
        let tokens = TokenHttp::new();
        tokens.success(&f, &claims);
        assert!(matches!(
            client(&f, tokens.clone(), AppleClientType::Web)
                .exchange(exchange, code())
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(tokens.posts(), 1);
    }
}

#[tokio::test]
async fn native_nonce_convention_has_no_automatic_plain_or_hashed_fallback() {
    for kind in [
        AppleClientType::Web,
        AppleClientType::Native(AppleNonceEncoding::Sha256Hex),
    ] {
        let f = fixture();
        let (exchange, mut claims) = f.exchange().await;
        if kind == AppleClientType::Web {
            claims["nonce"] =
                json!(AppleNonceEncoding::Sha256Hex.authorization_nonce(exchange.proof().nonce()));
        }
        let tokens = TokenHttp::new();
        tokens.success(&f, &claims);
        assert!(matches!(
            client(&f, tokens, kind).exchange(exchange, code()).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[tokio::test]
async fn unexpected_apple_endpoint_or_auth_method_rejects_before_code_disclosure() {
    for (field, value) in [
        ("token_endpoint", json!("https://appleid.apple.com/foreign")),
        ("jwks_uri", json!("https://appleid.apple.com/foreign")),
        (
            "authorization_endpoint",
            json!("https://appleid.apple.com/foreign"),
        ),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
    ] {
        let f = fixture();
        let (exchange, _) = f.exchange().await;
        f.http.metadata.lock().unwrap()[field] = value;
        let tokens = TokenHttp::new();
        assert!(matches!(
            client(&f, tokens.clone(), AppleClientType::Web)
                .exchange(exchange, code())
                .await,
            Err(Error::Unavailable)
        ));
        assert_eq!(tokens.posts(), 0);
    }
}

#[tokio::test]
async fn original_duplicate_signed_flags_are_not_normalized_before_verification() {
    let f = fixture();
    let (exchange, mut claims) = f.exchange().await;
    claims["email_verified"] = json!("true");
    let raw = serde_json::to_string(&claims).unwrap().replace(
        "\"email_verified\":\"true\"",
        "\"email_verified\":false,\"email_verified\":\"true\"",
    );
    assert_eq!(raw.matches("\"email_verified\"").count(), 2);
    let tokens = TokenHttp::new();
    *tokens.body.lock().unwrap() = serde_json::to_vec(&json!({"id_token":f.key.raw(raw.as_bytes()),"access_token":"unused","token_type":"Bearer"})).unwrap();
    assert!(matches!(
        client(&f, tokens, AppleClientType::Web)
            .exchange(exchange, code())
            .await,
        Err(Error::Unauthorized)
    ));
}
