use super::super::setup::{Fixture, TokenHttp};
use super::setup::*;
use crate::*;
use serde_json::json;
use std::sync::atomic::Ordering;

#[test]
fn google_profile_refuses_another_issuer_or_public_authentication_without_io() {
    let f = Fixture::new(OidcSigningAlgorithm::RS256, &[]);
    let tokens = TokenHttp::new();
    assert!(matches!(
        client(&f, tokens.clone(), authentication(false)),
        Err(Error::InvalidInput)
    ));
    assert_eq!(f.gets(), 0);
    assert_eq!(tokens.posts(), 0);
    let f = fixture(false);
    assert!(matches!(
        client(&f, tokens.clone(), OidcClientAuthentication::Public),
        Err(Error::InvalidInput)
    ));
    let original = &f.store.connection;
    let dedicated = OAuthConnection::new(
        original.realm(),
        original.connection(),
        original.client(),
        original.issuer(),
        original.provider_client(),
        original.redirect(),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    assert!(matches!(
        GoogleCodeExchange::new(
            dedicated,
            f.store.clone(),
            f.store.clone(),
            authentication(false),
            f.http.clone(),
            tokens.clone()
        ),
        Err(Error::InvalidInput)
    ));
    assert_eq!(f.gets(), 0);
    assert_eq!(tokens.posts(), 0);
}

#[tokio::test]
async fn fixed_google_scope_and_original_s256_do_not_disclose_private_verifier() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "google-offline",
        purpose: OAuthPurpose::SignIn,
    };
    let start = flow.begin(&intent).await.unwrap();
    let destination = client.authorization_url(&start).await.unwrap();
    let url = url::Url::parse(destination.expose()).unwrap();
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://accounts.google.com"
    );
    assert_eq!(url.path(), "/o/oauth2/v2/auth");
    let pairs: Vec<_> = url.query_pairs().collect();
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_ref())
    };
    assert_eq!(value("scope"), Some("openid email profile"));
    assert_eq!(value("code_challenge_method"), Some("S256"));
    assert!(value("state") == Some(start.state.expose()));
    assert!(value("nonce") == Some(start.proof.nonce().expose()));
    assert!(value("code_challenge") == Some(start.proof.code_challenge().as_str()));
    assert!(value("code_verifier").is_none() && value("client_secret").is_none());
    assert_eq!(tokens.posts(), 0);
    flow.cancel(&intent, &start.state, &start.proof)
        .await
        .unwrap();
    assert!(matches!(
        flow.consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.store.connection.redirect(),
                issuer: Some(f.store.connection.issuer())
            }
        )
        .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test]
async fn foreign_endpoints_missing_s256_and_wrong_authentication_never_send_a_code() {
    for (field, value) in [
        ("token_endpoint", json!("https://attacker.example/token")),
        ("jwks_uri", json!("http://127.0.0.1/keys")),
        (
            "authorization_endpoint",
            json!("https://other.googleapis.com/authorize"),
        ),
        ("code_challenge_methods_supported", json!(["plain"])),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
        (
            "authorization_response_iss_parameter_supported",
            json!(false),
        ),
    ] {
        let f = fixture(false);
        f.http.metadata.lock().unwrap()[field] = value;
        let tokens = TokenHttp::new();
        let client = client(&f, tokens.clone(), authentication(false)).unwrap();
        let (exchange, _) = f.exchange().await;
        assert!(matches!(
            client.exchange(exchange, code()).await,
            Err(Error::Unavailable)
        ));
        assert_eq!(
            tokens.posts(),
            0,
            "provider configuration failure must precede code disclosure"
        );
    }
}

#[tokio::test]
async fn disabled_or_unavailable_source_retains_distinct_errors_before_token_exchange() {
    for unavailable in [false, true] {
        let f = fixture(false);
        let tokens = TokenHttp::new();
        let client = client(&f, tokens.clone(), authentication(false)).unwrap();
        let (exchange, _) = f.exchange().await;
        if unavailable {
            f.store.available.store(false, Ordering::SeqCst);
        } else {
            f.store.enabled.store(false, Ordering::SeqCst);
        }
        let error = client.exchange(exchange, code()).await.err().unwrap();
        assert!(matches!(
            (unavailable, error),
            (true, Error::Unavailable) | (false, Error::Unauthorized)
        ));
        assert_eq!(tokens.posts(), 0);
    }
}
