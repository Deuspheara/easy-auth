use super::super::setup::Fixture;
use super::setup::{Http, client};
use crate::{
    Error, OidcAuthorizationCode, OidcClientAuthentication, OidcClientSecret, OidcSigningAlgorithm,
    Secret,
};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn noncacheable_discovery_is_used_once_per_exchange_without_cross_operation_reuse() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.http.cache_seconds.store(0, Ordering::SeqCst);
    let http = Http::new();
    let client = client(
        &f,
        http.clone(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
    );
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    let result = client.exchange(exchange, code()).await;
    assert!(
        result.is_ok(),
        "one logical exchange must not refetch its discovery snapshot"
    );
    assert_eq!(f.gets(), 2, "one discovery and one JWKS fetch");
    assert_eq!(http.posts(), 1);

    assert!(
        matches!(f.documents.discovery().await, Err(Error::RateLimited)),
        "standalone metadata misses still fail promptly under the same budget"
    );
    assert_eq!(f.gets(), 2);
    assert_eq!(http.posts(), 1);
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert!(
        client.exchange(exchange, code()).await.is_ok(),
        "a new leased operation waits for fresh discovery rather than using stale metadata"
    );
    assert_eq!(
        http.posts(),
        2,
        "one POST per independently consumed context"
    );
    assert_eq!(
        f.gets(),
        4,
        "both discovery and keys are refetched for the second operation"
    );
    assert!(
        matches!(f.documents.discovery().await, Err(Error::RateLimited)),
        "successful flow scheduling does not disable public fetch admission"
    );
}

fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap()
}

#[tokio::test]
async fn immediate_callback_after_noncacheable_authorization_start_verifies_without_caller_delay() {
    use super::super::setup::NOW_US;
    use crate::{OAuthCallback, OAuthIntent, OAuthPurpose, OAuthTransactions};
    use serde_json::json;
    use std::time::Duration;

    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.http.cache_seconds.store(0, Ordering::SeqCst);
    let http = Http::new();
    let client = client(
        &f,
        http.clone(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
    );
    let transactions = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "immediate-callback",
        purpose: OAuthPurpose::SignIn,
    };
    let start = transactions.begin(&intent).await.unwrap();
    let authorization = client.authorization_url(&start, &[]).await.unwrap();
    assert!(!authorization.expose().is_empty());
    let claims = json!({"iss":f.store.connection.issuer(),"sub":"subject","aud":"client",
        "iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60,"nonce":start.proof.nonce().expose()});
    let exchange = transactions
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.store.connection.redirect(),
                issuer: Some(f.store.connection.issuer()),
            },
        )
        .await
        .unwrap();
    http.success(&f, &claims);
    let result = tokio::time::timeout(Duration::from_secs(5), client.exchange(exchange, code()))
        .await
        .expect("first discovery admission must have a bounded wait");
    let failure = result.as_ref().err().map(|error| match error {
        Error::RateLimited => "rate_limited",
        Error::Unavailable => "unavailable",
        Error::Unauthorized => "unauthorized",
        Error::InvalidInput => "invalid_input",
    });
    assert!(
        result.is_ok(),
        "valid fast callback failed: {failure:?}; code POSTs={}",
        http.posts()
    );
    assert_eq!(http.posts(), 1, "exactly one code POST");
    assert_eq!(f.gets(), 3, "fresh discovery for each operation, then JWKS");
    assert!(
        matches!(f.documents.discovery().await, Err(Error::RateLimited)),
        "standalone metadata still enforces its unchanged miss budget"
    );
}

#[tokio::test]
async fn consecutive_code_exchanges_refetch_noncacheable_keys_without_caller_delay() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    // Discovery can stay fresh independently of a provider's no-store keys.
    f.documents.discovery().await.unwrap();
    f.http.cache_seconds.store(0, Ordering::SeqCst);
    let http = Http::new();
    let client = client(
        &f,
        http.clone(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
    );
    let (first, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert!(
        client.exchange(first, code()).await.is_ok(),
        "actual signed positive control"
    );
    let (second, claims) = f.exchange().await;
    http.success(&f, &claims);
    let result = client.exchange(second, code()).await;
    let failure = result.as_ref().err().map(|error| match error {
        Error::RateLimited => "rate_limited",
        Error::Unavailable => "unavailable",
        Error::Unauthorized => "unauthorized",
        Error::InvalidInput => "invalid_input",
    });
    assert!(
        result.is_ok(),
        "consecutive valid code exchange failed: {failure:?}; code POSTs={}",
        http.posts()
    );
    assert_eq!(http.posts(), 2, "exactly one POST per consumed context");
    assert_eq!(
        f.gets(),
        3,
        "cached discovery and two independently fetched key documents"
    );
}
