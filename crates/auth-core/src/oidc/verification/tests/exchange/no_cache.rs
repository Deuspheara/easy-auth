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

    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert!(matches!(
        client.exchange(exchange, code()).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(
        http.posts(),
        1,
        "no-cache metadata cannot authorize a second POST"
    );
    assert_eq!(
        f.gets(),
        2,
        "original cross-operation fetch budget is unchanged"
    );
}

fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap()
}
