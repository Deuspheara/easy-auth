use super::super::setup::{Fixture, NOW_US};
use super::setup::{Http, client};
use crate::{
    Error, OidcAuthorizationCode, OidcClientAuthentication, OidcClientSecret, OidcSigningAlgorithm,
    Secret,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

fn authentication() -> OidcClientAuthentication {
    OidcClientAuthentication::ClientSecretBasic(
        OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
    )
}
fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap()
}

#[tokio::test]
async fn foreign_or_expired_context_cannot_send_code_or_client_credentials() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let other = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let http = Http::new();
    let client = client(&f, http.clone(), authentication());
    let (exchange, _) = other.exchange().await;
    assert!(matches!(
        client.exchange(exchange, code()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(http.posts(), 0);
    assert_eq!(f.gets(), 0);
    let (exchange, _) = f.exchange().await;
    f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst);
    assert!(matches!(
        client.exchange(exchange, code()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(http.posts(), 0);
    assert_eq!(f.gets(), 0);
}

#[tokio::test]
async fn expiry_during_dns_is_rechecked_before_sending_any_credentials() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let http = Http::new();
    let client = Arc::new(client(&f, http.clone(), authentication()));
    f.documents.discovery().await.unwrap();
    let (exchange, _) = f.exchange().await;
    f.http.hold_dns.store(true, Ordering::SeqCst);
    let action = {
        let client = client.clone();
        tokio::spawn(async move { client.exchange(exchange, code()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), f.http.dns_entered.notified())
        .await
        .expect("test infrastructure: token target DNS entered");
    f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst);
    f.http.dns_release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(2), action)
        .await
        .expect("test infrastructure: DNS-released exchange finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(http.posts(), 0);
}

#[tokio::test]
async fn disable_during_post_rejects_the_late_result_and_releases_capacity() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let http = Http::new();
    let client = Arc::new(client(&f, http.clone(), authentication()));
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    http.hold.store(true, Ordering::SeqCst);
    let action = {
        let client = client.clone();
        tokio::spawn(async move { client.exchange(exchange, code()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), http.entered.notified())
        .await
        .expect("test infrastructure: token POST entered");
    f.store.enabled.store(false, Ordering::SeqCst);
    http.hold.store(false, Ordering::SeqCst);
    http.release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(2), action)
        .await
        .expect("test infrastructure: released POST finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.store.checks.load(Ordering::SeqCst), 3);
    f.store.enabled.store(true, Ordering::SeqCst);
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert_eq!(
        client.exchange(exchange, code()).await.unwrap().subject(),
        "subject"
    );
    assert_eq!(http.posts(), 2);
}

#[tokio::test]
async fn shared_operation_budget_rejects_before_post_and_recovers_after_network_failure() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let http = Http::new();
    let client = Arc::new(client(&f, http.clone(), authentication()));
    f.documents.discovery().await.unwrap();
    http.hold.store(true, Ordering::SeqCst);
    http.fail.store(true, Ordering::SeqCst);
    let (first, _) = f.exchange().await;
    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.exchange(first, code()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), http.entered.notified())
        .await
        .expect("test infrastructure: first POST entered");
    let (second, _) = f.exchange().await;
    let second = {
        let client = client.clone();
        tokio::spawn(async move { client.exchange(second, code()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), http.entered.notified())
        .await
        .expect("test infrastructure: second POST entered");
    let (third, _) = f.exchange().await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), client.exchange(third, code()))
            .await
            .expect("capacity must reject promptly"),
        Err(Error::RateLimited)
    ));
    assert_eq!(http.posts(), 2);
    http.hold.store(false, Ordering::SeqCst);
    http.release.notify_waiters();
    for action in [first, second] {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), action)
                .await
                .expect("test infrastructure: held POST released")
                .unwrap(),
            Err(Error::Unavailable)
        ));
    }
    http.fail.store(false, Ordering::SeqCst);
    let (control, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert_eq!(
        client.exchange(control, code()).await.unwrap().subject(),
        "subject"
    );
    assert_eq!(http.posts(), 3);
}
