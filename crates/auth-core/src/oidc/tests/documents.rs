use super::setup::Fixture;
use crate::{Error, OAuthConnection, OAuthMixupDefense, OidcDocuments};
use std::{sync::atomic::Ordering, time::Duration};

#[tokio::test(start_paused = true)]
async fn fixed_cache_slots_cap_http_age_and_expiry_never_falls_back_to_stale_data() {
    let f = Fixture::new();
    let first = f.documents.jwks().await.unwrap();
    assert!(!first.as_bytes().is_empty());
    f.documents.jwks().await.unwrap();
    assert_eq!(f.gets(), 2);
    tokio::time::advance(Duration::from_secs(299)).await;
    f.documents.jwks().await.unwrap();
    assert_eq!(f.gets(), 2);
    *f.http.metadata.lock().unwrap() = b"not-json".to_vec();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(matches!(f.documents.jwks().await, Err(Error::Unavailable)));
    assert_eq!(
        f.gets(),
        3,
        "expired cache must make a fresh request and reject its invalid result"
    );
}

#[tokio::test]
async fn cache_hits_recheck_registry_and_another_realm_revision_cannot_reuse_context() {
    let f = Fixture::new();
    f.documents.jwks().await.unwrap();
    f.registry.enabled.store(false, Ordering::SeqCst);
    assert!(matches!(f.documents.jwks().await, Err(Error::Unauthorized)));
    assert_eq!(f.gets(), 2);
    let old = &f.registry.connection;
    let other = OAuthConnection::new(
        uuid::Uuid::new_v4(),
        old.connection(),
        old.client(),
        old.issuer(),
        old.provider_client(),
        old.redirect(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let other = OidcDocuments::new(
        other,
        &["https://issuer.example"],
        f.registry.clone(),
        f.http.clone(),
    )
    .unwrap();
    assert!(matches!(other.discovery().await, Err(Error::Unauthorized)));
    assert_eq!(f.gets(), 2);
}

#[tokio::test(start_paused = true)]
async fn concurrent_fetch_fails_promptly_and_disabled_inflight_result_is_not_cached() {
    let f = Fixture::new();
    f.http.hold.store(true, Ordering::SeqCst);
    let task = {
        let documents = f.documents.clone();
        tokio::spawn(async move { documents.discovery().await })
    };
    f.http.entered.notified().await;
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::RateLimited)
    ));
    f.registry.enabled.store(false, Ordering::SeqCst);
    f.http.release.notify_one();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.gets(), 1);
    f.registry.enabled.store(true, Ordering::SeqCst);
    f.http.hold.store(false, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(2)).await;
    f.documents.discovery().await.unwrap();
    assert_eq!(f.gets(), 2);
}

#[tokio::test(start_paused = true)]
async fn dns_stall_is_included_in_the_whole_operation_timeout() {
    let f = Fixture::new();
    f.http.stall_dns.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.documents.discovery().await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.gets(), 0);
}
