use super::setup::Fixture;
use crate::Error;
use std::{sync::atomic::Ordering, time::Duration};

#[tokio::test(start_paused = true)]
async fn unknown_key_refresh_is_bounded_and_old_observers_reuse_the_new_snapshot() {
    let f = Fixture::new();
    let original = f.documents.jwks().await.unwrap();
    assert_eq!(f.gets(), 2);
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::RateLimited)
    ));
    tokio::time::advance(Duration::from_secs(1)).await;
    *f.http.keys.lock().unwrap() = br#"{"keys":[{"kid":"rotated-envelope"}]}"#.to_vec();
    let current = f.documents.refresh_jwks(&original).await.unwrap();
    assert_ne!(original.as_bytes(), current.as_bytes());
    assert_eq!(f.gets(), 3);
    let coalesced = f.documents.refresh_jwks(&original).await.unwrap();
    assert_eq!(coalesced.as_bytes(), current.as_bytes());
    assert_eq!(
        f.gets(),
        3,
        "old observers must not amplify a completed refresh"
    );
    assert!(matches!(
        f.documents.refresh_jwks(&current).await,
        Err(Error::RateLimited)
    ));
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(matches!(
        f.documents.refresh_jwks(&current).await,
        Err(Error::RateLimited)
    ));
    tokio::time::advance(Duration::from_secs(1)).await;
    f.documents.refresh_jwks(&current).await.unwrap();
    assert_eq!(f.gets(), 4);
}

#[tokio::test(start_paused = true)]
async fn failed_refresh_spends_its_budget_and_returns_no_old_document() {
    let f = Fixture::new();
    let original = f.documents.jwks().await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    *f.http.keys.lock().unwrap() = b"invalid-json".to_vec();
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.gets(), 3);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.gets(), 3);
    tokio::time::advance(Duration::from_secs(29)).await;
    *f.http.keys.lock().unwrap() = br#"{"keys":[{"kid":"repaired-envelope"}]}"#.to_vec();
    let current = f.documents.refresh_jwks(&original).await.unwrap();
    assert_ne!(current.as_bytes(), original.as_bytes());
    assert_eq!(f.gets(), 4);
}

#[tokio::test(start_paused = true)]
async fn concurrent_refresh_fails_promptly_and_disable_rejects_its_late_result() {
    let f = Fixture::new();
    let original = f.documents.jwks().await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    f.http.hold.store(true, Ordering::SeqCst);
    let action = {
        let documents = f.documents.clone();
        let original = original.clone();
        tokio::spawn(async move { documents.refresh_jwks(&original).await })
    };
    f.http.entered.notified().await;
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::RateLimited)
    ));
    f.registry.enabled.store(false, Ordering::SeqCst);
    f.http.release.notify_one();
    assert!(matches!(action.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.gets(), 3);
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gets(), 3);
}

#[tokio::test(start_paused = true)]
async fn non_cacheable_refresh_cannot_satisfy_an_old_observer_without_a_new_fetch() {
    let f = Fixture::new();
    f.http.age.store(0, Ordering::SeqCst);
    let original = f.documents.jwks().await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    f.documents.refresh_jwks(&original).await.unwrap();
    assert_eq!(
        f.gets(),
        4,
        "both non-cacheable documents must be fetched again"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(
        f.gets(),
        5,
        "discovery cannot reuse non-cacheable data, but key refresh remains throttled"
    );
    assert!(matches!(f.documents.jwks().await, Err(Error::RateLimited)));
    assert_eq!(f.gets(), 5);
}

#[tokio::test(start_paused = true)]
async fn refresh_dns_timeout_spends_budget_and_releases_the_slot_without_returning_old_data() {
    let f = Fixture::new();
    let original = f.documents.jwks().await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    f.http.stall_dns.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.gets(), 2, "timed-out DNS must not reach HTTP");
    f.http.stall_dns.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.documents.refresh_jwks(&original).await,
        Err(Error::RateLimited)
    ));
    tokio::time::advance(Duration::from_secs(25)).await;
    f.documents.refresh_jwks(&original).await.unwrap();
    assert_eq!(
        f.gets(),
        3,
        "cancelled operation releases its slot; failed attempt retained its budget"
    );
}
