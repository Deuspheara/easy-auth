use super::super::setup::{Fixture, NOW_US};
use super::setup::{Http, client};
use crate::{
    Error, OidcAuthorizationCode, OidcClientAuthentication, OidcClientSecret, OidcSigningAlgorithm,
    Secret,
};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

fn authentication() -> OidcClientAuthentication {
    OidcClientAuthentication::ClientSecretBasic(
        OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
    )
}
fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap()
}
async fn observe_checks(f: &Fixture, expected: usize) {
    // The mock repository completes synchronously. Yield until its observable
    // pre-I/O check ran; the paused clock cannot spend the admission interval.
    for _ in 0..100 {
        if f.store.checks.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("test infrastructure: pre-I/O exchange checks were not observed");
}

#[tokio::test]
async fn admission_wait_rechecks_expiry_disable_and_broken_registry_without_sending_credentials() {
    for mode in ["expiry", "disable", "registry"] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        f.http.cache_seconds.store(0, Ordering::SeqCst);
        f.documents.discovery().await.unwrap();
        let http = Http::new();
        let client = Arc::new(client(&f, http.clone(), authentication()));
        let (exchange, _) = f.exchange().await;
        tokio::time::pause();
        let action = {
            let client = client.clone();
            tokio::spawn(async move { client.exchange(exchange, code()).await })
        };
        observe_checks(&f, 1).await;
        assert_eq!(f.gets(), 1, "no new fetch while admission is pending");
        assert_eq!(http.posts(), 0);
        match mode {
            "expiry" => f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst),
            "disable" => f.store.enabled.store(false, Ordering::SeqCst),
            _ => f.store.available.store(false, Ordering::SeqCst),
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = action.await.unwrap();
        tokio::time::resume();
        if mode == "registry" {
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "storage failure is not authorization evidence"
            );
        } else {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
        assert_eq!(
            http.posts(),
            0,
            "waiting cannot extend credential-send authority"
        );
        assert_eq!(f.gets(), if mode == "expiry" { 2 } else { 1 });
    }
}

#[tokio::test]
async fn admission_waits_hold_existing_leases_and_cancellation_releases_capacity() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.http.cache_seconds.store(0, Ordering::SeqCst);
    f.documents.discovery().await.unwrap();
    let http = Http::new();
    let client = Arc::new(client(&f, http.clone(), authentication()));
    tokio::time::pause();
    let mut actions = Vec::new();
    for expected in 1..=2 {
        let (exchange, _) = f.exchange().await;
        let client = client.clone();
        actions.push(tokio::spawn(async move {
            client.exchange(exchange, code()).await
        }));
        observe_checks(&f, expected).await;
    }
    let (third, _) = f.exchange().await;
    assert!(
        matches!(
            client.exchange(third, code()).await,
            Err(Error::RateLimited)
        ),
        "admission timers cannot create an unbounded wait queue"
    );
    assert_eq!(http.posts(), 0);
    assert_eq!(f.gets(), 1);
    for action in actions {
        action.abort();
        assert!(action.await.unwrap_err().is_cancelled());
    }
    tokio::time::resume();
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    let result = tokio::time::timeout(Duration::from_secs(5), client.exchange(exchange, code()))
        .await
        .expect("released admission capacity must permit bounded fresh work");
    assert!(
        result.is_ok(),
        "actual signed control must succeed after cancellation"
    );
    assert_eq!(http.posts(), 1);
    assert_eq!(f.gets(), 3, "fresh discovery and keys, no stale reuse");
}

#[tokio::test]
async fn ordinary_key_admission_wait_retains_the_original_exchange_deadline() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    // Keep metadata fresh while the independently fetched key set is no-store.
    f.documents.discovery().await.unwrap();
    f.http.cache_seconds.store(0, Ordering::SeqCst);
    f.documents.jwks().await.unwrap();
    let http = Http::new();
    let client = Arc::new(client(&f, http.clone(), authentication()));
    let (exchange, claims) = f.exchange().await;
    http.success(&f, &claims);
    tokio::time::pause();
    let action = {
        let client = client.clone();
        tokio::spawn(async move { client.exchange(exchange, code()).await })
    };
    observe_checks(&f, 3).await;
    assert_eq!(
        http.posts(),
        1,
        "initial valid code POST completed before expiry"
    );
    assert_eq!(f.gets(), 2, "ordinary key admission is still pending");
    f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;
    // Native signature work must run against a normal clock after the controlled
    // admission wait; paused-runtime auto-advance is not crypto-timeout evidence.
    tokio::time::resume();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("admitted key fetch and final check complete")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(
        f.store.checks.load(Ordering::SeqCst),
        4,
        "actual valid signature must reach the final original-deadline check"
    );
    assert_eq!(
        f.gets(),
        3,
        "fresh keys are fetched instead of reusing no-store data"
    );
    assert_eq!(
        http.posts(),
        1,
        "expiry cannot retry a consumed provider code"
    );
}
