use super::super::OidcHttps;
use auth_core::Error;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Semaphore, oneshot};

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_native_lookup_keeps_budget_until_the_blocking_job_finishes() {
    let mut http = OidcHttps::new();
    http.operations = Arc::new(Semaphore::new(1));
    let (entered, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let task = {
        let http = http.clone();
        tokio::spawn(async move {
            http.lookup(move || {
                entered.send(()).unwrap();
                gate.recv().unwrap();
                Ok(Vec::new())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), ready)
        .await
        .expect("test infrastructure: lookup entered")
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(http.operations.available_permits(), 0);
    assert!(matches!(
        http.lookup(|| Ok(Vec::new())).await,
        Err(Error::RateLimited)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while http.operations.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test infrastructure: completed native job releases its permit");
    assert!(http.lookup(|| Ok(Vec::new())).await.unwrap().is_empty());
}
