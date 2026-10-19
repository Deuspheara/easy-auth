use super::setup::Fixture;
use crate::{Error, OidcSigningAlgorithm};
use std::{future::Future, sync::mpsc, task::Poll, time::Duration};

struct BlockingGate(Option<mpsc::Sender<()>>);
impl Drop for BlockingGate {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

#[test]
fn cancelled_native_jobs_retain_capacity_until_completion_then_new_work_succeeds() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        f.documents.jwks().await.unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gate = BlockingGate(Some(release_tx));
        let occupier = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("test infrastructure: owned blocking gate released");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("test infrastructure: native worker occupied");

        let (first, claims) = f.exchange().await;
        let mut first = Box::pin(f.verifier.verify(first, f.key.token(&claims)));
        // All fixture ports are immediately ready and documents are warm. Poll
        // through the real async verifier until its native job is queued.
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        let (second, claims) = f.exchange().await;
        let mut second = Box::pin(f.verifier.verify(second, f.key.token(&claims)));
        std::future::poll_fn(|cx| {
            assert!(second.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let (third, claims) = f.exchange().await;
        let overloaded = tokio::time::timeout(
            Duration::from_secs(1),
            f.verifier.verify(third, f.key.token(&claims)),
        )
        .await
        .expect("overload must reject promptly, not wait for the native queue");
        assert!(
            matches!(overloaded, Err(Error::RateLimited)),
            "cancelling an async caller must not free its queued native lease"
        );
        assert_eq!(
            f.gets(),
            2,
            "capacity rejection must not be a cache/network failure"
        );
        drop(second);
        drop(gate);
        occupier.await.unwrap();

        let identity = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (exchange, claims) = f.exchange().await;
                match f.verifier.verify(exchange, f.key.token(&claims)).await {
                    Ok(identity) => break identity,
                    Err(Error::RateLimited) => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(_) => panic!("valid signature must succeed after native capacity recovers"),
                }
            }
        })
        .await
        .expect("test infrastructure: native jobs finish and return their leases");
        assert_eq!(identity.subject(), "subject");
        assert_eq!(f.gets(), 2);
    });
}
