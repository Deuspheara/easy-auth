use super::{AppleGrantVault, MAX_STORAGE_WORKERS};
use crate::{
    Error,
    oidc::apple::grants::{
        protection,
        tests::{binding, payload, vault},
    },
};
use std::{
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

struct Release(Arc<(Mutex<bool>, Condvar)>);
impl Drop for Release {
    fn drop(&mut self) {
        let (lock, ready) = &*self.0;
        *lock.lock().unwrap() = true;
        ready.notify_all();
    }
}
#[tokio::test]
async fn cancelling_waiters_retains_bounded_native_work_until_actual_completion() {
    let vault: Arc<AppleGrantVault> = Arc::new(vault());
    let envelope = protection::seal(&vault.keys, binding(), payload()).unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let cleanup = Release(gate.clone());
    let (started, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let mut waiters = Vec::new();
    for _ in 0..MAX_STORAGE_WORKERS {
        let v = vault.clone();
        let gate = gate.clone();
        let started = started.clone();
        waiters.push(tokio::spawn(async move {
            v.blocking(move |_| {
                started.send(()).unwrap();
                let (lock, ready) = &*gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = ready.wait(released).unwrap();
                }
                Ok(())
            })
            .await
        }));
    }
    for _ in 0..MAX_STORAGE_WORKERS {
        tokio::time::timeout(Duration::from_secs(5), observed.recv())
            .await
            .unwrap()
            .unwrap();
    }
    for waiter in waiters {
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
    }
    assert!(matches!(
        vault.rewrap(&envelope).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(vault.workers.available_permits(), 0);
    drop(cleanup);
    tokio::time::timeout(Duration::from_secs(5), async {
        while vault.workers.available_permits() != MAX_STORAGE_WORKERS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(vault.rewrap(&envelope).await.is_ok());
}
