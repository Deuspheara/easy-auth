use super::*;
use std::{sync::Mutex, time::Duration};

struct RejectingStore {
    calls: Mutex<Vec<RetentionCategory>>,
}

#[async_trait]
impl RetentionRepository for RejectingStore {
    async fn retain_batch(
        &self,
        _realm: Uuid,
        category: RetentionCategory,
        _policy: RetentionPolicy,
    ) -> Result<RetentionBatch> {
        self.calls.lock().unwrap().push(category);
        Err(Error::Unavailable)
    }
}

#[test]
fn operator_horizons_reject_zero_fractional_and_excessive_durations() {
    for value in [
        Duration::ZERO,
        Duration::from_millis(1500),
        Duration::from_secs(3_153_600_001),
        Duration::MAX,
    ] {
        assert!(matches!(
            RetentionHorizon::after(value),
            Err(Error::InvalidInput)
        ));
    }
    assert_eq!(
        RetentionHorizon::after(Duration::from_secs(1))
            .unwrap()
            .seconds(),
        Some(1)
    );
    assert_eq!(
        RetentionHorizon::after(Duration::from_secs(3_153_600_000))
            .unwrap()
            .seconds(),
        Some(3_153_600_000)
    );
    let policy = RetentionPolicy::new(
        RetentionHorizon::keep(),
        RetentionHorizon::after(Duration::from_secs(86400)).unwrap(),
    );
    assert_eq!(policy.audit().seconds(), None);
    assert_eq!(policy.exhausted_notices().seconds(), Some(86400));
}

#[tokio::test]
async fn nil_realm_never_reaches_destructive_storage() {
    let store = RejectingStore {
        calls: Mutex::new(Vec::new()),
    };
    let result = run_retention(
        &store,
        Uuid::nil(),
        RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep()),
    )
    .await;
    assert!(matches!(result, Err(Error::InvalidInput)));
    assert!(store.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn storage_failure_stops_later_categories_without_retry_or_false_report() {
    let store = RejectingStore {
        calls: Mutex::new(Vec::new()),
    };
    let result = run_retention(
        &store,
        Uuid::new_v4(),
        RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep()),
    )
    .await;
    assert!(matches!(result, Err(Error::Unavailable)));
    assert_eq!(store.calls.lock().unwrap().len(), 1);
}
