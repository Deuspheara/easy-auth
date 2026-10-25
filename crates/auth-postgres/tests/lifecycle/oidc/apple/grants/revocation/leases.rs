use super::fixture::*;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn active_and_foreign_sources_cannot_claim_and_concurrent_claims_have_one_lease(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    sign_in(&f, "active").await;
    assert!(
        f.store
            .claim_apple_revocation(f.policy.configuration())
            .await
            .unwrap()
            .is_none()
    );
    let other = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&other).await;
    assert!(
        f.store
            .claim_apple_revocation(f.policy.configuration())
            .await
            .unwrap()
            .is_none()
    );
    let source = other.policy.configuration();
    let (a, b) = tokio::join!(
        other.store.claim_apple_revocation(source),
        other.store.claim_apple_revocation(source)
    );
    let mut jobs = vec![a.unwrap(), b.unwrap()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(jobs.len(), 1);
    let job = jobs.pop().unwrap();
    assert!(matches!(
        f.store
            .check_apple_revocation(f.policy.configuration(), &job)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        other
            .store
            .check_apple_revocation(source, &job)
            .await
            .is_ok()
    );
    assert!(
        !f.store
            .defer_apple_revocation(
                f.policy.configuration(),
                &job,
                AppleRevocationFailure::Provider
            )
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn valid_late200_cannot_acknowledge_an_already_rescheduled_generation(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await);
    pending(&f).await;
    let http = Http::new(&f);
    *http.mode.lock().unwrap() = Mode::Hold;
    let w = worker(&f, http.clone());
    let action = tokio::spawn(async move { w.run_once().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), http.entered.notified())
        .await
        .unwrap();
    let job = leased(&f).await;
    assert!(
        f.store
            .defer_apple_revocation(
                f.policy.configuration(),
                &job,
                AppleRevocationFailure::Transport
            )
            .await
            .unwrap()
    );
    http.release.notify_one();
    assert_eq!(
        action.await.unwrap().unwrap(),
        AppleRevocationOutcome::Stale
    );
    let row = state(&f).await;
    assert_eq!(row.0, "pending");
    assert!(!row.3);
    assert_eq!(http.applied.load(Ordering::SeqCst), 1);
}
#[sqlx::test(migrations = "./migrations")]
async fn lost_success_response_retries_only_after_real_backoff_and_confirms_idempotently(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&f).await;
    let http = Http::new(&f);
    *http.mode.lock().unwrap() = Mode::LostResponse;
    let worker = worker(&f, http.clone());
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Transport)
    );
    assert_eq!(http.applied.load(Ordering::SeqCst), 1);
    let cap:i64=sqlx::query_scalar("SELECT (extract(epoch FROM next_attempt_at)*1000000)::bigint FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
    wait_clock(&f.pool, cap).await;
    *http.mode.lock().unwrap() = Mode::Success;
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Confirmed
    );
    assert_eq!(state(&f).await, ("completed".into(), 2, None, true));
    assert_eq!(http.calls.load(Ordering::SeqCst), 2);
}
